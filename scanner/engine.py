import asyncio
import logging
import socket
import ipaddress
from urllib.parse import urlparse
from typing import Any, Dict, List

from scanner import scoring, reporter
from scanner.correlation import correlate

from scanner.core.profiles import get_profile
from scanner.core.crawler import Crawler
from scanner.core.plugin_loader import load_plugins
from scanner.core.rate_limiter import RateLimiter
from scanner.core.task_queue import TaskQueue

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ScannerEngine:
    def __init__(self, target: str, profile: str = "normal"):
        self.target = self._normalize_target(target)
        self.profile = get_profile(profile)
        self.findings: List[Dict[str, Any]] = []

        self._validate_target()

        # Shared orchestration helpers
        self.limiter = RateLimiter(self.profile.rate_per_sec, burst=self.profile.rate_per_sec)

    # -------------------------
    # Target Handling
    # -------------------------
    def _normalize_target(self, target: str) -> str:
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        return target.rstrip("/")

    def _validate_target(self):
        parsed = urlparse(self.target)
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Invalid target URL")

        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)

        # Hosted-safe default: block private/internal targets
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
            raise ValueError("Scanning private/internal IPs is not allowed.")

    # -------------------------
    # Finding Normalization
    # -------------------------
    def _normalize_finding(self, f: Any) -> Dict[str, Any] | None:
        """
        Enforce a stable schema so one broken module doesn't break reports.
        Required: title, severity
        Optional: description, remediation, metadata
        """
        if not isinstance(f, dict):
            return None

        title = f.get("title")
        severity = f.get("severity")

        if not title or not severity:
            return None

        f.setdefault("description", "")
        f.setdefault("remediation", "")
        f.setdefault("metadata", {})

        # (optional) attach module name if not present
        return f

    # -------------------------
    # Crawl Attack Surface
    # -------------------------
    async def _build_attack_surface(self) -> List[str]:
        """
        Crawl site to discover internal endpoints.
        Uses profile depth/concurrency/include_query and caps max_pages.
        """
        crawler = Crawler(
            self.target,
            max_depth=self.profile.depth,
            concurrency=self.profile.concurrency,
            include_query=self.profile.include_query,
        )

        urls = await crawler.crawl()

        # Cap pages to prevent blow-ups
        if self.profile.max_pages and len(urls) > self.profile.max_pages:
            urls = urls[: self.profile.max_pages]

        logger.info(f"[CRAWLER] Discovered {len(urls)} endpoints (cap={self.profile.max_pages})")
        return urls

    # -------------------------
    # Run a single module safely
    # -------------------------
    async def _run_module(self, module, endpoints: List[str]):
        """
        Module contract:
          async def scan(target: str, endpoints: list[str] | None = None) -> list[dict]
        Backward compatible:
          async def scan(target: str) -> list[dict]
        """
        try:
            await self.limiter.acquire()

            # Support modules that accept endpoints
            try:
                results = await asyncio.wait_for(
                    module.scan(self.target, endpoints=endpoints),
                    timeout=self.profile.module_timeout_sec
                )
            except TypeError:
                # module.scan(target) signature
                results = await asyncio.wait_for(
                    module.scan(self.target),
                    timeout=self.profile.module_timeout_sec
                )

            if isinstance(results, list):
                for item in results:
                    nf = self._normalize_finding(item)
                    if nf:
                        # attach module name if helpful for debugging
                        nf.setdefault("metadata", {})
                        nf["metadata"].setdefault("module", getattr(module, "__name__", "unknown"))
                        self.findings.append(nf)

        except asyncio.TimeoutError:
            logger.warning(f"[ENGINE] Timeout in {getattr(module, '__name__', 'module')}")
        except Exception as e:
            logger.error(f"[ENGINE] Error in {getattr(module, '__name__', 'module')}: {e}")

    # -------------------------
    # Main scan
    # -------------------------
    async def run(self, output_format: str = "json"):
        logger.info(f"[ENGINE] Starting scan on {self.target} (profile={self.profile.name})")

        # 1) Crawl
        endpoints = await self._build_attack_surface()

        # 2) Load plugins
        plugins = load_plugins(
            enabled_modules=self.profile.enabled_modules,
            disabled_modules=self.profile.disabled_modules,
            strict=False
        )
        modules = [p["module"] for p in plugins]
        logger.info(f"[PLUGINS] Loaded {len(modules)} modules")

        # 3) Execute modules via TaskQueue
        q = TaskQueue(concurrency=self.profile.concurrency, task_timeout=self.profile.module_timeout_sec)

        for m in modules:
            await q.add(lambda m=m: self._run_module(m, endpoints))

        stats = await q.run()
        if stats["errors"]:
            logger.warning(f"[ENGINE] TaskQueue errors: {stats['errors']}")

        # 4) Correlate + score
        self.findings = correlate(self.findings)
        score_data = scoring.calculate_score(self.findings)

        # 5) Report
        if output_format == "pdf":
            pdf_bytes = reporter.generate_pdf(self.findings)
            return {"pdf_bytes": pdf_bytes, "score": score_data, "findings": self.findings}

        if output_format == "html":
            return reporter.generate_html(self.target, self.findings, score_data)

        return reporter.generate_json(self.target, self.findings, score_data)
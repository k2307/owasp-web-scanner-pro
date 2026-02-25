import asyncio
import logging
import socket
import ipaddress
import time
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional, Callable, Any

from scanner import scoring, reporter
from scanner.correlation import correlate

# Optional "God Mode" components (keep them modular)
try:
    from scanner.attack_graph import build_attack_paths
except Exception:
    build_attack_paths = None

try:
    from scanner.policy import evaluate_policy
except Exception:
    evaluate_policy = None

try:
    from scanner.diff import diff_scans
except Exception:
    diff_scans = None

from scanner.storage import Storage
from scanner.core.profiles import get_profile
from scanner.core.plugin_loader import load_plugins
from scanner.core.crawler import Crawler
from scanner.core.task_queue import TaskQueue

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def _emit(progress_cb: Optional[Callable[[dict], Any]], event: str, message: str, data: dict | None = None):
    """
    Emit progress events for SSE/UI. Must never break scan.
    """
    if callable(progress_cb):
        try:
            progress_cb({
                "ts": time.time(),
                "event": event,
                "message": message,
                "data": data or {},
            })
        except Exception:
            pass


class ScannerEngine:
    """
    Async scanning orchestrator (reliability + UI streaming).

    - Normalize + validate target
    - Crawl endpoints (depth-controlled)
    - Load modules via plugin_loader (profile enable/disable)
    - Run modules with TaskQueue + per-module timeout
    - Correlate findings
    - Score (CVSS-aware via scoring.calculate_score)
    - Optional diff + policy + attack paths
    - Persist to SQLite
    - Produce JSON/HTML/PDF payloads
    """

    def __init__(self, target: str, profile: str = "normal"):
        self.target = self._normalize_target(target)
        self.profile = get_profile(profile)

        self.findings: list[dict] = []

        # concurrency for module execution (TaskQueue also uses profile.concurrency)
        self.semaphore = asyncio.Semaphore(self.profile.concurrency)

        self._validate_target()

        # storage (SQLite) - ensure data/ exists
        data_dir = Path("data")
        data_dir.mkdir(parents=True, exist_ok=True)
        self.storage = Storage(str(data_dir / "scanner.db"))

    # -------------------------
    # Target Handling
    # -------------------------

    def _normalize_target(self, target: str) -> str:
        t = (target or "").strip()
        if not t.startswith(("http://", "https://")):
            t = "http://" + t
        return t.rstrip("/")

    def _validate_target(self):
        parsed = urlparse(self.target)
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Invalid target URL")

        try:
            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)

            # Guardrails against scanning private/internal ranges by accident
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                raise ValueError("Scanning private/internal IPs is not allowed.")
        except Exception as e:
            raise ValueError(f"Target validation failed: {e}")

    # -------------------------
    # Crawling
    # -------------------------

    async def crawl_endpoints(self, progress_cb=None) -> list[str]:
        _emit(progress_cb, "crawl_start", "Crawler starting…", {
            "depth": self.profile.depth,
            "max_pages": self.profile.max_pages,
            "include_query": self.profile.include_query,
        })

        crawler = Crawler(
            base_url=self.target,
            max_depth=self.profile.depth,
            concurrency=self.profile.concurrency,
            include_query=self.profile.include_query,
        )

        endpoints = await crawler.crawl()
        endpoints = endpoints[: self.profile.max_pages]

        _emit(progress_cb, "crawl_done", f"Crawler discovered {len(endpoints)} endpoints", {"count": len(endpoints)})
        return endpoints

    # -------------------------
    # Module Loading
    # -------------------------

    async def load_modules(self, progress_cb=None):
        _emit(progress_cb, "plugins_discover", "Discovering plugins…", {})
        plugins = load_plugins(
            enabled_modules=self.profile.enabled_modules,
            disabled_modules=self.profile.disabled_modules,
            strict=False,
        )
        loaded = [p["module"] for p in plugins if p.get("loaded")]

        _emit(progress_cb, "modules_loaded", f"Loaded {len(loaded)} modules", {"count": len(loaded)})
        return loaded

    # -------------------------
    # Module Execution
    # -------------------------

    async def run_module(self, module, endpoints: list[str], progress_cb=None):
        name = module.__name__.split(".")[-1]
        _emit(progress_cb, "module_start", f"Running module: {name}", {"module": name})

        async with self.semaphore:
            try:
                # Prefer scan(target, endpoints=endpoints) if supported
                try:
                    coro = module.scan(self.target, endpoints=endpoints)
                except TypeError:
                    coro = module.scan(self.target)

                results = await asyncio.wait_for(coro, timeout=self.profile.module_timeout_sec)

                if results and isinstance(results, list):
                    self.findings.extend(results)
                    _emit(progress_cb, "module_done", f"Finished module: {name}", {
                        "module": name,
                        "findings": len(results),
                    })
                else:
                    _emit(progress_cb, "module_done", f"Finished module: {name}", {
                        "module": name,
                        "findings": 0,
                    })

            except asyncio.TimeoutError:
                _emit(progress_cb, "module_timeout", f"Timeout in module: {name}", {"module": name})
            except Exception as e:
                _emit(progress_cb, "module_error", f"Error in module: {name}", {"module": name, "error": str(e)})

    # -------------------------
    # Main Execution
    # -------------------------

    async def run(self, output_format: str = "json", progress_cb=None):
        fmt = (output_format or "json").strip().lower()

        _emit(progress_cb, "scan_start", f"Scan started for {self.target}", {
            "target": self.target,
            "profile": self.profile.name,
            "output_format": fmt,
        })
        logger.info(f"[ENGINE] Starting scan on {self.target} (profile={self.profile.name})")

        # 1) Crawl
        endpoints = await self.crawl_endpoints(progress_cb=progress_cb)

        # 2) Load modules
        modules = await self.load_modules(progress_cb=progress_cb)

        # 3) Run modules via TaskQueue (avoid lambda late-binding by binding default args)
        _emit(progress_cb, "modules_run", "Executing modules…", {"count": len(modules)})

        queue = TaskQueue(concurrency=self.profile.concurrency, task_timeout=self.profile.module_timeout_sec)

        for mod in modules:
            async def task(mod_=mod):
                await self.run_module(mod_, endpoints=endpoints, progress_cb=progress_cb)
            await queue.add(task)

        qstats = await queue.run()
        _emit(progress_cb, "modules_done", "All modules finished", qstats)

        # 4) Correlate / dedupe
        _emit(progress_cb, "correlate", "Correlating findings…", {"pre_count": len(self.findings)})
        self.findings = correlate(self.findings)
        _emit(progress_cb, "correlate_done", "Correlation complete", {"count": len(self.findings)})

        # 5) Score
        _emit(progress_cb, "score", "Scoring findings…", {"count": len(self.findings)})
        score_data = scoring.calculate_score(self.findings)
        _emit(progress_cb, "score_done", "Scoring complete", {"score": score_data.get("score"), "grade": score_data.get("grade")})

        # 6) Previous scan + diff (optional)
        diff = {}
        prev = None
        try:
            prev = self.storage.get_latest_scan(self.target)
            if prev and callable(diff_scans):
                curr_obj = {"findings": self.findings, "score": score_data}
                diff = diff_scans(prev, curr_obj) or {}
        except Exception:
            diff = {}

        # 7) Attack paths + policy (optional)
        attack_paths = []
        policy = {"decision": "pass", "reasons": []}

        try:
            if callable(build_attack_paths):
                attack_paths = build_attack_paths(self.findings) or []
        except Exception:
            attack_paths = []

        try:
            if callable(evaluate_policy):
                policy = evaluate_policy(score_data, self.findings, diff, attack_paths) or policy
        except Exception:
            policy = policy

        # 8) Unified result object
        result_obj = {
            "target": self.target,
            "profile": self.profile.name,
            "score": score_data,
            "policy": policy,
            "diff": diff,
            "attack_paths": attack_paths,
            "findings": self.findings,
        }

        # 9) Persist
        scan_id = None
        try:
            _emit(progress_cb, "persist_start", "Saving scan to storage…", {})
            scan_id = self.storage.save_scan(
                target=self.target,
                score_data=score_data,
                findings=self.findings,
                raw_json=result_obj,
            )
            result_obj["scan_id"] = scan_id
            _emit(progress_cb, "persist_done", "Scan saved", {"scan_id": scan_id})
        except Exception as e:
            _emit(progress_cb, "persist_error", "Failed to save scan", {"error": str(e)})

        # 10) Report payloads
        if fmt == "pdf":
            pdf_bytes = reporter.generate_pdf(self.findings)
            _emit(progress_cb, "scan_done", "Scan completed ✅", {"scan_id": scan_id, "format": "pdf"})
            return {**result_obj, "pdf_bytes": pdf_bytes}

        if fmt == "html":
            html = reporter.generate_html(self.target, self.findings, score_data)
            _emit(progress_cb, "scan_done", "Scan completed ✅", {"scan_id": scan_id, "format": "html"})
            return {**result_obj, "html": html}

        json_text = reporter.generate_json(self.target, self.findings, score_data)
        _emit(progress_cb, "scan_done", "Scan completed ✅", {"scan_id": scan_id, "format": "json"})
        return {**result_obj, "json": json_text}


# -------------------------
# CLI Runner
# -------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m scanner.engine <target> [profile] [format]")
        print("Example: python -m scanner.engine https://example.com normal json")
        sys.exit(1)

    target = sys.argv[1]
    profile = sys.argv[2] if len(sys.argv) >= 3 else "normal"
    outfmt = sys.argv[3] if len(sys.argv) >= 4 else "json"

    engine = ScannerEngine(target, profile=profile)
    result = asyncio.run(engine.run(output_format=outfmt))
    print(result)
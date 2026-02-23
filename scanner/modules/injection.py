import aiohttp
import re
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from hashlib import sha256
from typing import List, Dict, Any, Optional

# --- SQL error patterns (error-based signal) ---
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "sql syntax",
    "mysql_fetch",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pdoexception",
    "odbc sql",
    "ora-",
    "sqlite error",
    "psql:",
    "postgresql",
]

# --- XSS payload (reflection check) ---
XSS_PAYLOAD = "<script>alert(1)</script>"

# --- Sensitive exposure patterns (signal; can be Critical with strong proof) ---
SENSITIVE_PATTERNS = [
    ("Private Key Block", re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA)? ?PRIVATE KEY-----")),
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Generic API Key", re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?key)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
    ("DB Connection String", re.compile(r"(?i)\b(mysql|postgres|mongodb|redis)://[^ \n\r\"']+")),
    ("Possible /etc/passwd", re.compile(r"(?m)^[a-z_][a-z0-9_-]*:x:\d+:\d+:[^:]*:/[^:]*:/[^:\n]*$")),
    ("Stack Trace", re.compile(r"(?i)(traceback \(most recent call last\)|exception in thread|stack trace)")),
]

TIMEOUT_SEC = 12
MAX_URLS_PER_SCAN = 150
MAX_PARAMS_PER_URL = 12
CONTENT_READ_LIMIT = 250_000


def _severity_for_sensitive(label: str) -> str:
    # True "critical proof" buckets:
    if label in ("Private Key Block", "AWS Access Key"):
        return "Critical"
    if label in ("Google API Key", "DB Connection String", "Generic API Key"):
        return "High"
    if label in ("Possible /etc/passwd",):
        return "High"
    if label in ("Stack Trace",):
        return "Low"
    return "Medium"


def _sig(text: str) -> str:
    return sha256(text[:5000].encode("utf-8", errors="ignore")).hexdigest()[:16]


def _set_query_param(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[key] = value
    new_query = urlencode(q, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, ""))


def _extract_snippet(text: str, match: re.Match, window: int = 90) -> str:
    start = max(0, match.start() - window)
    end = min(len(text), match.end() + window)
    snippet = text[start:end].replace("\n", " ")
    return snippet[:260]


async def _fetch(session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
    async with session.get(url, allow_redirects=True) as r:
        text = await r.text(errors="ignore")
        if len(text) > CONTENT_READ_LIMIT:
            text = text[:CONTENT_READ_LIMIT]

        return {
            "status": r.status,
            "url": str(r.url),
            "len": len(text),
            "sig": _sig(text),
            "body": text,
            "body_lower": text.lower(),
            "content_type": (r.headers.get("Content-Type") or "").lower(),
        }


def _is_text_like(content_type: str) -> bool:
    return any(ct in content_type for ct in ("text/html", "application/json", "text/plain"))


async def scan(target: str, endpoints: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    seen = set()  # dedup key set

    urls = endpoints or [target]
    param_urls = [u for u in urls if "?" in u]
    param_urls = param_urls[:MAX_URLS_PER_SCAN]

    if not param_urls:
        return findings

    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SEC)
    headers = {"User-Agent": "OWASP-Web-Scanner-Pro/1.0"}

    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        for url in param_urls:
            try:
                baseline = await _fetch(session, url)
            except Exception:
                continue

            if not _is_text_like(baseline["content_type"]):
                continue

            p = urlparse(url)
            params = list(parse_qsl(p.query, keep_blank_values=True))[:MAX_PARAMS_PER_URL]

            for (param, _) in params:
                # --- XSS reflection test ---
                try:
                    xss_url = _set_query_param(url, param, XSS_PAYLOAD)
                    ev = await _fetch(session, xss_url)

                    # Only consider if text-like
                    if not _is_text_like(ev["content_type"]):
                        continue

                    reflected = XSS_PAYLOAD.lower() in ev["body_lower"]
                    changed = (ev["sig"] != baseline["sig"]) or (abs(ev["len"] - baseline["len"]) > 150)

                    if reflected:
                        key = ("xss", ev["url"], param)
                        if key not in seen:
                            seen.add(key)
                            findings.append({
                                "title": f"Reflected XSS Detected (param: {param})",
                                "severity": "High",
                                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                                "description": "Injected script payload was reflected in the response without safe encoding.",
                                "remediation": "Use context-aware output encoding and validate/sanitize input server-side.",
                                "metadata": {
                                    "endpoint": ev["url"],
                                    "parameter": param,
                                    "evidence": "payload_reflected",
                                    "baseline_status": baseline["status"],
                                    "test_status": ev["status"],
                                }
                            })

                    # --- SQL error pattern signal ---
                    if changed:
                        for err in SQL_ERRORS:
                            if err in ev["body_lower"]:
                                key = ("sqli_error", ev["url"], param, err)
                                if key not in seen:
                                    seen.add(key)
                                    findings.append({
                                        "title": f"SQL Error Pattern Signal (param: {param})",
                                        "severity": "High",
                                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                                        "description": f"Response contained a database error pattern: '{err}'.",
                                        "remediation": "Use parameterized queries (prepared statements) and strict input validation.",
                                        "metadata": {
                                            "endpoint": ev["url"],
                                            "parameter": param,
                                            "matched_error": err,
                                            "baseline_sig": baseline["sig"],
                                            "test_sig": ev["sig"],
                                        }
                                    })
                                break

                    # --- Sensitive content exposure (signal, can be Critical) ---
                    # Scan only if response differs or baseline already seems sensitive
                    scan_sensitive = changed or any(lbl in baseline["body"] for (lbl, _) in [])
                    if scan_sensitive:
                        for label, rx in SENSITIVE_PATTERNS:
                            m = rx.search(ev["body"])
                            if m:
                                sev = _severity_for_sensitive(label)
                                snippet = _extract_snippet(ev["body"], m)

                                key = ("sensitive", label, ev["url"], sha256(snippet.encode("utf-8", errors="ignore")).hexdigest()[:10])
                                if key not in seen:
                                    seen.add(key)
                                    findings.append({
                                        "title": f"Sensitive Content Exposure (Signal): {label}",
                                        "severity": sev,
                                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                                        "description": (
                                            "Response appears to contain sensitive information. "
                                            "This is a strong indicator and should be verified."
                                        ),
                                        "remediation": (
                                            "Remove secrets from responses, disable debug output, store credentials securely "
                                            "(env/secret manager), and rotate any exposed credentials immediately."
                                        ),
                                        "metadata": {
                                            "endpoint": ev["url"],
                                            "parameter_tested": param,
                                            "matched": label,
                                            "snippet": snippet,
                                            "baseline_sig": baseline["sig"],
                                            "test_sig": ev["sig"],
                                        }
                                    })
                                break

                except Exception:
                    continue

    return findings
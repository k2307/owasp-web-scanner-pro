import aiohttp
from urllib.parse import urlparse, parse_qsl, unquote, urlencode, urlunparse
import re
import time
from hashlib import sha256

SSRF_KEYWORDS = {
    "url","uri","dest","destination","next","redirect","return","continue",
    "callback","feed","image","avatar","file","download","proxy","forward",
    "target","endpoint","host","domain","remote"
}

NESTED_URL_RE = re.compile(r"(?i)\bhttps?%3a%2f%2f|https?://|//[a-z0-9\.-]+\.[a-z]{2,}")

# benign, non-exploit, used only for differential behavior checks
BENIGN_URLLIKE_VALUES = [
    "https://example.com",
    "//example.com",
    "https:%2f%2fexample.com",
]

def _extract_params(url: str):
    p = urlparse(url)
    return list(parse_qsl(p.query, keep_blank_values=True))

def _looks_like_url(value: str) -> bool:
    if not value:
        return False
    v = value.strip()
    v_dec = unquote(v)
    return bool(NESTED_URL_RE.search(v) or NESTED_URL_RE.search(v_dec))

def _set_param(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[key] = value
    new_query = urlencode(q, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))

def _hash_text(text: str) -> str:
    return sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]

async def _fetch_evidence(session: aiohttp.ClientSession, url: str) -> dict:
    """
    Quietly fetch response metadata for correlation/evidence.
    """
    t0 = time.perf_counter()
    async with session.get(url, allow_redirects=False) as r:
        # Read limited text to avoid memory blowups
        body = await r.text(errors="ignore")
        dt_ms = int((time.perf_counter() - t0) * 1000)

        headers = {k.lower(): v for k, v in r.headers.items()}
        ctype = headers.get("content-type", "")
        location = headers.get("location", "")

        # keep fingerprint headers only (avoid dumping everything)
        fingerprint = {}
        for h in ("server", "x-powered-by", "via"):
            if h in headers:
                fingerprint[h] = headers[h]

        return {
            "status": r.status,
            "len": len(body),
            "hash": _hash_text(body),
            "content_type": ctype,
            "location": location,
            "time_ms": dt_ms,
            "fingerprint_headers": fingerprint,
        }

async def scan(target: str):
    findings = []
    timeout = aiohttp.ClientTimeout(total=12)
    headers = {"User-Agent": "OWASP-Web-Scanner-Pro/1.0"}

    params = _extract_params(target)
    if not params:
        return findings

    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        # Baseline evidence
        try:
            baseline = await _fetch_evidence(session, target)
        except Exception:
            return findings

        path = urlparse(target).path.lower()

        for k, v in params:
            k_l = (k or "").lower()
            confidence = "low"
            reasons = []

            if k_l in SSRF_KEYWORDS:
                confidence = "medium"
                reasons.append("parameter_name_keyword")

            if _looks_like_url(v):
                confidence = "high"
                reasons.append("value_looks_like_url")

            if any(x in path for x in ("/fetch", "/proxy", "/download", "/import", "/url", "/redirect")):
                if confidence == "low":
                    confidence = "medium"
                reasons.append("endpoint_name_suggests_fetching")

            if confidence == "low":
                continue

            # Quiet differential behavior checks (benign)
            diffs = []
            for payload in BENIGN_URLLIKE_VALUES:
                test_url = _set_param(target, k, payload)
                try:
                    ev = await _fetch_evidence(session, test_url)

                    diffs.append({
                        "payload": payload,
                        "status_delta": ev["status"] != baseline["status"],
                        "len_delta": abs(ev["len"] - baseline["len"]),
                        "hash_changed": ev["hash"] != baseline["hash"],
                        "redirected": bool(ev.get("location")),
                        "status": ev["status"],
                        "location": ev.get("location", ""),
                        "time_ms": ev.get("time_ms", None),
                    })
                except Exception:
                    continue

            # Confidence bump if behavior changes significantly
            behavior_changed = any(
                d["status_delta"] or d["hash_changed"] or d["redirected"] or d["len_delta"] > 200
                for d in diffs
            )
            if behavior_changed and confidence == "medium":
                confidence = "high"
                reasons.append("response_behavior_changed_on_urllike_value")

            findings.append({
                "title": f"Possible SSRF Surface: {k}",
                "severity": "Medium" if confidence == "medium" else "High",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                "description": (
                    "This endpoint appears to accept a URL-like input or a parameter name commonly "
                    "associated with server-side fetching. Evidence shows response behavior differences "
                    "when supplying benign URL-like values."
                    if behavior_changed else
                    "This endpoint appears to accept a URL-like input or a parameter name commonly "
                    "associated with server-side fetching. This is not confirmation of SSRF by itself."
                ),
                "remediation": (
                    "If server-side URL fetching occurs: enforce allowlists, validate scheme/host, "
                    "resolve DNS and block private/loopback/link-local ranges, and disable redirects."
                ),
                "metadata": {
                    "endpoint": target,
                    "parameter": k,
                    "sample_value": v[:120] if isinstance(v, str) else str(v)[:120],
                    "confidence": confidence,
                    "signals": reasons,
                    "baseline": baseline,
                    "differential_tests": diffs[:5],  # cap output
                }
            })

    return findings
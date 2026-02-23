import aiohttp
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

REDIRECT_PARAMS = ["redirect", "url", "next", "return", "returnTo", "continue", "dest", "destination"]

# payloads that commonly trigger open redirect bugs
PAYLOADS = [
    "https://evil.example",          # absolute
    "//evil.example",               # scheme-relative
    "///evil.example",              # triple slash weirdness
    "https:%2f%2fevil.example",      # encoded slashes
    "%2f%2fevil.example",           # encoded scheme-relative
]

VALID_REDIRECT_CODES = {301, 302, 303, 307, 308}


def _set_query_param(url: str, key: str, value: str) -> str:
    """
    Safely add/replace a query parameter in a URL.
    """
    parts = list(urlparse(url))
    query = dict(parse_qsl(parts[4], keep_blank_values=True))
    query[key] = value
    parts[4] = urlencode(query, doseq=True)
    return urlunparse(parts)


def _looks_like_external_redirect(location: str, evil_host: str) -> bool:
    """
    Check if Location header points to evil host.
    Handles absolute and scheme-relative redirects.
    """
    if not location:
        return False

    loc = location.strip()

    # Absolute URL
    if loc.startswith("http://") or loc.startswith("https://"):
        return urlparse(loc).netloc.lower() == evil_host

    # Scheme-relative
    if loc.startswith("//"):
        return urlparse("https:" + loc).netloc.lower() == evil_host

    return False


async def scan(target: str):
    findings = []
    timeout = aiohttp.ClientTimeout(total=12)

    headers = {
        "User-Agent": "OWASP-Web-Scanner-Pro/1.0"
    }

    evil_host = "evil.example"

    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        for param in REDIRECT_PARAMS:
            for payload in PAYLOADS:
                test_url = _set_query_param(target, param, payload)

                try:
                    async with session.get(test_url, allow_redirects=False) as r:
                        location = r.headers.get("Location", "")

                        if r.status in VALID_REDIRECT_CODES and _looks_like_external_redirect(location, evil_host):
                            findings.append({
                                "title": "Open Redirect Detected",
                                "severity": "High",
                                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                                "description": (
                                    f"The application appears to redirect users to an external domain "
                                    f"via parameter '{param}'."
                                ),
                                "remediation": (
                                    "Do not redirect to arbitrary user-provided URLs. "
                                    "Use a strict allowlist of internal paths or known domains."
                                ),
                                "metadata": {
                                    "endpoint": test_url,
                                    "parameter": param,
                                    "payload": payload,
                                    "status": r.status,
                                    "location": location
                                }
                            })

                            # Stop after first confirmed hit for this param (reduces noise)
                            break

                except aiohttp.ClientError:
                    continue
                except Exception:
                    continue

    return findings
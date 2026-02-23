import aiohttp
from urllib.parse import urljoin

TEST_PATHS = [
    "/uploads/",
    "/images/",
    "/backup/",
    "/files/",
    "/static/",
    "/private/",
]

# Common directory listing fingerprints across servers
SIGNATURES = [
    "Index of /",                      # Apache
    "<title>Index of",                 # Apache alt
    "Directory listing for",           # Some frameworks
    "Parent Directory",                # Apache
    "nginx",                           # Nginx listing often includes this
    "<h1>Directory listing for",       # Generic
    "Listing directory",               # Generic
    "Last modified</a>",               # Apache listing table
    "Name</a>",                        # Apache listing table
    "Size</a>",                        # Apache listing table
    "IIS",                             # IIS may leak in listing-like pages
]

async def scan(target: str):
    findings = []
    timeout = aiohttp.ClientTimeout(total=12)

    headers = {
        "User-Agent": "OWASP-Web-Scanner-Pro/1.0"
    }

    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        for path in TEST_PATHS:
            url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))

            try:
                async with session.get(url, allow_redirects=True) as r:
                    # Only interesting if response is OK-ish
                    if r.status not in (200, 206):
                        continue

                    content_type = (r.headers.get("Content-Type") or "").lower()

                    # Directory listing pages are usually HTML
                    if "text/html" not in content_type:
                        # Still try small read in case server mislabels
                        body = await r.text(errors="ignore")
                    else:
                        body = await r.text(errors="ignore")

                    body_lower = body.lower()

                    # Stronger detection: signature + directory markers
                    matched = None
                    for sig in SIGNATURES:
                        if sig.lower() in body_lower:
                            matched = sig
                            break

                    # Require "directory-ish" markers to reduce false positives
                    directory_markers = ("parent directory" in body_lower) or ("href=" in body_lower and "last modified" in body_lower)

                    if matched and directory_markers:
                        findings.append({
                            "title": "Directory Listing Enabled",
                            "severity": "Medium",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                            "description": f"Directory listing appears enabled at {url}",
                            "remediation": (
                                "Disable directory indexing/autoindex. "
                                "For Nginx: remove 'autoindex on;'. "
                                "For Apache: disable 'Indexes' option. "
                                "For IIS: disable 'Directory Browsing'."
                            ),
                            "metadata": {
                                "endpoint": url,
                                "status": r.status,
                                "matched_signature": matched
                            }
                        })

            except aiohttp.ClientError:
                # network/SSL issues -> ignore safely
                continue
            except Exception:
                continue

    return findings
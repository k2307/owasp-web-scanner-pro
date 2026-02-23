import aiohttp
import re

# Detect typical version patterns: nginx/1.25.3, Apache/2.4.58, PHP/8.2.1, OpenSSL/3.0.2 etc.
VERSION_PATTERN = re.compile(r"(?i)\b[a-z0-9\-_]+\/\d+(?:\.\d+){1,3}\b")

# Headers that frequently disclose product/version
DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "Via",
    "X-Generator"
]

async def scan(target: str):
    findings = []
    timeout = aiohttp.ClientTimeout(total=12)
    headers = {"User-Agent": "OWASP-Web-Scanner-Pro/1.0"}

    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.get(target, allow_redirects=True) as r:
                exposed = {}

                for h in DISCLOSURE_HEADERS:
                    val = r.headers.get(h)
                    if not val:
                        continue

                    # Flag if it clearly contains a product/version token
                    if VERSION_PATTERN.search(val):
                        exposed[h] = val

                if exposed:
                    findings.append({
                        "title": "Software Version Disclosure in Response Headers",
                        "severity": "Low",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                        "description": (
                            "The response headers disclose software names/versions. "
                            "This can help attackers fingerprint the stack and target known vulnerabilities."
                        ),
                        "remediation": (
                            "Remove or minimize version disclosure in headers. "
                            "For Nginx: 'server_tokens off;'. "
                            "For Apache: 'ServerTokens Prod' and 'ServerSignature Off'. "
                            "Also disable X-Powered-By in application frameworks."
                        ),
                        "metadata": {
                            "endpoint": str(r.url),
                            "disclosed_headers": exposed
                        }
                    })

    except aiohttp.ClientError:
        pass
    except Exception:
        pass

    return findings
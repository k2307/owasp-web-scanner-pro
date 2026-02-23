import aiohttp
from urllib.parse import urlparse

HEADERS_TO_CHECK = {
    "strict-transport-security": "Enforce HTTPS via HSTS.",
    "content-security-policy": "Prevent XSS via CSP.",
    "x-frame-options": "Prevent clickjacking.",
    "x-content-type-options": "Prevent MIME sniffing.",
    "referrer-policy": "Control referrer leakage.",
    "permissions-policy": "Restrict powerful browser features."
}

GOOD_XCTO = {"nosniff"}
GOOD_XFO = {"deny", "sameorigin"}


def _add_finding(findings, title, severity, description, remediation, metadata=None):
    findings.append({
        "title": title,
        "severity": severity,
        "description": description,
        "remediation": remediation,
        "metadata": metadata or {}
    })


async def scan(target: str):
    findings = []
    timeout = aiohttp.ClientTimeout(total=12)
    headers = {"User-Agent": "OWASP-Web-Scanner-Pro/1.0"}

    parsed = urlparse(target)
    is_https = parsed.scheme.lower() == "https"

    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.get(target, allow_redirects=True) as r:
                resp_headers = {k.lower(): v for k, v in r.headers.items()}

                # -------------------------
                # Missing headers
                # -------------------------
                for h, rec in HEADERS_TO_CHECK.items():
                    if h not in resp_headers:
                        # HSTS only relevant on HTTPS
                        if h == "strict-transport-security" and not is_https:
                            continue

                        _add_finding(
                            findings,
                            title=f"Missing Security Header: {h}",
                            severity="Medium",
                            description=f"The response is missing '{h}'.",
                            remediation=rec,
                            metadata={"endpoint": str(r.url)}
                        )

                # -------------------------
                # Weak / misconfigured values
                # -------------------------

                # HSTS checks (only meaningful on HTTPS)
                if is_https and "strict-transport-security" in resp_headers:
                    hsts = resp_headers["strict-transport-security"].lower()

                    # Very basic checks
                    if "max-age" not in hsts:
                        _add_finding(
                            findings,
                            "Weak HSTS Policy",
                            "Medium",
                            "HSTS header is present but missing 'max-age'.",
                            "Set Strict-Transport-Security with a max-age, includeSubDomains, and optionally preload.",
                            {"value": resp_headers["strict-transport-security"], "endpoint": str(r.url)}
                        )
                    elif "max-age=0" in hsts:
                        _add_finding(
                            findings,
                            "HSTS Disabled (max-age=0)",
                            "High",
                            "HSTS is effectively disabled by max-age=0.",
                            "Set a strong max-age (e.g., 15552000+), includeSubDomains, and optionally preload.",
                            {"value": resp_headers["strict-transport-security"], "endpoint": str(r.url)}
                        )
                    elif "includesubdomains" not in hsts:
                        _add_finding(
                            findings,
                            "HSTS Missing includeSubDomains",
                            "Low",
                            "HSTS does not include subdomains, leaving them downgradeable.",
                            "Add includeSubDomains if appropriate for your domain structure.",
                            {"value": resp_headers["strict-transport-security"], "endpoint": str(r.url)}
                        )

                # X-Content-Type-Options checks
                if "x-content-type-options" in resp_headers:
                    xcto = resp_headers["x-content-type-options"].strip().lower()
                    if xcto not in GOOD_XCTO:
                        _add_finding(
                            findings,
                            "Weak X-Content-Type-Options",
                            "Low",
                            f"Unexpected X-Content-Type-Options value: '{xcto}'.",
                            "Set X-Content-Type-Options: nosniff",
                            {"value": resp_headers["x-content-type-options"], "endpoint": str(r.url)}
                        )

                # X-Frame-Options checks
                if "x-frame-options" in resp_headers:
                    xfo = resp_headers["x-frame-options"].strip().lower()
                    # allow-from is obsolete/inconsistent
                    if xfo.startswith("allow-from"):
                        _add_finding(
                            findings,
                            "Deprecated X-Frame-Options Policy",
                            "Low",
                            "X-Frame-Options uses ALLOW-FROM which is not consistently supported.",
                            "Prefer CSP frame-ancestors over ALLOW-FROM. Use DENY or SAMEORIGIN otherwise.",
                            {"value": resp_headers["x-frame-options"], "endpoint": str(r.url)}
                        )
                    elif xfo not in GOOD_XFO:
                        _add_finding(
                            findings,
                            "Weak X-Frame-Options Policy",
                            "Low",
                            f"Unexpected X-Frame-Options value: '{xfo}'.",
                            "Use X-Frame-Options: DENY or SAMEORIGIN, and/or CSP frame-ancestors.",
                            {"value": resp_headers["x-frame-options"], "endpoint": str(r.url)}
                        )

                # CSP checks
                if "content-security-policy" in resp_headers:
                    csp = resp_headers["content-security-policy"]
                    csp_l = csp.lower()

                    if "unsafe-inline" in csp_l or "unsafe-eval" in csp_l:
                        _add_finding(
                            findings,
                            "Weak Content-Security-Policy",
                            "Medium",
                            "CSP contains 'unsafe-inline' or 'unsafe-eval' which weakens XSS protections.",
                            "Avoid unsafe-inline/unsafe-eval. Use nonces/hashes for scripts and strict directives.",
                            {"value": csp, "endpoint": str(r.url)}
                        )

                    # Very basic quality checks
                    if "default-src" not in csp_l:
                        _add_finding(
                            findings,
                            "Incomplete Content-Security-Policy",
                            "Low",
                            "CSP is present but missing default-src, which is recommended as a baseline.",
                            "Add a restrictive default-src and explicitly allow required sources.",
                            {"value": csp, "endpoint": str(r.url)}
                        )

                # Referrer-Policy checks (basic)
                if "referrer-policy" in resp_headers:
                    rp = resp_headers["referrer-policy"].lower()
                    if "unsafe-url" in rp:
                        _add_finding(
                            findings,
                            "Weak Referrer-Policy",
                            "Low",
                            "Referrer-Policy is set to unsafe-url, which can leak sensitive paths/params.",
                            "Prefer strict-origin-when-cross-origin or no-referrer depending on use-case.",
                            {"value": resp_headers["referrer-policy"], "endpoint": str(r.url)}
                        )

                # Server banner disclosure (optional but useful)
                if "server" in resp_headers:
                    _add_finding(
                        findings,
                        "Server Version Disclosure",
                        "Low",
                        f"Server header exposed: {resp_headers.get('server')}",
                        "Mask or remove the Server header in production.",
                        {"value": resp_headers.get("server"), "endpoint": str(r.url)}
                    )

    except aiohttp.ClientError:
        # network/ssl issues - ignore silently for private tool
        return findings
    except Exception:
        return findings

    return findings
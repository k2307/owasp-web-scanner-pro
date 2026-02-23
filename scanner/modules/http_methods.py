import aiohttp

# Methods commonly considered risky if unnecessary
DANGEROUS_METHODS = [
    "PUT",
    "DELETE",
    "TRACE",
    "CONNECT",
    "PATCH",
    "PROPFIND",   # WebDAV
    "PROPPATCH",  # WebDAV
    "MKCOL",      # WebDAV
]

async def scan(target: str):
    findings = []

    timeout = aiohttp.ClientTimeout(total=12)

    headers = {
        "User-Agent": "OWASP-Web-Scanner-Pro/1.0"
    }

    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:

            # -------------------------
            # Passive check via OPTIONS
            # -------------------------
            async with session.options(target, allow_redirects=True) as r:

                allow_header = (r.headers.get("Allow") or "")
                cors_header = (r.headers.get("Access-Control-Allow-Methods") or "")

                methods_raw = f"{allow_header},{cors_header}"
                methods = {m.strip().upper() for m in methods_raw.split(",") if m.strip()}

                for method in DANGEROUS_METHODS:
                    if method in methods:
                        findings.append({
                            "title": f"Dangerous HTTP Method Enabled: {method}",
                            "severity": "High",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                            "description": (
                                f"The server advertises support for HTTP method '{method}'. "
                                "Unnecessary methods increase attack surface."
                            ),
                            "remediation": (
                                "Disable unused HTTP methods at web server or reverse proxy level."
                            ),
                            "metadata": {
                                "endpoint": target,
                                "source": "Allow/Access-Control-Allow-Methods header",
                                "allowed_methods": sorted(list(methods))
                            }
                        })

            # -------------------------
            # Active verification (safe)
            # -------------------------
            # Some servers don't advertise methods but still allow them.
            # We test with harmless request bodies.
            for method in ["TRACE", "PUT", "DELETE"]:
                try:
                    async with session.request(
                        method,
                        target,
                        data="test",
                        allow_redirects=False
                    ) as probe:

                        # 2xx / 3xx / 405 logic:
                        # - 405 = blocked (good)
                        # - 501 = not implemented (good)
                        # anything else may indicate enabled
                        if probe.status not in (405, 501):
                            findings.append({
                                "title": f"HTTP Method Possibly Enabled: {method}",
                                "severity": "Medium",
                                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                                "description": (
                                    f"Server responded with status {probe.status} "
                                    f"to a {method} request."
                                ),
                                "remediation": "Explicitly deny unnecessary HTTP methods.",
                                "metadata": {
                                    "endpoint": target,
                                    "probe_status": probe.status,
                                    "source": "active verification"
                                }
                            })

                except aiohttp.ClientError:
                    continue

    except aiohttp.ClientError:
        pass
    except Exception:
        pass

    return findings
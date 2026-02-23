import aiohttp

SECURITY_HEADERS = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy"
]

SENSITIVE_PATHS = [
    "/.env",
    "/config.php",
    "/backup.zip",
    "/admin/",
    "/phpinfo.php"
]

async def scan(target):
    findings = []

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(target, headers={
                "User-Agent": "Mozilla/5.0"
            }) as response:

                # Missing Security Headers
                for header in SECURITY_HEADERS:
                    if header not in response.headers:
                        findings.append({
                            "title": f"Missing Security Header: {header}",
                            "severity": "Medium",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                            "description": f"{header} header is missing.",
                            "remediation": f"Configure server to include {header}."
                        })

                # Server Banner Disclosure
                if "Server" in response.headers:
                    findings.append({
                        "title": "Server Version Disclosure",
                        "severity": "Low",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                        "description": f"Server header exposed: {response.headers.get('Server')}",
                        "remediation": "Disable or mask server version headers."
                    })

                # Check for Directory Listing
                text = await response.text()
                if "Index of /" in text:
                    findings.append({
                        "title": "Directory Listing Enabled",
                        "severity": "High",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                        "description": "Directory listing appears to be enabled.",
                        "remediation": "Disable directory listing in web server configuration."
                    })

                # Check Allowed HTTP Methods
                async with session.options(target) as options_response:
                    allow = options_response.headers.get("Allow", "")
                    if any(method in allow for method in ["PUT", "DELETE", "TRACE"]):
                        findings.append({
                            "title": "Dangerous HTTP Methods Enabled",
                            "severity": "Medium",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                            "description": f"Server allows risky methods: {allow}",
                            "remediation": "Disable unnecessary HTTP methods."
                        })

        except Exception as e:
            findings.append({
                "title": "Misconfiguration Scan Failed",
                "severity": "Info",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                "description": str(e),
                "remediation": "Ensure target is reachable."
            })

        # Sensitive Files Exposure
        for path in SENSITIVE_PATHS:
            try:
                async with session.get(target.rstrip("/") + path) as r:
                    if r.status == 200:
                        findings.append({
                            "title": f"Sensitive File Exposed: {path}",
                            "severity": "High",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                            "description": f"{path} is publicly accessible.",
                            "remediation": "Restrict access to sensitive files."
                        })
            except:
                pass

    return findings
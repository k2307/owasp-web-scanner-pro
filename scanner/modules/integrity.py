import aiohttp
import re

SENSITIVE_FILES = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/backup.zip",
    "/backup.tar.gz",
    "/config.php",
    "/package.json",
    "/composer.json",
    "/.DS_Store"
]

async def scan(target):
    findings = []

    async with aiohttp.ClientSession() as session:
        try:
            base = target.rstrip("/")

            # Sensitive File Exposure
            for file in SENSITIVE_FILES:
                try:
                    async with session.get(base + file) as response:
                        if response.status == 200:
                            findings.append({
                                "title": f"Sensitive File Exposed: {file}",
                                "severity": "High",
                                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                                "description": f"{file} is publicly accessible.",
                                "remediation": "Restrict access to sensitive files via server configuration."
                            })
                except:
                    continue

            # Source Map Exposure
            async with session.get(base) as main_response:
                body = await main_response.text()

                sourcemaps = re.findall(r'src="(.*?\.map)"', body)
                for sm in sourcemaps:
                    findings.append({
                        "title": "Source Map File Referenced",
                        "severity": "Medium",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                        "description": f"Source map file found: {sm}",
                        "remediation": "Remove source maps from production builds."
                    })

                # Check for Subresource Integrity (SRI)
                external_scripts = re.findall(r'<script[^>]+src="https?://[^"]+"[^>]*>', body)

                for script in external_scripts:
                    if "integrity=" not in script:
                        findings.append({
                            "title": "Missing Subresource Integrity (SRI)",
                            "severity": "Medium",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                            "description": "External script loaded without integrity attribute.",
                            "remediation": "Use integrity attribute to ensure script integrity."
                        })
                        break

        except Exception as e:
            findings.append({
                "title": "Integrity Scan Failed",
                "severity": "Info",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                "description": str(e),
                "remediation": "Ensure target is reachable."
            })

    return findings
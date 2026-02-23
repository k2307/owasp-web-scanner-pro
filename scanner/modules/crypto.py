import aiohttp
import re

async def scan(target):
    findings = []

    # Check HTTP instead of HTTPS
    if target.startswith("http://"):
        findings.append({
            "title": "Site Not Using HTTPS",
            "severity": "High",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            "description": "The application does not enforce HTTPS. Traffic can be intercepted.",
            "remediation": "Redirect all HTTP traffic to HTTPS and use a valid SSL certificate."
        })

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(target, headers={
                "User-Agent": "Mozilla/5.0"
            }) as response:

                # Check HSTS
                if "Strict-Transport-Security" not in response.headers:
                    findings.append({
                        "title": "HSTS Not Enabled",
                        "severity": "Medium",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                        "description": "Strict-Transport-Security header is missing.",
                        "remediation": "Enable HSTS to enforce HTTPS connections."
                    })

                # Check Secure / HttpOnly Cookies
                cookies = response.cookies
                for cookie in cookies.values():
                    if not cookie["secure"]:
                        findings.append({
                            "title": f"Insecure Cookie: {cookie.key}",
                            "severity": "Medium",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                            "description": "Cookie does not have Secure flag.",
                            "remediation": "Set Secure flag on cookies."
                        })
                    if not cookie["httponly"]:
                        findings.append({
                            "title": f"Cookie Missing HttpOnly: {cookie.key}",
                            "severity": "Low",
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                            "description": "Cookie accessible via JavaScript.",
                            "remediation": "Set HttpOnly flag."
                        })

                # Check Weak Hash Usage in Page
                text = await response.text()
                if re.search(r'\b(md5|sha1)\b', text.lower()):
                    findings.append({
                        "title": "Weak Hash Algorithm Detected",
                        "severity": "Medium",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                        "description": "MD5 or SHA1 detected in page content.",
                        "remediation": "Use SHA-256 or stronger hashing algorithms."
                    })

        except Exception as e:
            findings.append({
                "title": "Crypto Scan Failed",
                "severity": "Info",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                "description": str(e),
                "remediation": "Ensure target is reachable."
            })

    return findings
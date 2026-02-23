
import aiohttp

COMMON_PATHS = ["/admin", "/backup", "/dashboard"]

async def scan(target):
    findings = []
    async with aiohttp.ClientSession() as session:
        for path in COMMON_PATHS:
            try:
                async with session.get(target + path) as r:
                    if r.status == 200:
                        findings.append({
                            "title": f"Exposed Path: {path}",
                            "severity": "Medium",
                            "description": "Sensitive path accessible.",
                            "remediation": "Restrict via authentication."
                        })
            except:
                pass
    return findings

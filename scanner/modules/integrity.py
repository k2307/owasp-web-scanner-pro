
import aiohttp

FILES = ["/.env","/.git/config"]

async def scan(target):
    findings = []
    async with aiohttp.ClientSession() as session:
        for f in FILES:
            try:
                async with session.get(target + f) as r:
                    if r.status == 200:
                        findings.append({
                            "title": f"Exposed File: {f}",
                            "severity": "High",
                            "description": "Sensitive file exposed.",
                            "remediation": "Block access in server config."
                        })
            except:
                pass
    return findings

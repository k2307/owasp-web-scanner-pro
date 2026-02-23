
import aiohttp

HEADERS = ["X-Frame-Options","Content-Security-Policy","X-Content-Type-Options"]

async def scan(target):
    findings = []
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(target) as r:
                for h in HEADERS:
                    if h not in r.headers:
                        findings.append({
                            "title": f"Missing Header: {h}",
                            "severity": "Low",
                            "description": "Security header missing.",
                            "remediation": "Configure server to include header."
                        })
        except:
            pass
    return findings

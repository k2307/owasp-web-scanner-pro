
async def scan(target):
    findings = []
    if target.startswith("http://"):
        findings.append({
            "title": "Site Not Using HTTPS",
            "severity": "High",
            "description": "Traffic is not encrypted.",
            "remediation": "Enable HTTPS with valid certificate."
        })
    return findings

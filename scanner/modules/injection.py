
async def scan(target):
    findings = []
    if "?" in target:
        findings.append({
            "title": "Potential Injection Surface",
            "severity": "Medium",
            "description": "URL contains parameters.",
            "remediation": "Validate and sanitize inputs."
        })
    return findings

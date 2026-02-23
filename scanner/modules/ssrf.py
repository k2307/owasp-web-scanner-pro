
async def scan(target):
    findings = []
    if "url=" in target:
        findings.append({
            "title": "Potential SSRF Parameter Detected",
            "severity": "Medium",
            "description": "URL parameter may allow SSRF.",
            "remediation": "Validate outgoing requests server-side."
        })
    return findings

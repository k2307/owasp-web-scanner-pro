from typing import Any, Dict, List, Set, Tuple


def _has(finds: List[Dict[str, Any]], keyword: str) -> bool:
    kw = keyword.lower()
    for f in finds:
        title = (f.get("title") or "").lower()
        desc = (f.get("description") or "").lower()
        if kw in title or kw in desc:
            return True
    return False


def build_attack_paths(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Rule-based attack chain generator.
    Outputs a list of attack paths with:
      - chain steps
      - impact summary
      - risk level
    """
    paths: List[Dict[str, Any]] = []

    # Signals (keep simple: infer from titles/descriptions you already produce)
    has_xss = _has(findings, "xss")
    has_missing_csp = _has(findings, "content-security-policy") or _has(findings, "missing security header: content-security-policy")
    has_cookie_weak = _has(findings, "httponly") or _has(findings, "secure flag") or _has(findings, "cookie")
    has_idor = _has(findings, "idor")
    has_admin_exposure = _has(findings, "unrestricted access") or _has(findings, "exposed path") or _has(findings, "/admin")
    has_open_redirect = _has(findings, "open redirect")
    has_ssrf = _has(findings, "ssrf")

    # Chain 1: XSS → Session theft / takeover
    if has_xss and (has_missing_csp or has_cookie_weak):
        steps = ["Reflected XSS", "Weak browser defenses (CSP/cookies)", "Session theft / account takeover risk"]
        paths.append({
            "name": "Client-side takeover chain",
            "risk": "Critical" if has_cookie_weak else "High",
            "steps": steps,
            "impact": "Potential account takeover via injected script + weak defenses.",
            "confidence": "high" if (has_missing_csp and has_cookie_weak) else "medium",
        })

    # Chain 2: Admin exposure → Privilege escalation
    if has_admin_exposure:
        steps = ["Sensitive endpoint exposed", "No authentication/authorization gate", "Privilege abuse / data exposure"]
        paths.append({
            "name": "Admin surface exposure chain",
            "risk": "High",
            "steps": steps,
            "impact": "Attackers may access privileged functionality directly.",
            "confidence": "medium",
        })

    # Chain 3: IDOR → Data exfiltration
    if has_idor:
        steps = ["Object-level authorization missing (IDOR)", "Access other users' objects", "Sensitive data exposure / tampering"]
        paths.append({
            "name": "IDOR data access chain",
            "risk": "High",
            "steps": steps,
            "impact": "Unauthorized access to other users' records.",
            "confidence": "medium",
        })

    # Chain 4: Open redirect → Phishing / token theft
    if has_open_redirect:
        steps = ["Open redirect", "Phishing / auth token leakage scenarios", "Account compromise risk"]
        paths.append({
            "name": "Open redirect phishing chain",
            "risk": "Medium",
            "steps": steps,
            "impact": "Can aid phishing and credential/token theft workflows.",
            "confidence": "low",
        })

    # Chain 5: SSRF → internal access
    if has_ssrf:
        steps = ["SSRF surface detected", "Possible internal service reachability", "Metadata / internal data exposure risk"]
        paths.append({
            "name": "SSRF internal pivot chain",
            "risk": "High",
            "steps": steps,
            "impact": "Possible access to internal services or metadata endpoints.",
            "confidence": "low-to-medium",
        })

    return paths
from typing import List, Dict, Any
from copy import deepcopy

SEVERITY_ORDER = ["Info", "Low", "Medium", "High", "Critical"]

def _sev_index(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return 0

def _raise_severity(current: str, new: str) -> str:
    return new if _sev_index(new) > _sev_index(current) else current

def _title_contains(f: Dict[str, Any], text: str) -> bool:
    return text.lower() in str(f.get("title", "")).lower()

def correlate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    correlated = deepcopy(findings)
    titles = [str(f.get("title", "")).lower() for f in correlated]

    def has_kw(kw: str) -> bool:
        kw = kw.lower()
        return any(kw in t for t in titles)

    injection_signals = (
        has_kw("sql injection") or has_kw("reflected xss")
        or has_kw("potential injection") or has_kw("command injection")
    )
    missing_headers = has_kw("missing security header") or has_kw("missing header")

    if injection_signals and missing_headers:
        for f in correlated:
            if _title_contains(f, "missing"):
                old = f.get("severity", "Info")
                f["severity"] = _raise_severity(old, "High")
                f.setdefault("metadata", {})
                f["metadata"]["correlation"] = {
                    "rule": "headers+injection",
                    "note": "Missing defensive headers increases exploitability of injection/XSS signals.",
                    "evidence": ["missing security headers", "injection signal present"]
                }

    http_signal = has_kw("site not using https") or has_kw("http instead of https")
    cookie_signal = has_kw("cookie") and (has_kw("httponly") or has_kw("secure"))

    if http_signal and cookie_signal:
        for f in correlated:
            if _title_contains(f, "https"):
                old = f.get("severity", "Info")
                f["severity"] = _raise_severity(old, "Critical")
                f.setdefault("metadata", {})
                f["metadata"]["correlation"] = {
                    "rule": "http+cookies",
                    "note": "Unencrypted transport + weak cookie flags increases session theft risk.",
                    "evidence": ["http usage", "cookie weakness signal present"]
                }

    waf_present = has_kw("waf detected") or has_kw("web application firewall")
    if waf_present:
        for f in correlated:
            f.setdefault("metadata", {})
            env = f["metadata"].get("environment", {})
            env["waf"] = True
            f["metadata"]["environment"] = env

    return correlated
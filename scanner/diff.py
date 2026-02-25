import hashlib
from typing import Any, Dict, List, Tuple


def _stable_id(f: Dict[str, Any]) -> str:
    """
    Create a stable ID for a finding so we can diff scans.
    We prefer metadata fields if present.
    """
    title = (f.get("title") or "").strip().lower()
    sev = (f.get("severity") or "").strip().lower()

    md = f.get("metadata") or {}
    endpoint = (md.get("endpoint") or md.get("url") or "").strip().lower()
    param = (md.get("parameter") or md.get("param") or "").strip().lower()

    raw = f"{title}|{sev}|{endpoint}|{param}"
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]


def diff_scans(
    prev: Dict[str, Any] | None,
    curr: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Compare two scan results and return deltas:
    - new findings
    - resolved findings
    - severity delta
    - score delta (if present)
    """
    prev = prev or {}
    prev_findings = prev.get("findings") or []
    curr_findings = curr.get("findings") or []

    prev_map = {_stable_id(f): f for f in prev_findings}
    curr_map = {_stable_id(f): f for f in curr_findings}

    new_ids = [i for i in curr_map.keys() if i not in prev_map]
    gone_ids = [i for i in prev_map.keys() if i not in curr_map]

    new_findings = [curr_map[i] for i in new_ids]
    resolved_findings = [prev_map[i] for i in gone_ids]

    prev_score = (prev.get("score") or {}).get("score")
    curr_score = (curr.get("score") or {}).get("score")

    score_delta = None
    if isinstance(prev_score, (int, float)) and isinstance(curr_score, (int, float)):
        score_delta = round(curr_score - prev_score, 2)

    def _sev_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
        out = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            s = (f.get("severity") or "Info").title()
            if s not in out:
                s = "Info"
            out[s] += 1
        return out

    return {
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "new_counts": _sev_counts(new_findings),
        "resolved_counts": _sev_counts(resolved_findings),
        "prev_score": prev_score,
        "curr_score": curr_score,
        "score_delta": score_delta,
    }
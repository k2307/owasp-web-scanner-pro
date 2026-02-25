from __future__ import annotations
from typing import Dict, List, Any, Tuple, Optional
from collections import Counter
import math

# --- Fallback weights when CVSS is not provided ---
SEVERITY_WEIGHT = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 2,
    "Info": 0.5,
}
MAX_POINTS = 100

# --- CVSS v3.1 metric weights (Base) ---
AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
CIA = {"N": 0.00, "L": 0.22, "H": 0.56}

# PR depends on Scope
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}


def _roundup_1(x: float) -> float:
    # CVSS requires rounding up to 1 decimal
    return math.ceil(x * 10.0) / 10.0


def _norm_sev(sev: str) -> str:
    if not sev:
        return "Info"
    s = str(sev).strip().lower()
    if s == "critical":
        return "Critical"
    if s == "high":
        return "High"
    if s == "medium":
        return "Medium"
    if s == "low":
        return "Low"
    return "Info"


def _dedup_key(f: Dict[str, Any]) -> Tuple[str, str, str]:
    title = str(f.get("title", "")).strip().lower()
    md = f.get("metadata") or {}
    endpoint = str(md.get("endpoint") or md.get("url") or "").strip().lower()
    param = str(md.get("parameter") or md.get("parameter_tested") or "").strip().lower()
    return (title, endpoint, param)


def _grade_from_score(score: int) -> str:
    # 0 best, 100 worst
    if score <= 5:
        return "A"
    if score <= 15:
        return "B"
    if score <= 30:
        return "C"
    if score <= 50:
        return "D"
    return "F"


def _severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss > 0.0:
        return "Low"
    return "Info"


def _parse_cvss_vector(vector: str) -> Optional[Dict[str, str]]:
    """
    Accepts vectors like:
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    or without prefix:
      "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    """
    if not vector:
        return None
    v = vector.strip()
    if v.startswith("CVSS:"):
        parts = v.split("/")[1:]  # skip CVSS:3.1
    else:
        parts = v.split("/")

    metrics = {}
    for p in parts:
        if ":" not in p:
            continue
        k, val = p.split(":", 1)
        metrics[k.strip().upper()] = val.strip().upper()

    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(metrics.keys()):
        return None
    return metrics


def _calc_cvss_base(metrics: Dict[str, str]) -> Optional[float]:
    """
    CVSS v3.1 Base Score calculator (base only).
    Returns score 0.0 - 10.0
    """
    try:
        av = AV[metrics["AV"]]
        ac = AC[metrics["AC"]]
        ui = UI[metrics["UI"]]
        s = metrics["S"]
        c = CIA[metrics["C"]]
        i = CIA[metrics["I"]]
        a = CIA[metrics["A"]]

        pr = (PR_C if s == "C" else PR_U)[metrics["PR"]]

        exploitability = 8.22 * av * ac * pr * ui
        impact_sub = 1 - ((1 - c) * (1 - i) * (1 - a))

        if s == "U":
            impact = 6.42 * impact_sub
            if impact <= 0:
                return 0.0
            base = min(impact + exploitability, 10.0)
            return _roundup_1(base)

        # Scope changed
        impact = 7.52 * (impact_sub - 0.029) - 3.25 * pow((impact_sub - 0.02), 15)
        if impact <= 0:
            return 0.0
        base = min(1.08 * (impact + exploitability), 10.0)
        return _roundup_1(base)

    except Exception:
        return None


def _get_cvss_from_finding(f: Dict[str, Any]) -> Optional[float]:
    """
    Supports either:
      f["cvss"] as dict of metrics
      f["cvss_vector"] as string
    """
    if isinstance(f.get("cvss"), dict):
        m = {k.upper(): str(v).upper() for k, v in f["cvss"].items()}
        required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
        if required.issubset(m.keys()):
            return _calc_cvss_base(m)

    vec = f.get("cvss_vector")
    if isinstance(vec, str):
        m = _parse_cvss_vector(vec)
        if m:
            return _calc_cvss_base(m)

    return None


def calculate_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    CVSS-based scoring (minimal-change outputs).

    - If any CVSS exists: overall score driven by top-N CVSS distribution.
    - If no CVSS exists: fallback severity-volume model.
    """
    if not findings:
        return {
            "score": 0,
            "grade": "A",
            "counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
            "unique_findings": 0,
            "top_risks": [],
            "cvss_summary": {"count": 0, "avg": None, "max": None},
        }

    # Normalize + dedup
    unique: dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for f in findings:
        f = dict(f)
        f["severity"] = _norm_sev(f.get("severity"))
        unique[_dedup_key(f)] = f

    uniq = list(unique.values())

    # Compute CVSS if present
    cvss_scores: list[float] = []
    for f in uniq:
        cv = _get_cvss_from_finding(f)
        if cv is not None:
            f["cvss_score"] = float(cv)
            cvss_scores.append(float(cv))

            # Optional alignment: if module left severity as Info/Low etc., keep it.
            # BUT if it set something nonsense/empty, derive from CVSS.
            if f.get("severity") in (None, "", "Info"):
                f["severity"] = _severity_from_cvss(float(cv))

    # Severity counts for UI
    counts = Counter(f["severity"] for f in uniq)
    for k in ("Critical", "High", "Medium", "Low", "Info"):
        counts.setdefault(k, 0)

    has_cvss = len(cvss_scores) > 0
    max_cvss = max(cvss_scores) if cvss_scores else None
    avg_cvss = (sum(cvss_scores) / len(cvss_scores)) if cvss_scores else None

    # Fallback volume model (kept)
    total_weight = sum(SEVERITY_WEIGHT.get(f["severity"], 0.5) for f in uniq)
    fallback_score = int(round(MAX_POINTS * (1 - math.exp(-0.08 * total_weight))))

    if not has_cvss:
        score = fallback_score
    else:
        # CVSS-based: use average of top-N to reflect multiple big issues
        # N=5 is stable and “minimal change” for small scanners
        top_n = sorted(cvss_scores, reverse=True)[:5]
        top_avg = sum(top_n) / len(top_n)

        # Map 0-10 => 0-100
        cvss_component = int(round((top_avg / 10.0) * 100))

        # Small volume factor (prevents many medium issues being underrated)
        # but CVSS remains primary driver.
        score = int(round(0.85 * cvss_component + 0.15 * fallback_score))

    score = int(min(100, max(0, score)))

    # Critical forcing (kept)
    has_critical = counts["Critical"] > 0 or (max_cvss is not None and max_cvss >= 9.0)
    grade = _grade_from_score(score)
    if has_critical:
        grade = "F"
        score = max(score, 85)

    # Top risks: prefer CVSS_score else severity weight
    def risk_key(f: Dict[str, Any]) -> float:
        if "cvss_score" in f and isinstance(f["cvss_score"], (int, float)):
            return float(f["cvss_score"]) + 10.0
        return float(SEVERITY_WEIGHT.get(f["severity"], 0.5))

    top = sorted(uniq, key=risk_key, reverse=True)[:5]
    compact_top = []
    for f in top:
        md = f.get("metadata") or {}
        compact_top.append({
            "title": f.get("title"),
            "severity": f.get("severity"),
            "cvss": f.get("cvss_score", None),
            "endpoint": md.get("endpoint") or md.get("url") or None,
        })

    return {
        "score": score,
        "grade": grade,
        "counts": dict(counts),
        "unique_findings": len(uniq),
        "top_risks": compact_top,
        "cvss_summary": {
            "count": len(cvss_scores),
            "avg": round(avg_cvss, 1) if avg_cvss is not None else None,
            "max": round(max_cvss, 1) if max_cvss is not None else None,
        },
    }
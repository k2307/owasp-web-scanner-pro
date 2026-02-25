from typing import Any, Dict, List


def evaluate_policy(
    score_data: Dict[str, Any],
    findings: List[Dict[str, Any]],
    diff: Dict[str, Any] | None,
    attack_paths: List[Dict[str, Any]] | None,
) -> Dict[str, Any]:
    """
    Returns:
      {
        "decision": "pass" | "warn" | "fail",
        "reasons": [...],
      }
    """
    reasons = []
    decision = "pass"

    # Basic severity gates
    sev_counts = {"Critical": 0, "High": 0}
    for f in findings:
        s = (f.get("severity") or "Info").title()
        if s in sev_counts:
            sev_counts[s] += 1

    if sev_counts["Critical"] > 0:
        decision = "fail"
        reasons.append("Critical findings present")

    # CVSS / score gate (your scoring.py returns overall score/grade)
    grade = (score_data or {}).get("grade")
    if grade == "F" and decision != "fail":
        decision = "fail"
        reasons.append("Overall grade is F")

    # Regression gates
    if diff:
        new_high = (diff.get("new_counts") or {}).get("High", 0)
        new_crit = (diff.get("new_counts") or {}).get("Critical", 0)
        if new_crit > 0:
            decision = "fail"
            reasons.append("New Critical finding introduced since last scan")
        elif new_high > 0 and decision == "pass":
            decision = "warn"
            reasons.append("New High finding introduced since last scan")

        if isinstance(diff.get("score_delta"), (int, float)) and diff["score_delta"] >= 10 and decision == "pass":
            decision = "warn"
            reasons.append(f"Risk score increased by {diff['score_delta']}")

    # Attack-path gates
    if attack_paths:
        for p in attack_paths:
            if (p.get("risk") or "").lower() == "critical":
                decision = "fail"
                reasons.append(f"Critical attack chain detected: {p.get('name')}")
                break
        if decision == "pass" and any((p.get("risk") or "").lower() == "high" for p in attack_paths):
            decision = "warn"
            reasons.append("High-risk attack chain detected")

    if not reasons:
        reasons.append("No policy violations")

    return {"decision": decision, "reasons": reasons}
import json
import html
from io import BytesIO
from typing import List, Dict, Any

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

MAX_FINDINGS = 500

def _safe_text(v: Any) -> str:
    return html.escape("" if v is None else str(v))

def _norm(f: Dict[str, Any]) -> Dict[str, str]:
    return {
        "title": _safe_text(f.get("title", "Untitled Issue")),
        "severity": _safe_text(f.get("severity", "Unknown")),
        "description": _safe_text(f.get("description", "")),
        "remediation": _safe_text(f.get("remediation", "")),
    }

def generate_json(target: str, findings: List[Dict], score: Dict) -> str:
    safe = [_norm(x) for x in findings[:MAX_FINDINGS]]
    return json.dumps({
        "target": _safe_text(target),
        "score": score,
        "total_findings": len(findings),
        "findings_returned": len(safe),
        "findings": safe,
    }, indent=4)

def generate_html(target: str, findings: List[Dict], score: Dict) -> str:
    safe_target = _safe_text(target)
    safe_score = _safe_text(score.get("score", "N/A"))
    safe_grade = _safe_text(score.get("grade", "N/A"))

    limited = findings[:MAX_FINDINGS]

    out = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>OWASP Scan Report</title>
<style>
body{{font-family:Arial,sans-serif;padding:20px}}
.issue{{border:1px solid #ddd;padding:12px;margin:12px 0;border-radius:10px}}
.sev{{font-weight:bold}}
small{{color:#666}}
</style></head><body>
<h1>Scan Report for {safe_target}</h1>
<p><b>Score:</b> {safe_score} ({safe_grade})</p>
<small>Total findings: {len(findings)} | Showing: {len(limited)}</small>
<hr>
"""
    for f in limited:
        n = _norm(f)
        out += f"""
<div class="issue">
  <h3>{n["title"]}</h3>
  <p class="sev">Severity: {n["severity"]}</p>
  <p>{n["description"]}</p>
  <p><b>Remediation:</b> {n["remediation"]}</p>
</div>
"""
    out += "</body></html>"
    return out

def generate_pdf(findings: List[Dict]) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("OWASP Web Security Scan Report", styles["Title"]))
    elements.append(Spacer(1, 0.4 * inch))

    limited = findings[:MAX_FINDINGS]
    for f in limited:
        n = _norm(f)
        elements.append(Paragraph(f"<b>{n['title']}</b>", styles["Heading2"]))
        elements.append(Paragraph(f"Severity: {n['severity']}", styles["Normal"]))
        elements.append(Paragraph(n["description"], styles["Normal"]))
        elements.append(Paragraph(f"Remediation: {n['remediation']}", styles["Normal"]))
        elements.append(Spacer(1, 0.25 * inch))

    doc.build(elements)
    buffer.seek(0)
    return buffer.read()
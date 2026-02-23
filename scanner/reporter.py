from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

def generate_pdf(issues, filename):
    doc = SimpleDocTemplate(filename)
    elements = []
    styles = getSampleStyleSheet()

    elements.append(Paragraph("OWASP Web Security Scan Report", styles["Title"]))
    elements.append(Spacer(1, 0.5 * inch))

    for issue in issues:
        elements.append(Paragraph(f"<b>{issue['title']}</b>", styles["Heading2"]))
        elements.append(Paragraph(f"Severity: {issue['severity']}", styles["Normal"]))
        elements.append(Paragraph(issue["description"], styles["Normal"]))
        elements.append(Paragraph(f"Remediation: {issue['remediation']}", styles["Normal"]))
        elements.append(Spacer(1, 0.3 * inch))

    doc.build(elements)

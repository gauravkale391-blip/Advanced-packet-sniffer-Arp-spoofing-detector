from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
import time
import io


def generate_incident_report(suspicious_entries, mitre_info):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleStyle", parent=styles["Title"], textColor=colors.HexColor("#0F6E56")
    )
    heading_style = ParagraphStyle(
        "HeadingStyle", parent=styles["Heading2"], textColor=colors.HexColor("#1A1A2E"), spaceBefore=14
    )
    normal_style = styles["Normal"]

    elements = []

    elements.append(Paragraph("Security Incident Report", title_style))
    elements.append(Paragraph(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    elements.append(Spacer(1, 0.3 * inch))

    elements.append(Paragraph("Incident Summary", heading_style))
    elements.append(Paragraph(
        f"This report documents {len(suspicious_entries)} suspected ARP spoofing incident(s) "
        f"detected by the Advanced Packet Sniffer & ARP Spoofing Detector.",
        normal_style
    ))
    elements.append(Spacer(1, 0.2 * inch))

    if suspicious_entries:
        elements.append(Paragraph("Affected Hosts", heading_style))
        table_data = [["IP Address", "MAC Addresses", "MAC Count"]]
        for entry in suspicious_entries:
            table_data.append([entry["IP Address"], entry["MAC Address(es)"], str(entry["MAC Count"])])

        table = Table(table_data, colWidths=[1.5 * inch, 3.2 * inch, 1 * inch])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F6E56")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F7FA")]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 0.3 * inch))

    elements.append(Paragraph("MITRE ATT&CK Classification", heading_style))
    elements.append(Paragraph(f"<b>Technique:</b> {mitre_info['technique']} — {mitre_info['name']}", normal_style))
    elements.append(Paragraph(f"<b>Tactic:</b> {mitre_info['tactic']}", normal_style))
    elements.append(Spacer(1, 0.1 * inch))
    elements.append(Paragraph(f"<b>Description:</b> {mitre_info['description']}", normal_style))
    elements.append(Spacer(1, 0.1 * inch))
    elements.append(Paragraph(f"<b>Recommended Mitigation:</b> {mitre_info['mitigation']}", normal_style))

    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph(
        "This report was generated automatically. All recommended actions should be reviewed "
        "and confirmed by a qualified SOC analyst before implementation.",
        ParagraphStyle("Footer", parent=normal_style, textColor=colors.grey, fontSize=8)
    ))

    doc.build(elements)
    buffer.seek(0)
    return buffer

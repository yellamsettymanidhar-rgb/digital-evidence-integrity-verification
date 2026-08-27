"""
Generates a one-page PDF verification report for a given verification_log
entry, using ReportLab. This is the artifact an investigator would print or
attach to a case file.
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER

NAVY = colors.HexColor("#0F1720")
TEAL = colors.HexColor("#2E9E76")
RED = colors.HexColor("#C9463B")
SLATE = colors.HexColor("#4B5A68")
LIGHT = colors.HexColor("#F2F5F7")


def build_verification_report(output_path: str, *, log_row, generated_by: str):
    """
    log_row: a models.get_verification_log() row (has evidence + verification
    fields joined together).
    """
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"], textColor=NAVY, fontSize=16, spaceAfter=2,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle", parent=styles["Normal"], textColor=SLATE, fontSize=9, alignment=TA_CENTER,
    )
    section_style = ParagraphStyle(
        "Section", parent=styles["Heading2"], textColor=NAVY, fontSize=11, spaceBefore=14, spaceAfter=6,
    )
    mono_style = ParagraphStyle(
        "Mono", parent=styles["Normal"], fontName="Courier", fontSize=8.5, textColor=NAVY,
    )
    disclaimer_style = ParagraphStyle(
        "Disclaimer", parent=styles["Normal"], fontSize=7.5, textColor=SLATE, leading=11,
    )

    result_is_match = log_row["result"] == "MATCH"
    status_text = "INTEGRITY VERIFIED — UNCHANGED" if result_is_match else "INTEGRITY COMPROMISED — MODIFIED"
    status_color = TEAL if result_is_match else RED

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        topMargin=18 * mm, bottomMargin=16 * mm, leftMargin=18 * mm, rightMargin=18 * mm,
    )

    elements = []
    elements.append(Paragraph("Digital Evidence Integrity Verification System", title_style))
    elements.append(Paragraph("Evidence Verification Report", subtitle_style))
    elements.append(Spacer(1, 8))
    elements.append(HRFlowable(width="100%", thickness=1, color=NAVY))
    elements.append(Spacer(1, 10))

    # Status banner
    status_table = Table([[status_text]], colWidths=[174 * mm])
    status_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), status_color),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 0), (-1, -1), 13),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    elements.append(status_table)
    elements.append(Spacer(1, 14))

    # Evidence details
    elements.append(Paragraph("Evidence Details", section_style))
    details = [
        ["Evidence ID", log_row["evidence_uid"]],
        ["File Name", log_row["original_filename"]],
        ["File Type", log_row["file_type"]],
        ["File Size", f"{log_row['file_size_bytes']:,} bytes"],
        ["Case Reference", log_row["case_reference"] or "—"],
        ["Description", log_row["description"] or "—"],
    ]
    dt = Table(details, colWidths=[45 * mm, 129 * mm])
    dt.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), SLATE),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#DCE3E8")),
    ]))
    elements.append(dt)

    # Hash comparison
    elements.append(Paragraph("Hash Comparison (SHA-256)", section_style))
    hash_data = [
        ["Original Hash (at registration)", Paragraph(log_row["original_hash"], mono_style)],
        ["Current Hash (at verification)", Paragraph(log_row["current_hash"], mono_style)],
    ]
    ht = Table(hash_data, colWidths=[42 * mm, 132 * mm])
    ht.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (0, -1), 8.5),
        ("TEXTCOLOR", (0, 0), (0, -1), SLATE),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BACKGROUND", (1, 0), (1, -1), LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (0, -1), 0),
        ("RIGHTPADDING", (0, 0), (0, -1), 8),
        ("LEFTPADDING", (1, 0), (1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("BOX", (1, 0), (1, -1), 0.5, colors.HexColor("#DCE3E8")),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#DCE3E8")),
    ]))
    elements.append(ht)

    # Verification metadata
    elements.append(Paragraph("Verification Metadata", section_style))
    meta = [
        ["Hash Algorithm", "SHA-256"],
        ["Verification Result", log_row["result"]],
        ["Verified By", log_row["verified_by_name"]],
        ["Verified At (UTC)", log_row["verified_at"]],
        ["Report Generated By", generated_by],
    ]
    mt = Table(meta, colWidths=[45 * mm, 129 * mm])
    mt.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), SLATE),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#DCE3E8")),
    ]))
    elements.append(mt)

    elements.append(Spacer(1, 16))
    elements.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#DCE3E8")))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(
        "<b>Forensic note:</b> A SHA-256 match confirms this file is byte-for-byte identical to the "
        "file registered as evidence under the ID above — it demonstrates <b>integrity</b> (the file has "
        "not been altered since registration). It does not, by itself, establish the file's original "
        "provenance, authorship, or chain of physical custody prior to registration. This report is "
        "generated by a college mini-project system and is not a substitute for a legally-recognised "
        "forensic chain-of-custody process.",
        disclaimer_style,
    ))

    doc.build(elements)

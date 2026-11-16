"""
Audit PDF Dossier Generator
Generates printable, audit-grade defensive compliance reports using ReportLab.
"""
import io
from typing import Dict, Any, List
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def generate_pdf_report(latest_run: Dict[str, Any], proposals_count: int = 0) -> bytes:
    """
    Generates a stylized PDF document containing audit metadata,
    detection scores, and defensive verification badges.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    
    styles = getSampleStyleSheet()
    
    # Custom Typography Styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=18
    )
    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=14,
        spaceAfter=8
    )
    cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#1e293b")
    )
    cell_bold_style = ParagraphStyle(
        "TableCellBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#0f172a")
    )

    elements = []

    # Header
    elements.append(Paragraph("RuleHardener — Defensive Audit Dossier", title_style))
    elements.append(Paragraph("Deterministic Sigma Rule Evaluation & Verification Report | 100% Offline / Local Execution", subtitle_style))
    elements.append(Spacer(1, 8))

    # Metadata Table
    meta_data = [
        [Paragraph("Evaluation Run ID:", cell_bold_style), Paragraph(str(latest_run.get("run_id", "N/A")), cell_style),
         Paragraph("Generated At:", cell_bold_style), Paragraph(str(latest_run.get("created_at", "N/A")), cell_style)],
        [Paragraph("Target Rule:", cell_bold_style), Paragraph(str(latest_run.get("rule_title", "N/A")), cell_style),
         Paragraph("Rule Version:", cell_bold_style), Paragraph(f"v{latest_run.get('rule_version', 1)}", cell_style)],
        [Paragraph("Rule UUID:", cell_bold_style), Paragraph(str(latest_run.get("rule_id", "N/A"))[:18] + "...", cell_style),
         Paragraph("Proposals Recorded:", cell_bold_style), Paragraph(str(proposals_count), cell_style)],
    ]
    meta_table = Table(meta_data, colWidths=[110, 160, 110, 160])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 14))

    # Metrics Section
    elements.append(Paragraph("Detection Performance Scorecard", section_style))
    
    det_rate = latest_run.get("detection_rate", 0.0)
    fp_rate = latest_run.get("false_positive_rate", 0.0)
    fps = latest_run.get("false_positives", 0)

    fp_status = "0 New False Positives (Clean)" if fps == 0 else f"{fps} False Positive(s) Flagged"
    cov_status = "High Coverage" if det_rate >= 80 else ("Moderate" if det_rate >= 50 else "Gaps Identified")

    metrics_data = [
        [Paragraph("Metric", cell_bold_style), Paragraph("Evaluated Value", cell_bold_style), Paragraph("Defensive Status", cell_bold_style)],
        [Paragraph("Detection Rate (Attack Coverage)", cell_style), Paragraph(f"{det_rate}%", cell_bold_style), Paragraph(cov_status, cell_style)],
        [Paragraph("False Positive Rate", cell_style), Paragraph(f"{fp_rate}%", cell_bold_style), Paragraph(fp_status, cell_style)],
        [Paragraph("Precision", cell_style), Paragraph(str(latest_run.get("precision", 0.0)), cell_style), Paragraph("TP / (TP + FP)", cell_style)],
        [Paragraph("Recall", cell_style), Paragraph(str(latest_run.get("recall", 0.0)), cell_style), Paragraph("TP / (TP + FN)", cell_style)],
        [Paragraph("F1 Score", cell_style), Paragraph(str(latest_run.get("f1_score", 0.0)), cell_style), Paragraph("Harmonic Mean", cell_style)],
    ]
    metrics_table = Table(metrics_data, colWidths=[200, 140, 200])
    metrics_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(metrics_table)
    elements.append(Spacer(1, 14))

    # Scenario Breakdown Section
    elements.append(Paragraph("Scenario & Telemetry Breakdown", section_style))
    breakdown_data = [
        [Paragraph("Category", cell_bold_style), Paragraph("Total Tested", cell_bold_style), Paragraph("Detected Count", cell_bold_style), Paragraph("Missed Count", cell_bold_style)],
        [Paragraph("Attack Scenarios", cell_style),
         Paragraph(str(latest_run.get("total_scenarios", 0)), cell_style),
         Paragraph(str(latest_run.get("detected_scenarios", 0)), cell_style),
         Paragraph(str(latest_run.get("missed_scenarios", 0)), cell_style)],
        [Paragraph("Benign Telemetry Events", cell_style),
         Paragraph(str(latest_run.get("total_scenarios", 0) + fps), cell_style),
         Paragraph(f"{fps} (FP)", cell_style),
         Paragraph("N/A", cell_style)],
    ]
    breakdown_table = Table(breakdown_data, colWidths=[160, 120, 130, 130])
    breakdown_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(breakdown_table)
    elements.append(Spacer(1, 18))

    # Footer note
    footer_text = "This report was generated offline by the RuleHardener deterministic detection engine. All evaluation artifacts, unified diffs, and version lineages are stored in SQLite."
    elements.append(Paragraph(footer_text, subtitle_style))

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()

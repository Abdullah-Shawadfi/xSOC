#!/usr/bin/env python3
"""
PDF Report Generation for Security Visibility Assessment

Generates professional PDF reports from assessment results.
"""

import io
from datetime import datetime
from typing import List, Dict, Any


def generate_pdf_report(results: List[Dict[str, Any]], coverage: float) -> bytes:
    """
    Generate PDF report from assessment results.
    
    Args:
        results: List of assessment results
        coverage: Overall coverage percentage
    
    Returns:
        PDF bytes
    """
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

    except ImportError:
        # Fallback: return simple text as PDF
        text = generate_text_report(results, coverage)
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph
        from reportlab.lib.styles import getSampleStyleSheet

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        style = getSampleStyleSheet()
        paragraphs = [Paragraph(line) for line in text.split('\n')]
        doc.build(paragraphs)
        return buffer.getvalue()

    # Create PDF
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    story = []
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#0D1B2A'),
        spaceAfter=30,
        alignment=TA_CENTER,
    )

    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#415A77'),
        spaceAfter=10,
        spaceBefore=10,
    )

    # Title
    story.append(Paragraph("Security Visibility Assessment Report", title_style))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 0.3 * inch))

    # Coverage summary
    coverage_data = [
        ['Metric', 'Value'],
        ['Overall Coverage', f"{coverage:.0f}%"],
        ['Covered', str(sum(1 for r in results if r["status"] == "COVERED"))],
        ['Partial Visibility', str(sum(1 for r in results if r["status"] == "PARTIAL VISIBILITY"))],
        ['Blind Spots', str(sum(1 for r in results if r["status"] == "BLIND SPOT"))],
    ]

    coverage_table = Table(coverage_data)
    coverage_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#415A77')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))

    story.append(coverage_table)
    story.append(Spacer(1, 0.3 * inch))

    # Blind spots
    blind_spots = [r for r in results if r["status"] == "BLIND SPOT"]
    if blind_spots:
        story.append(Paragraph("❌ BLIND SPOTS — Immediate Action Required", heading_style))

        for r in blind_spots:
            story.append(Paragraph(f"<b>{r['technique_id']} — {r['name']}</b>", styles['Normal']))
            story.append(Paragraph(f"<b>Tactic:</b> {r['tactic']}", styles['Normal']))
            story.append(Paragraph(f"<b>Why:</b> {r['why']}", styles['Normal']))
            story.append(Paragraph(f"<b>Impact:</b> {r['impact']}", styles['Normal']))

            if r["remediation"]:
                story.append(Paragraph("<b>Remediation:</b>", styles['Normal']))
                for i, step in enumerate(r["remediation"], 1):
                    story.append(Paragraph(f"{i}. {step}", styles['Normal']))

            story.append(Spacer(1, 0.2 * inch))

    # Partial visibility
    partial = [r for r in results if r["status"] == "PARTIAL VISIBILITY"]
    if partial:
        story.append(PageBreak())
        story.append(Paragraph("⚠️ PARTIAL VISIBILITY — Add Alert Rules", heading_style))

        for r in partial:
            story.append(Paragraph(f"<b>{r['technique_id']} — {r['name']}</b>", styles['Normal']))
            story.append(Paragraph(f"<b>Tactic:</b> {r['tactic']}", styles['Normal']))

            if r["quality_gaps"]:
                story.append(Paragraph("<b>Quality Gaps:</b>", styles['Normal']))
                for gap in r["quality_gaps"]:
                    story.append(Paragraph(f"• {gap}", styles['Normal']))

            if r["satisfied_requirements"]:
                story.append(Paragraph("<b>Currently Detected By:</b>", styles['Normal']))
                for req in r["satisfied_requirements"]:
                    story.append(Paragraph(f"• {req}", styles['Normal']))

            if r["remediation"]:
                story.append(Paragraph("<b>To Achieve Full Coverage:</b>", styles['Normal']))
                for i, step in enumerate(r["remediation"], 1):
                    story.append(Paragraph(f"{i}. {step}", styles['Normal']))

            story.append(Spacer(1, 0.2 * inch))

    # Covered techniques
    covered = [r for r in results if r["status"] == "COVERED"]
    if covered:
        story.append(PageBreak())
        story.append(Paragraph("✅ COVERED TECHNIQUES — Good Job", heading_style))

        covered_data = [['Technique ID', 'Name', 'Tactic']]
        for r in covered:
            covered_data.append([r['technique_id'], r['name'], r['tactic']])

        covered_table = Table(covered_data)
        covered_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2EC4B6')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgreen),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))

        story.append(covered_table)

    # Build PDF
    doc.build(story)
    return buffer.getvalue()


def generate_text_report(results: List[Dict[str, Any]], coverage: float) -> str:
    """
    Generate text-based report (fallback).
    
    Args:
        results: List of assessment results
        coverage: Overall coverage percentage
    
    Returns:
        Text report string
    """
    lines = [
        "=" * 80,
        "SECURITY VISIBILITY ASSESSMENT REPORT",
        "=" * 80,
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"OVERALL COVERAGE: {coverage:.0f}%",
        f"Covered: {sum(1 for r in results if r['status'] == 'COVERED')}",
        f"Partial: {sum(1 for r in results if r['status'] == 'PARTIAL VISIBILITY')}",
        f"Blind: {sum(1 for r in results if r['status'] == 'BLIND SPOT')}",
        "",
        "=" * 80,
        "BLIND SPOTS — IMMEDIATE ACTION REQUIRED",
        "=" * 80,
    ]

    for r in results:
        if r["status"] == "BLIND SPOT":
            lines.extend([
                "",
                f"[❌] {r['technique_id']} — {r['name']}",
                f"Tactic: {r['tactic']}",
                f"Why: {r['why']}",
                f"Impact: {r['impact']}",
                "Remediation:",
            ])
            for i, step in enumerate(r["remediation"], 1):
                lines.append(f"  {i}. {step}")

    lines.extend([
        "",
        "=" * 80,
        "PARTIAL VISIBILITY — ADD ALERT RULES",
        "=" * 80,
    ])

    for r in results:
        if r["status"] == "PARTIAL VISIBILITY":
            lines.extend([
                "",
                f"[⚠️] {r['technique_id']} — {r['name']}",
                f"Quality gaps: {', '.join(r['quality_gaps'])}",
                "Fix:",
            ])
            for i, step in enumerate(r["remediation"], 1):
                lines.append(f"  {i}. {step}")

    lines.extend([
        "",
        "=" * 80,
    ])

    return "\n".join(lines)

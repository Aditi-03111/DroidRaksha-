"""
Report route: returns shareable public report by SHA256 or analysis ID as PDF.
"""
from __future__ import annotations
from fastapi import APIRouter, HTTPException, Response
from backend.db import database
import json
from loguru import logger

router = APIRouter()

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, ListFlowable, ListItem
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from io import BytesIO
    REPORTLAB_AVAILABLE = True
except Exception as e:
    REPORTLAB_AVAILABLE = False
    logger.warning(f"ReportLab could not be loaded: {e}. Falling back to JSON reports.")


@router.get("/report/{identifier}")
async def get_report(identifier: str):
    """
    Get a public report by analysis ID or SHA256 hash as a PDF.
    """
    # Try by analysis ID first
    result = await database.get_analysis(identifier)
    if not result:
        # Try by SHA256
        result = await database.get_analysis_by_hash(identifier)

    if not result:
        raise HTTPException(status_code=404, detail="Report not found")

    # If ReportLab is not available, return the JSON result
    if not REPORTLAB_AVAILABLE:
        return result

    # The result might be a database model, convert to dict if needed


    if not result:
        raise HTTPException(status_code=404, detail="Report not found")

    # The result might be a database model, convert to dict if needed
    # Assuming result has a __dict__ or is a dict
    if hasattr(result, "__dict__"):
        data = result.__dict__
    else:
        data = dict(result)

    # Parse JSON strings if they are stored as strings in DB
    for key in ["permissions", "yara_matches", "cert_details", "strings", "recommendations"]:
        if key in data and isinstance(data[key], str):
            try:
                data[key] = json.loads(data[key])
            except:
                pass

    pkg = data.get("manifest", {}).get("package_name", "Unknown Package")
    score = data.get("risk", {}).get("score", 0)
    narrative = data.get("ai_narrative", "No narrative available.")
    recommendations = data.get("ai_recommendations", [])
    yara_matches = data.get("yara", {}).get("matches", [])
    permissions = data.get("manifest", {}).get("permissions", [])
    import asyncio
    
    def _generate_pdf():
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1e1b4b'),
            alignment=1,
            spaceAfter=10
        )
        subtitle_style = ParagraphStyle(
            'SubtitleStyle',
            parent=styles['Normal'],
            fontSize=14,
            textColor=colors.HexColor('#6366f1'),
            alignment=1,
            spaceAfter=20
        )
        section_title_style = ParagraphStyle(
            'SectionTitleStyle',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#1e1b4b'),
            spaceBefore=15,
            spaceAfter=10
        )
        normal_style = styles['Normal']
        
        elements = []
        
        # Header
        elements.append(Paragraph("DroidRaksha Threat Analysis", title_style))
        elements.append(Paragraph("Malware Detection & AI Narrative Platform", subtitle_style))
        elements.append(Spacer(1, 20))
        
        # Score Card
        score_color = '#ef4444' if score >= 70 else '#f59e0b' if score >= 40 else '#10b981'
        score_text = f"<font size=24 color='{score_color}'><b>{score}/100</b></font>"
        
        score_data = [
            [Paragraph("<b>Risk Score</b>", normal_style), Paragraph(f"<b>Target Package:</b> {pkg}", normal_style)],
            [Paragraph(score_text, normal_style), ""]
        ]
        
        score_table = Table(score_data, colWidths=[150, 300])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ALIGN', (0, 0), (0, 1), 'CENTER'),
            ('SPAN', (1, 0), (1, 1)),
        ]))
        elements.append(score_table)
        elements.append(Spacer(1, 20))
        
        # AI Threat Narrative
        narrative_str = str(narrative).replace('\\n', '<br/>')
        elements.append(Paragraph("AI Threat Narrative", section_title_style))
        elements.append(Paragraph(narrative_str, normal_style))
        elements.append(Spacer(1, 15))
        
        # Security Recommendations
        elements.append(Paragraph("Security Recommendations", section_title_style))
        if recommendations:
            bullet_items = [ListItem(Paragraph(str(r), normal_style)) for r in recommendations]
            elements.append(ListFlowable(bullet_items, bulletType='bullet', spaceAfter=10))
        else:
            elements.append(Paragraph("No specific recommendations available.", normal_style))
        elements.append(Spacer(1, 15))
        
        # YARA Rules
        elements.append(Paragraph("YARA Rules Matched", section_title_style))
        if yara_matches:
            yara_data = [["Rule", "Description"]]
            for m in yara_matches:
                yara_data.append([str(m.get('rule', '')), str(m.get('description', 'N/A'))])
            
            yara_table = Table(yara_data, colWidths=[150, 300])
            yara_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#475569')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(yara_table)
        else:
            elements.append(Paragraph("No YARA rules matched.", normal_style))
        elements.append(Spacer(1, 15))
        
        # Permissions
        elements.append(Paragraph("Dangerous Permissions", section_title_style))
        if permissions:
            perm_items = []
            for p in permissions:
                if p.get("is_dangerous"):
                    perm_items.append(ListItem(Paragraph(f"<b>{p.get('name')}</b>: {p.get('description', 'N/A')}", normal_style)))
            
            if perm_items:
                elements.append(ListFlowable(perm_items, bulletType='bullet', spaceAfter=10))
            else:
                elements.append(Paragraph("No dangerous permissions listed.", normal_style))
        else:
            elements.append(Paragraph("No permissions listed.", normal_style))
            
        doc.build(elements)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

    # Generate PDF
    pdf_bytes = await asyncio.to_thread(_generate_pdf)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=DroidRaksha_Report_{pkg}.pdf"
        }
    )


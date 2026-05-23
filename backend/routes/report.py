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
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except Exception as e:
    WEASYPRINT_AVAILABLE = False
    logger.warning(f"WeasyPrint could not be loaded: {e}. Falling back to JSON reports.")


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

    # If WeasyPrint is not available, return the JSON result
    if not WEASYPRINT_AVAILABLE:
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
    
    # Simple HTML template for the PDF
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>DroidRaksha Analysis Report - {pkg}</title>
        <style>
            body {{ font-family: Helvetica, Arial, sans-serif; color: #333; line-height: 1.6; padding: 40px; }}
            .header {{ text-align: center; border-bottom: 2px solid #6366f1; padding-bottom: 20px; margin-bottom: 30px; }}
            .title {{ color: #1e1b4b; font-size: 28px; margin-bottom: 5px; }}
            .subtitle {{ color: #6366f1; font-size: 16px; margin: 0; }}
            .score-card {{ background-color: #f8fafc; border: 1px solid #e2e8f0; padding: 20px; border-radius: 8px; margin-bottom: 30px; text-align: center; }}
            .score-value {{ font-size: 48px; font-weight: bold; color: {'#ef4444' if score >= 70 else '#f59e0b' if score >= 40 else '#10b981'}; }}
            .section {{ margin-bottom: 30px; }}
            .section-title {{ font-size: 20px; color: #1e1b4b; border-left: 4px solid #6366f1; padding-left: 10px; margin-bottom: 15px; }}
            .recommendations {{ background-color: #f0fdf4; border: 1px solid #bbf7d0; padding: 15px; border-radius: 8px; }}
            .recommendations li {{ color: #15803d; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ padding: 10px; border: 1px solid #e2e8f0; text-align: left; }}
            th {{ background-color: #f1f5f9; color: #475569; }}
            .footer {{ text-align: center; color: #94a3b8; font-size: 12px; margin-top: 50px; border-top: 1px solid #e2e8f0; padding-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1 class="title">DroidRaksha Threat Analysis</h1>
            <p class="subtitle">Malware Detection & AI Narrative Platform</p>
        </div>

        <div class="score-card">
            <div>Risk Score</div>
            <div class="score-value">{score}/100</div>
            <div>Target Package: <strong>{pkg}</strong></div>
        </div>

        <div class="section">
            <div class="section-title">AI Threat Narrative</div>
            <p>{narrative}</p>
        </div>

        <div class="section">
            <div class="section-title">Security Recommendations</div>
            <div class="recommendations">
                <ul>
                    {"".join([f"<li>{r}</li>" for r in recommendations]) or "<li>No specific recommendations available.</li>"}
                </ul>
            </div>
        </div>

        <div class="section">
            <div class="section-title">YARA Rules Matched</div>
            {f"<table><tr><th>Rule</th><th>Description</th></tr>" + "".join([f"<tr><td>{m.get('rule')}</td><td>{m.get('description', 'N/A')}</td></tr>" for m in yara_matches]) + "</table>" if yara_matches else "<p>No YARA rules matched.</p>"}
        </div>

        <div class="section">
            <div class="section-title">Dangerous Permissions</div>
            {f"<ul>" + "".join([f"<li><strong>{p.get('name')}</strong>: {p.get('description', 'N/A')}</li>" for p in permissions if p.get("is_dangerous")]) + "</ul>" if permissions else "<p>No permissions listed.</p>"}
        </div>

        <div class="footer">
            Generated by DroidRaksha • Security Intelligence Platform
        </div>
    </body>
    </html>
    """

    import asyncio
    # Generate PDF
    pdf_bytes = await asyncio.to_thread(HTML(string=html_content).write_pdf)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=DroidRaksha_Report_{pkg}.pdf"
        }
    )


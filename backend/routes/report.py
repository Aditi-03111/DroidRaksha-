"""
Report route: Generates a deep forensic PDF report by analysis ID or SHA256.

Sections:
  Cover Page → Executive Summary → ML Intelligence → MITRE ATT&CK →
  YARA → Permissions → Certificate → Strings/IOCs → India IOC →
  Network/PCAP → Obfuscation

Uses ReportLab; falls back to JSON if unavailable.
"""
from __future__ import annotations
import asyncio
from io import BytesIO
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Response
from loguru import logger

from backend.db import database

router = APIRouter()

# ── Optional ReportLab import ─────────────────────────────────────────────────
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        ListFlowable, ListItem, HRFlowable, PageBreak,
    )
    RL_OK = True
except Exception as _e:
    RL_OK = False
    logger.warning(f"ReportLab not available ({_e}) — PDF reports disabled.")


# ── Route ─────────────────────────────────────────────────────────────────────

@router.get("/report/{identifier}")
async def get_report(identifier: str):
    """Get a forensic PDF report by analysis ID or SHA-256 hash."""
    result = await database.get_analysis(identifier)
    if not result:
        result = await database.get_analysis_by_hash(identifier)
    if not result:
        raise HTTPException(status_code=404, detail="Report not found")

    if not RL_OK:
        return result                         # fallback: return JSON

    data = result if isinstance(result, dict) else dict(result)
    pdf_bytes = await asyncio.to_thread(_build_pdf, data)

    pkg = data.get("manifest", {}).get("package_name", "unknown")
    safe_pkg = pkg.replace(".", "_").replace(" ", "_")
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="DroidRaksha_{safe_pkg}.pdf"'},
    )


# ── Colour palette ─────────────────────────────────────────────────────────────

_NAVY   = colors.HexColor("#0f172a")
_INDIGO = colors.HexColor("#6366f1")
_RED    = colors.HexColor("#ef4444")
_ORANGE = colors.HexColor("#f97316")
_YELLOW = colors.HexColor("#f59e0b")
_GREEN  = colors.HexColor("#22c55e")
_CYAN   = colors.HexColor("#22d3ee")
_SLATE  = colors.HexColor("#64748b")
_LIGHT  = colors.HexColor("#f1f5f9")
_BORDER = colors.HexColor("#e2e8f0")
_DARK   = colors.HexColor("#1e293b")

_LEVEL_HEX = {
    "CRITICAL": "#ef4444", "HIGH": "#f97316",
    "MEDIUM": "#f59e0b",   "LOW":  "#22c55e", "SAFE": "#22d3ee",
}


# ── Style sheet ───────────────────────────────────────────────────────────────

def _S():
    base = getSampleStyleSheet()

    def p(name, parent="Normal", **kw):
        return ParagraphStyle(name, parent=base[parent], **kw)

    return {
        "cover_h":   p("cover_h",   "Heading1", fontSize=30, textColor=_INDIGO, alignment=1, spaceAfter=6),
        "cover_sub": p("cover_sub", "Normal",   fontSize=13, textColor=_SLATE,  alignment=1, spaceAfter=4),
        "cover_fn":  p("cover_fn",  "Normal",   fontSize=8,  textColor=_SLATE,  alignment=1),
        "section":   p("section",   "Heading2", fontSize=13, textColor=_NAVY,   spaceBefore=16, spaceAfter=6),
        "sub":       p("sub",       "Heading3", fontSize=10, textColor=_INDIGO, spaceBefore=8,  spaceAfter=4),
        "body":      p("body",      "Normal",   fontSize=9,  textColor=_DARK,   leading=14, spaceAfter=3),
        "mono":      p("mono",      "Normal",   fontSize=8,  fontName="Courier", textColor=_DARK, leading=12),
        "footer":    p("footer",    "Normal",   fontSize=7,  textColor=_SLATE,  alignment=1),
        "verdict":   p("verdict",   "Normal",   fontSize=9,  textColor=_DARK,   leading=15,
                        backColor=colors.HexColor("#f0f4ff"), borderPad=5),
    }


# ── Helpers ────────────────────────────────────────────────────────────────────

def _hr():
    return HRFlowable(width="100%", thickness=0.8, color=_INDIGO, spaceAfter=5)


def _kv_table(E, rows: list[list], widths=(5 * cm, 11 * cm)):
    """Key-value two-column table (no header)."""
    t = Table(rows, colWidths=list(widths))
    t.setStyle(TableStyle([
        ("FONTSIZE",        (0, 0), (-1, -1), 9),
        ("FONTNAME",        (0, 0), (0, -1),  "Helvetica-Bold"),
        ("TEXTCOLOR",       (0, 0), (0, -1),  _SLATE),
        ("ROWBACKGROUNDS",  (0, 0), (-1, -1), [colors.white, _LIGHT]),
        ("GRID",            (0, 0), (-1, -1), 0.4, _BORDER),
        ("PADDING",         (0, 0), (-1, -1), 5),
        ("VALIGN",          (0, 0), (-1, -1), "TOP"),
    ]))
    E.append(t)
    E.append(Spacer(1, 0.2 * cm))


def _grid_table(E, rows: list[list], col_widths: list):
    """Multi-column table with styled header row."""
    S = _S()
    hdr = [Paragraph(f"<b>{c}</b>", ParagraphStyle("th", fontSize=8, textColor=colors.white))
           for c in rows[0]]
    body = [[Paragraph(str(c), S["body"]) for c in row] for row in rows[1:]]
    t = Table([hdr] + body, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (len(rows[0]) - 1, 0), _NAVY),
        ("ALIGN",          (0, 0), (-1, -1), "LEFT"),
        ("PADDING",        (0, 0), (-1, -1), 5),
        ("GRID",           (0, 0), (-1, -1), 0.4, _BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _LIGHT]),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE",       (0, 1), (-1, -1), 8),
    ]))
    E.append(t)
    E.append(Spacer(1, 0.2 * cm))


# ── Main PDF builder ──────────────────────────────────────────────────────────

def _build_pdf(data: dict) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        rightMargin=2 * cm, leftMargin=2 * cm,
        topMargin=2.5 * cm, bottomMargin=2.5 * cm,
    )
    S = _S()
    E: list = []

    now         = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    manifest    = data.get("manifest", {})
    hashes      = data.get("hashes", {})
    risk        = data.get("risk", {})
    cert        = data.get("certificate", {})
    yara        = data.get("yara", [])
    obf         = data.get("obfuscation", {})
    vt          = data.get("virustotal", {})
    ioc         = data.get("india_ioc", {})
    mitre       = data.get("mitre", [])
    strings     = data.get("strings", [])
    ml_cls      = data.get("ml_classification", {})
    xgb         = data.get("xgboost", {})
    malbert     = data.get("malbert", {})
    anomaly     = data.get("anomaly", {})
    agent       = data.get("agent_verdict", {})
    network     = data.get("network", {})

    pkg         = manifest.get("package_name", "Unknown Package")
    score       = risk.get("score", 0)
    risk_level  = risk.get("risk_level", "UNKNOWN")
    analysis_id = data.get("id", "N/A")
    filename    = data.get("filename", "Unknown APK")
    narrative   = data.get("ai_narrative", "")

    # ── Cover ─────────────────────────────────────────────────────────────────
    E.append(Spacer(1, 2 * cm))
    E.append(Paragraph("DroidRaksha", S["cover_h"]))
    E.append(Paragraph("Deep Forensic Analysis Report", S["cover_sub"]))
    E.append(Spacer(1, 0.3 * cm))
    E.append(HRFlowable(width="60%", thickness=2, color=_INDIGO, hAlign="CENTER"))
    E.append(Spacer(1, 0.6 * cm))

    lvl_hex = _LEVEL_HEX.get(risk_level, "#64748b")
    cover_rows = [
        ["Package",      pkg],
        ["File",         filename],
        ["Risk Level",   f"● {risk_level}"],
        ["Risk Score",   f"{score} / 100"],
        ["Analysis ID",  analysis_id],
        ["SHA-256",      (hashes.get("sha256", "N/A") or "N/A")[:48] + "…"],
        ["Generated",    now],
    ]
    ct = Table(cover_rows, colWidths=[3.5 * cm, 12 * cm])
    ct.setStyle(TableStyle([
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("FONTNAME",       (0, 0), (0, -1),  "Helvetica-Bold"),
        ("TEXTCOLOR",      (0, 0), (0, -1),  _SLATE),
        ("TEXTCOLOR",      (1, 2), (1, 3),   colors.HexColor(lvl_hex)),
        ("FONTNAME",       (1, 2), (1, 3),   "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, _LIGHT]),
        ("GRID",           (0, 0), (-1, -1), 0.4, _BORDER),
        ("PADDING",        (0, 0), (-1, -1), 6),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
    ]))
    E.append(ct)
    E.append(Spacer(1, 1 * cm))
    E.append(Paragraph(
        "This report is CONFIDENTIAL and intended solely for the authorised recipient. "
        "Generated by DroidRaksha Threat Intelligence Platform (PHAPGUYZ — Round 2).",
        S["cover_fn"],
    ))
    E.append(PageBreak())

    # ── 1. Executive Summary ──────────────────────────────────────────────────
    E.append(Paragraph("1. Executive Summary", S["section"]))
    E.append(_hr())
    breakdown = risk.get("breakdown", {})
    _kv_table(E, [
        ["Static Score",        str(breakdown.get("static_score", "—"))],
        ["Threat Intel Score",  str(breakdown.get("threat_intel_score", "—"))],
        ["YARA Score",          str(breakdown.get("yara_score", "—"))],
        ["Total Risk Score",    f"{score} / 100"],
        ["VirusTotal",          f"{vt.get('detection_count', 0)} / {vt.get('total_engines', 0)} engines"],
        ["Obfuscation Score",   f"{obf.get('score', 0)} / 100"],
        ["India IOC — UPI",     "⚠ YES" if ioc.get("is_fake_upi") else "No"],
        ["India IOC — Bank",    "⚠ YES" if ioc.get("is_fake_bank") else "No"],
        ["India IOC — Loans",   "⚠ YES" if ioc.get("is_loan_scam") else "No"],
    ])

    if narrative:
        E.append(Paragraph("AI Threat Narrative", S["sub"]))
        E.append(Paragraph(str(narrative)[:2500].replace("\n", "<br/>"), S["body"]))

    court = (agent or {}).get("court_narrative", "")
    if court:
        E.append(Paragraph("LangChain Agent Court Verdict", S["sub"]))
        E.append(Paragraph(str(court)[:2500].replace("\n", "<br/>"), S["verdict"]))

    recs = data.get("ai_recommendations", []) or (agent or {}).get("recommendations", [])
    if recs:
        E.append(Paragraph("Recommendations", S["sub"]))
        E.append(ListFlowable(
            [ListItem(Paragraph(str(r), S["body"])) for r in recs[:10]],
            bulletType="bullet", spaceAfter=3,
        ))
    E.append(PageBreak())

    # ── 2. ML Intelligence ────────────────────────────────────────────────────
    E.append(Paragraph("2. ML Intelligence Layer", S["section"]))
    E.append(_hr())

    if ml_cls:
        E.append(Paragraph("2.1  Rule-Based Family Classifier", S["sub"]))
        _kv_table(E, [
            ["Family",          ml_cls.get("family", "—")],
            ["Confidence",      f"{ml_cls.get('confidence', 0):.0%}"],
            ["India Targeted",  "⚠ YES" if ml_cls.get("is_india_targeted") else "No"],
            ["Evidence",        "; ".join((ml_cls.get("evidence") or [])[:5])],
        ])

    if xgb:
        E.append(Paragraph("2.2  XGBoost (CICMalDroid 2020)", S["sub"]))
        _kv_table(E, [
            ["Predicted Class",  xgb.get("predicted_class", "—")],
            ["Confidence",       f"{xgb.get('confidence', 0):.1%}"],
        ])
        shap_top = xgb.get("shap_top5", [])
        if shap_top:
            E.append(Paragraph("SHAP Feature Impact (Top 5)", S["sub"]))
            _grid_table(E,
                [["Feature", "Impact"]] + [[f.get("feature", ""), f"{f.get('value', 0):.4f}"] for f in shap_top],
                [9 * cm, 3 * cm],
            )

    if malbert:
        E.append(Paragraph("2.3  MalBERT Zero-Shot (HuggingFace BART)", S["sub"]))
        _kv_table(E, [
            ["Verdict",     malbert.get("verdict", "—")],
            ["Confidence",  f"{malbert.get('confidence', 0):.1%}"],
            ["Top Class",   malbert.get("top_class", "—")],
            ["Inference",   f"{malbert.get('inference_ms', 0)} ms"],
        ])

    if anomaly:
        E.append(Paragraph("2.4  Isolation Forest — Zero-Day Detection", S["sub"]))
        _kv_table(E, [
            ["Verdict",          anomaly.get("verdict", "—")],
            ["Anomaly Score",    f"{anomaly.get('anomaly_score_pct', 0):.1f}%"],
            ["Is Anomaly",       "⚠ YES" if anomaly.get("is_anomaly") else "No"],
        ])
    E.append(PageBreak())

    # ── 3. MITRE ATT&CK ───────────────────────────────────────────────────────
    E.append(Paragraph("3. MITRE ATT&CK Mapping", S["section"]))
    E.append(_hr())
    if mitre:
        _grid_table(E,
            [["ID", "Name", "Tactic", "Evidence"]] + [
                [m.get("technique_id", ""), m.get("name", ""),
                 m.get("tactic", ""), str(m.get("evidence", ""))[:80]]
                for m in mitre
            ],
            [2.5 * cm, 5 * cm, 3 * cm, 5.5 * cm],
        )
    else:
        E.append(Paragraph("No MITRE techniques mapped.", S["body"]))
    E.append(PageBreak())

    # ── 4. YARA ───────────────────────────────────────────────────────────────
    E.append(Paragraph("4. YARA Detections", S["section"]))
    E.append(_hr())
    if yara:
        _grid_table(E,
            [["Rule", "Severity", "Tags", "Description"]] + [
                [y.get("rule", ""), y.get("severity", ""),
                 ", ".join(y.get("tags", [])), str(y.get("description", ""))[:90]]
                for y in yara
            ],
            [4 * cm, 2 * cm, 3.5 * cm, 6.5 * cm],
        )
    else:
        E.append(Paragraph("No YARA rules matched.", S["body"]))

    # ── 5. Permissions ────────────────────────────────────────────────────────
    E.append(Paragraph("5. Permissions Analysis", S["section"]))
    E.append(_hr())
    perms     = manifest.get("permissions", [])
    dangerous = [p for p in perms if p.get("is_dangerous")]
    E.append(Paragraph(
        f"Total: <b>{len(perms)}</b> — "
        f"Dangerous: <b><font color='#ef4444'>{len(dangerous)}</font></b>",
        S["body"],
    ))
    if dangerous:
        E.append(Paragraph("Dangerous Permissions", S["sub"]))
        _grid_table(E,
            [["Permission", "Description"]] + [
                [p.get("name", ""), str(p.get("description", ""))[:100]]
                for p in dangerous
            ],
            [7 * cm, 9 * cm],
        )
    combos = manifest.get("dangerous_combos", [])
    if combos:
        E.append(Paragraph("Dangerous Combinations", S["sub"]))
        for c in combos:
            E.append(Paragraph(
                f"<b><font color='#f97316'>[{c.get('severity','?')}]</font></b> "
                f"{c.get('label','?')}: {', '.join(c.get('permissions', []))}",
                S["body"],
            ))

    E.append(PageBreak())

    # ── 6. Certificate ────────────────────────────────────────────────────────
    E.append(Paragraph("6. Certificate Analysis", S["section"]))
    E.append(_hr())
    if cert:
        _kv_table(E, [
            ["Subject",      cert.get("subject", "—")],
            ["Issuer",       cert.get("issuer", "—")],
            ["Self-Signed",  "⚠ YES" if cert.get("is_self_signed") else "No"],
            ["Expired",      "⚠ YES" if cert.get("is_expired") else "No"],
            ["Valid From",   cert.get("not_before", "—")],
            ["Valid Until",  cert.get("not_after", "—")],
            ["SHA-256",      (cert.get("sha256_fingerprint") or "")[:40] + "…"],
        ])
        for w in cert.get("warnings", []):
            E.append(Paragraph(f"⚠ {w}", S["body"]))

    # ── 7. Strings & IOCs ────────────────────────────────────────────────────
    E.append(Paragraph("7. Extracted Strings & IOCs", S["section"]))
    E.append(_hr())
    high_risk = [s for s in strings if s.get("risk") == "high"]
    E.append(Paragraph(
        f"Total extracted: <b>{len(strings)}</b> — "
        f"High-risk: <b><font color='#ef4444'>{len(high_risk)}</font></b>",
        S["body"],
    ))
    if high_risk:
        _grid_table(E,
            [["Type", "Value", "Risk"]] + [
                [s.get("type", ""), str(s.get("value", ""))[:80], s.get("risk", "")]
                for s in high_risk[:30]
            ],
            [2.5 * cm, 12 * cm, 1.5 * cm],
        )

    # ── 8. India Threat Intelligence ─────────────────────────────────────────
    E.append(Paragraph("8. India Threat Intelligence", S["section"]))
    E.append(_hr())
    _kv_table(E, [
        ["Fake UPI",        "⚠ YES" if ioc.get("is_fake_upi") else "No"],
        ["Fake Bank App",   "⚠ YES" if ioc.get("is_fake_bank") else "No"],
        ["Loan Scam",       "⚠ YES" if ioc.get("is_loan_scam") else "No"],
        ["Matched Domains", ", ".join(ioc.get("matched_domains", []))[:100] or "None"],
        ["Matched IPs",     ", ".join(ioc.get("matched_ips", []))[:100] or "None"],
    ])
    for f in ioc.get("risk_flags", []):
        E.append(Paragraph(f"⚑ {f}", S["body"]))

    # ── 9. Network / PCAP ─────────────────────────────────────────────────────
    if network and network.get("available"):
        E.append(PageBreak())
        E.append(Paragraph("9. Network Traffic Analysis (PCAP)", S["section"]))
        E.append(_hr())
        summ = network.get("summary", {})
        _kv_table(E, [
            ["Total Packets",     str(summ.get("total_packets", 0))],
            ["Unique Remote IPs", str(summ.get("unique_remote_ips", 0))],
            ["DNS Queries",       str(summ.get("dns_query_count", 0))],
            ["HTTP Hosts",        str(summ.get("http_host_count", 0))],
            ["TLS SNI Hosts",     str(summ.get("tls_sni_count", 0))],
            ["Beaconing Alerts",  str(summ.get("beaconing_alerts", 0))],
            ["DGA Suspects",      str(summ.get("dga_suspects", 0))],
            ["India IOC Hits",    str(summ.get("india_hits", 0))],
            ["PCAP Risk",         network.get("pcap_risk", "—")],
        ])
        if network.get("beaconing_alerts"):
            E.append(Paragraph("C2 Beaconing Alerts", S["sub"]))
            _grid_table(E,
                [["IP", "Contacts", "Interval (s)", "Jitter CV", "Confidence"]] + [
                    [b["ip"], str(b["contact_count"]), str(b["avg_interval_sec"]),
                     str(b["jitter_cv"]), b["confidence"]]
                    for b in network["beaconing_alerts"]
                ],
                [4 * cm, 2 * cm, 3 * cm, 2.5 * cm, 2.5 * cm],
            )
        if network.get("dga_suspects"):
            E.append(Paragraph("DGA Domain Suspects", S["sub"]))
            _grid_table(E,
                [["Domain", "Queries", "Entropy"]] + [
                    [d["domain"], str(d["query_count"]), str(d["entropy"])]
                    for d in network["dga_suspects"][:20]
                ],
                [9 * cm, 2.5 * cm, 2.5 * cm],
            )

    # ── 10. Obfuscation ───────────────────────────────────────────────────────
    E.append(Paragraph("10. Obfuscation & Packing", S["section"]))
    E.append(_hr())
    _kv_table(E, [
        ["Obfuscation Score",  f"{obf.get('score', 0)} / 100"],
        ["Short Class Ratio",  f"{obf.get('short_class_ratio', 0):.1%}"],
        ["Short Method Ratio", f"{obf.get('short_method_ratio', 0):.1%}"],
        ["Reflection",         "YES" if obf.get("has_reflection") else "No"],
        ["DexClassLoader",     "YES" if obf.get("has_dex_classloader") else "No"],
        ["Native Libs",        "YES" if obf.get("has_native_libs") else "No"],
        ["String Encryption",  "YES" if obf.get("has_string_encryption") else "No"],
    ])

    # ── Footer ────────────────────────────────────────────────────────────────
    E.append(Spacer(1, 1 * cm))
    E.append(HRFlowable(width="100%", thickness=0.5, color=_BORDER))
    E.append(Spacer(1, 0.2 * cm))
    E.append(Paragraph(
        f"DroidRaksha Forensic Report · ID: {analysis_id} · {now} · CONFIDENTIAL · PHAPGUYZ",
        S["footer"],
    ))

    doc.build(E)
    pdf = buf.getvalue()
    buf.close()
    return pdf

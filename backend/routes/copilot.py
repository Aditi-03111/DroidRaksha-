"""
Threat Copilot API — DroidRaksha
================================
Streaming chat endpoint that accepts a user question + analysis_id,
fetches the full analysis context from the database, and streams
an LLM-powered conversational explanation back to the frontend.

Primary: Google Gemini 2.0 Flash
Fallback: Groq (Llama 3 70B) — used when Gemini is unavailable or fails.
"""
from __future__ import annotations
import os
import json
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from loguru import logger
from backend.db import database

router = APIRouter()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")


class CopilotRequest(BaseModel):
    analysis_id: str
    question: str
    context_tab: str = "overview"  # which tab the user is on


def _build_system_prompt(analysis: dict, tab: str) -> str:
    """Build a rich system prompt with the full analysis context."""
    pkg = analysis.get("manifest", {}).get("package_name", "unknown")
    risk = analysis.get("risk", {})
    ml = analysis.get("ml_classification", {})
    yara = analysis.get("yara", {})
    perms = analysis.get("manifest", {}).get("permissions", [])
    strings = analysis.get("strings", {})
    mitre = analysis.get("mitre", [])
    xgboost = analysis.get("xgboost", {})
    anomaly = analysis.get("anomaly", {})
    agent_verdict = analysis.get("agent_verdict", {})
    india_ioc = analysis.get("india_ioc", {})
    hashes = analysis.get("hashes", {})

    dangerous_perms = [
        p.get("name", "").split(".")[-1]
        for p in perms if p.get("is_dangerous")
    ]
    yara_rules = [m.get("rule", "") for m in yara.get("matches", [])[:10]]
    mitre_tactics = [
        f'{t.get("technique_id", "")} {t.get("technique_name", "")}'
        for t in (mitre or [])[:10]
    ]
    suspicious_strings = [
        s.get("value", "")
        for s in strings.get("suspicious_strings", [])[:10]
    ]

    return f"""You are DroidRaksha's Threat Copilot — a friendly, expert AI assistant embedded inside an Android malware analysis platform.

Your role is to help NON-TECHNICAL users (students, business executives, junior analysts) understand what was found in a scanned APK file, in simple, conversational English.

RULES:
- Use simple language. Avoid jargon unless the user specifically asks for technical details.
- When explaining a permission or YARA rule, give a real-world analogy (e.g., "READ_SMS is like giving someone access to read all your text messages, including OTP codes from your bank").
- Keep answers concise (3-5 sentences for simple questions, more for "explain everything").
- If the user asks "is this app safe?", give a clear YES/NO answer FIRST, then explain why.
- Reference the actual data from the analysis below — don't make up findings.
- Use markdown formatting for emphasis and bullet points.

─── CURRENT ANALYSIS CONTEXT ───
**Package:** {pkg}
**File:** {analysis.get('filename', 'unknown')}
**SHA-256:** {hashes.get('sha256', 'N/A')}
**File Size:** {hashes.get('file_size', 0)} bytes
**Risk Score:** {risk.get('score', 0)}/100 ({risk.get('risk_level', 'UNKNOWN')})

**ML Classification:** {ml.get('family', 'Unknown')} (confidence: {ml.get('confidence', 0)}%)
**XGBoost Label:** {xgboost.get('label', 'N/A')} ({round((xgboost.get('probability', 0)) * 100, 1)}%)
**Anomaly Detection:** {anomaly.get('zero_day_risk', 'N/A')} — {anomaly.get('explanation', '')}

**Dangerous Permissions ({len(dangerous_perms)}):** {', '.join(dangerous_perms[:15]) or 'None'}
**YARA Matches ({len(yara.get('matches', []))}):** {', '.join(yara_rules) or 'None'}
**MITRE ATT&CK:** {', '.join(mitre_tactics) or 'None'}
**Suspicious Strings:** {', '.join(suspicious_strings[:8]) or 'None'}

**India IOC Flags:** Fake UPI={india_ioc.get('is_fake_upi', False)}, Fake Bank={india_ioc.get('is_fake_bank', False)}, Loan Scam={india_ioc.get('is_loan_scam', False)}
**Risk Flags:** {', '.join(india_ioc.get('risk_flags', [])) or 'None'}

**Agent Verdict:** {agent_verdict.get('court_narrative', 'Not available')[:300]}

**User is currently viewing tab:** {tab}
"""


@router.post("/copilot/chat")
async def copilot_chat(req: CopilotRequest):
    """
    Streaming chat endpoint for the Threat Copilot.
    Tries Gemini first, falls back to Groq if Gemini fails.
    """
    if not GEMINI_API_KEY and not GROQ_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="No AI keys configured. Set GEMINI_API_KEY or GROQ_API_KEY in .env"
        )

    # Fetch analysis
    analysis = await database.get_analysis(req.analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    data = analysis if isinstance(analysis, dict) else (
        analysis.__dict__ if hasattr(analysis, "__dict__") else {}
    )

    system_prompt = _build_system_prompt(data, req.context_tab)

    async def generate():
        used_fallback = False

        # ── Try Gemini first ─────────────────────────────────────────────
        if GEMINI_API_KEY:
            try:
                import google.generativeai as genai
                genai.configure(api_key=GEMINI_API_KEY)

                model = genai.GenerativeModel(
                    "gemini-2.0-flash",
                    system_instruction=system_prompt,
                )

                response = model.generate_content(
                    req.question,
                    stream=True,
                )

                for chunk in response:
                    if chunk.text:
                        yield chunk.text

                return  # Success — don't fall through to Groq

            except Exception as e:
                logger.warning(f"Gemini Copilot failed, falling back to Groq: {e}")
                used_fallback = True

        # ── Fallback: Groq (Llama 3 70B) ─────────────────────────────────
        if (used_fallback or not GEMINI_API_KEY) and GROQ_API_KEY:
            try:
                from groq import Groq
                client = Groq(api_key=GROQ_API_KEY)

                response = client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": req.question},
                    ],
                    temperature=0.4,
                    max_tokens=1500,
                    stream=True,
                )

                for chunk in response:
                    delta = chunk.choices[0].delta
                    if delta and delta.content:
                        yield delta.content

                return

            except Exception as e:
                logger.error(f"Groq Copilot also failed: {e}")
                yield f"\n\n⚠️ Both AI services are unavailable. Error: {str(e)[:200]}"
                return

        yield "\n\n⚠️ No AI service available. Please check your API keys in .env"

    return StreamingResponse(
        generate(),
        media_type="text/plain",
        headers={
            "Cache-Control": "no-cache",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/copilot/quick-explain")
async def copilot_quick_explain(req: CopilotRequest):
    """
    Non-streaming endpoint for quick tooltip explanations.
    Tries Gemini first, falls back to Groq.
    """
    if not GEMINI_API_KEY and not GROQ_API_KEY:
        return {"explanation": "No AI keys configured. Set GEMINI_API_KEY or GROQ_API_KEY in .env"}

    analysis = await database.get_analysis(req.analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    data = analysis if isinstance(analysis, dict) else (
        analysis.__dict__ if hasattr(analysis, "__dict__") else {}
    )

    system_prompt = _build_system_prompt(data, req.context_tab)

    # ── Try Gemini first ─────────────────────────────────────────────
    if GEMINI_API_KEY:
        try:
            import google.generativeai as genai
            genai.configure(api_key=GEMINI_API_KEY)

            model = genai.GenerativeModel(
                "gemini-2.0-flash",
                system_instruction=system_prompt + "\n\nKEEP YOUR ANSWER TO 2-3 SENTENCES MAX.",
            )

            result = model.generate_content(req.question)
            return {"explanation": result.text}

        except Exception as e:
            logger.warning(f"Gemini quick-explain failed, trying Groq: {e}")

    # ── Fallback: Groq ───────────────────────────────────────────────
    if GROQ_API_KEY:
        try:
            from groq import Groq
            client = Groq(api_key=GROQ_API_KEY)

            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": system_prompt + "\n\nKEEP YOUR ANSWER TO 2-3 SENTENCES MAX."},
                    {"role": "user", "content": req.question},
                ],
                temperature=0.4,
                max_tokens=300,
            )

            return {"explanation": response.choices[0].message.content}

        except Exception as e:
            logger.error(f"Groq quick-explain also failed: {e}")

    return {"explanation": "AI services are currently unavailable. Please try again later."}


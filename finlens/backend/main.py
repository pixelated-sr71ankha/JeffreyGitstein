"""
FinLens — AI-Powered Financial Safety Net
Main FastAPI application serving the backend API and frontend.

Built for ForgeAI Hackathon @ graVITas'26
Track: AI for Finance (Scam Detection + Financial Literacy)
Observability: PRISM by Block Convey
"""

import os
import uuid
import time
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

from prism_config import prism, DEFAULT_MODEL
from llm import llm_call, gemini_configured, LLMError
from agents.scam_analyzer import analyze_scam
from agents.finance_health import check_financial_health
from agents.literacy_chat import financial_qa
from guardrails import check_guardrails, sanitize_input

load_dotenv()


# ─── Request/Response Models ───────────────────────────────────────

class ScamRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=5000, description="Suspicious message to analyze")
    session_id: str | None = Field(None, description="Optional session ID for conversation tracking")

class FinanceHealthRequest(BaseModel):
    profile: str = Field(..., min_length=1, max_length=5000, description="Income and expense details")
    session_id: str | None = Field(None)

class LiteracyRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=2000, description="Financial literacy question")
    session_id: str | None = Field(None)

class ApiResponse(BaseModel):
    success: bool
    data: dict
    session_id: str
    prism_trace_status: str | None = None


# ─── App Lifecycle ─────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown hooks."""
    print(f"\n{'='*60}")
    print(f"  FinLens — AI Financial Safety Net")
    print(f"  Model: {DEFAULT_MODEL}")
    print(f"  Gemini: {'Ready' if gemini_configured() else 'Missing GOOGLE_API_KEY'}")
    print(f"  PRISM: {'Connected' if prism.enabled else 'Disabled (no credentials)'}")
    print(f"  PRISM Project: {prism.project_id[:8]}..." if prism.project_id else "  PRISM Project: N/A")
    print(f"{'='*60}\n")
    if not gemini_configured():
        print("  Add GOOGLE_API_KEY to backend/.env, then restart.\n")
    yield


# ─── FastAPI App ───────────────────────────────────────────────────

app = FastAPI(
    title="FinLens",
    description="AI-Powered Financial Safety Net — Scam Detection + Financial Literacy",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend static files
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


# ─── API Endpoints ─────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    """Serve the main frontend page."""
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<h1>FinLens Backend Running</h1><p>Frontend not found.</p>")


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy" if gemini_configured() else "degraded",
        "service": "FinLens",
        "gemini_configured": gemini_configured(),
        "prism_connected": prism.enabled,
        "model": DEFAULT_MODEL,
    }


@app.post("/api/analyze-scam", response_model=ApiResponse)
async def api_analyze_scam(req: ScamRequest):
    """
    Analyze a suspicious message for scam indicators.
    This is the core FinLens feature.
    """
    session_id = req.session_id or prism.new_session_id()
    message = sanitize_input(req.message)

    if not message:
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    start = time.perf_counter()
    try:
        result = await analyze_scam(message, llm_call)
        latency_ms = int((time.perf_counter() - start) * 1000)

        # Trace to PRISM
        trace_result = await prism.trace(
            input_messages=[{"role": "user", "content": message}],
            output_message=json.dumps(result, ensure_ascii=False)[:4000],
            model=DEFAULT_MODEL,
            agent_id="finlens-scam-analyzer",
            session_id=session_id,
            latency_ms=latency_ms,
            metadata={
                "feature": "scam_analysis",
                "risk_level": result.get("risk_level"),
                "risk_score": result.get("risk_score"),
                "scam_type": result.get("scam_type"),
            },
        )

        _record_scan("scam", result)
        return ApiResponse(
            success=True,
            data=result,
            session_id=session_id,
            prism_trace_status=trace_result.get("status"),
        )
    except Exception as e:
        # Still trace errors to PRISM for observability
        latency_ms = int((time.perf_counter() - start) * 1000)
        await prism.trace(
            input_messages=[{"role": "user", "content": message}],
            output_message=f"[ERROR] {str(e)}",
            model=DEFAULT_MODEL,
            agent_id="finlens-scam-analyzer",
            session_id=session_id,
            latency_ms=latency_ms,
            metadata={"error": True},
        )
        status = 503 if isinstance(e, LLMError) else 500
        raise HTTPException(status_code=status, detail=str(e))


@app.post("/api/finance-health", response_model=ApiResponse)
async def api_finance_health(req: FinanceHealthRequest):
    """Analyze user's financial health from income/expense profile."""
    session_id = req.session_id or prism.new_session_id()
    profile = sanitize_input(req.profile)

    start = time.perf_counter()
    try:
        result = await check_financial_health(profile, llm_call)
        latency_ms = int((time.perf_counter() - start) * 1000)
        trace_result = await prism.trace(
            input_messages=[{"role": "user", "content": profile}],
            output_message=json.dumps(result, ensure_ascii=False)[:4000],
            model=DEFAULT_MODEL,
            agent_id="finlens-finance-health",
            session_id=session_id,
            latency_ms=latency_ms,
            metadata={
                "feature": "finance_health",
                "health_score": result.get("health_score"),
                "health_grade": result.get("health_grade"),
            },
        )

        _record_scan("health", result)
        return ApiResponse(
            success=True,
            data=result,
            session_id=session_id,
            prism_trace_status=trace_result.get("status"),
        )
    except Exception as e:
        latency_ms = int((time.perf_counter() - start) * 1000)
        await prism.trace(
            input_messages=[{"role": "user", "content": profile}],
            output_message=f"[ERROR] {str(e)}",
            model=DEFAULT_MODEL,
            agent_id="finlens-finance-health",
            session_id=session_id,
            latency_ms=latency_ms,
            metadata={"error": True},
        )
        status = 503 if isinstance(e, LLMError) else 500
        raise HTTPException(status_code=status, detail=str(e))



@app.post("/api/financial-qa", response_model=ApiResponse)
async def api_financial_qa(req: LiteracyRequest):
    """Answer a financial literacy question."""
    session_id = req.session_id or prism.new_session_id()
    question = sanitize_input(req.question)

    start = time.perf_counter()
    try:
        result = await financial_qa(question, llm_call)
        latency_ms = int((time.perf_counter() - start) * 1000)

        # Apply guardrails
        guardrail_result = check_guardrails(result.get("response", ""))

        if not guardrail_result["passed"]:
            # Log guardrail violations to PRISM
            await prism.trace(
                input_messages=[{"role": "user", "content": question}],
                output_message=f"[GUARDRAIL VIOLATION] {json.dumps(guardrail_result['violations'])}",
                model=DEFAULT_MODEL,
                agent_id="finlens-literacy-chat",
                session_id=session_id,
                latency_ms=latency_ms,
                metadata={
                    "feature": "financial_qa",
                    "guardrail_violations": guardrail_result["violation_count"],
                },
            )

        # Update response with guardrail-safe version
        result["response"] = guardrail_result["modified_text"]

        trace_result = await prism.trace(
            input_messages=[{"role": "user", "content": question}],
            output_message=json.dumps(result, ensure_ascii=False)[:4000],
            model=DEFAULT_MODEL,
            agent_id="finlens-literacy-chat",
            session_id=session_id,
            latency_ms=latency_ms,
            metadata={
                "feature": "financial_qa",
                "topic": result.get("topic"),
                "guardrail_passed": guardrail_result["passed"],
            },
        )

        _record_scan("qa", result)
        return ApiResponse(
            success=True,
            data=result,
            session_id=session_id,
            prism_trace_status=trace_result.get("status"),
        )
    except Exception as e:
        latency_ms = int((time.perf_counter() - start) * 1000)
        await prism.trace(
            input_messages=[{"role": "user", "content": question}],
            output_message=f"[ERROR] {str(e)}",
            model=DEFAULT_MODEL,
            agent_id="finlens-literacy-chat",
            session_id=session_id,
            latency_ms=latency_ms,
            metadata={"error": True},
        )
        status = 503 if isinstance(e, LLMError) else 500
        raise HTTPException(status_code=status, detail=str(e))


@app.get("/api/prism-status")
async def api_prism_status():
    """Check PRISM connection health."""
    return {
        "enabled": prism.enabled,
        "project_id": prism.project_id[:8] + "..." if prism.project_id else None,
        "host": prism.host,
    }


# ─── Dynamic Stats ──────────────────────────────────────────────

# In-memory counters (resets on server restart)
_stats = {
    "total_scans": 0,
    "scam_detected": 0,
    "health_checks": 0,
    "qa_questions": 0,
    "scam_types_seen": set(),
    "risk_distribution": {"SAFE": 0, "SUSPICIOUS": 0, "DANGEROUS": 0, "CONFIRMED_SCAM": 0},
}


def _record_scan(scan_type: str, result: dict = None):
    """Record a scan in the stats counter."""
    _stats["total_scans"] += 1
    if scan_type == "scam":
        _stats["scam_detected"] += 1
        if result:
            risk = result.get("risk_level", "SAFE")
            _stats["risk_distribution"][risk] = _stats["risk_distribution"].get(risk, 0) + 1
            scam_type = result.get("scam_type")
            if scam_type:
                _stats["scam_types_seen"].add(scam_type)
    elif scan_type == "health":
        _stats["health_checks"] += 1
    elif scan_type == "qa":
        _stats["qa_questions"] += 1


@app.get("/api/stats")
async def api_stats():
    """Return dynamic stats for the dashboard."""
    return {
        "total_scans": _stats["total_scans"],
        "scam_types_count": len(_stats["scam_types_seen"]),
        "scam_types_list": list(_stats["scam_types_seen"]),
        "scam_detected": _stats["scam_detected"],
        "health_checks": _stats["health_checks"],
        "qa_questions": _stats["qa_questions"],
        "risk_distribution": _stats["risk_distribution"],
        "prism_traces": prism._session_counter,
    }


# ─── Run ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    reload = os.getenv("FINLENS_RELOAD", "false").lower() in ("1", "true", "yes")
    uvicorn.run("main:app", host="127.0.0.1", port=port, reload=reload)

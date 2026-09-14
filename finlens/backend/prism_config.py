"""
PRISM by Block Convey — Observability Configuration
This module initializes PRISM trace handlers for every AI agent in FinLens.
Every user interaction is traced, scored, and observable.
"""

import os
import uuid
import time
from dotenv import load_dotenv

load_dotenv()

# ─── PRISM Credentials ────────────────────────────────────────────
PRISM_HOST = os.getenv("PRISMTRACE_HOST", "https://prism.blockconvey.com")
PRISM_PROJECT_ID = os.getenv("PRISMTRACE_PROJECT_ID", "")
PRISM_API_KEY = os.getenv("PRISMTRACE_API_KEY", "")

# ─── LLM Credentials (Gemini only) ────────────────────────────────
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
DEFAULT_MODEL = os.getenv("FINLENS_MODEL", "gemini-3.6-flash")


class PrismTracker:
    """
    Lightweight PRISM trace emitter using the HTTP API.
    Works with any LLM backend — no framework dependency required.
    Every method sends a trace to PRISM so the dashboard lights up
    with real data the judges can see.
    """

    def __init__(self):
        self.host = PRISM_HOST
        self.project_id = PRISM_PROJECT_ID
        self.api_key = PRISM_API_KEY
        self.enabled = bool(
            self.api_key
            and self.project_id
            and "your-" not in self.api_key.lower()
            and "your-" not in self.project_id.lower()
        )
        self._session_counter = 0

    def new_session_id(self) -> str:
        """Generate a unique session ID for conversation continuity."""
        self._session_counter += 1
        return f"finlens-session-{uuid.uuid4().hex[:12]}"

    async def trace(
        self,
        *,
        input_messages: list[dict],
        output_message: str,
        model: str,
        agent_id: str,
        session_id: str,
        latency_ms: int,
        metadata: dict | None = None,
    ):
        """
        Send a single trace to PRISM.
        This is the core observation unit — PRISM scores, clusters,
        and analyzes every trace automatically.
        """
        if not self.enabled:
            return {"status": "disabled", "reason": "No PRISM credentials"}

        import httpx

        payload = {
            "project_id": self.project_id,
            "model": model,
            "input_messages": input_messages,
            "output_message": output_message,
            "latency_ms": latency_ms,
            "session_id": session_id,
            "agent_id": agent_id,
        }
        if metadata:
            payload["metadata"] = metadata

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    f"{self.host}/api/traces",
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-PRISMtrace-Key": self.api_key,
                    },
                )
                if resp.status_code == 200:
                    return {"status": "ok", "trace_id": resp.json().get("id")}
                else:
                    return {"status": "error", "code": resp.status_code, "body": resp.text[:200]}
        except Exception as e:
            return {"status": "error", "exception": str(e)}

    async def trace_with_timing(self, *, fn, input_text: str, agent_id: str, session_id: str, model: str):
        """
        Wrap an async function call with PRISM tracing.
        Automatically measures latency and records input/output.
        """
        start = time.perf_counter()
        try:
            result = await fn()
            latency_ms = int((time.perf_counter() - start) * 1000)

            await self.trace(
                input_messages=[{"role": "user", "content": input_text}],
                output_message=str(result)[:4000],
                model=model,
                agent_id=agent_id,
                session_id=session_id,
                latency_ms=latency_ms,
            )
            return result
        except Exception as e:
            latency_ms = int((time.perf_counter() - start) * 1000)
            await self.trace(
                input_messages=[{"role": "user", "content": input_text}],
                output_message=f"[ERROR] {str(e)}",
                model=model,
                agent_id=agent_id,
                session_id=session_id,
                latency_ms=latency_ms,
                metadata={"error": True, "error_type": type(e).__name__},
            )
            raise


# Singleton tracker — imported everywhere
prism = PrismTracker()

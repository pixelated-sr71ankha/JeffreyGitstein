"""
Gemini LLM client for FinLens.

Every agent call goes through this module. There is no demo fallback
and no OpenAI/Anthropic routing — a missing or invalid Google API key
fails loudly so the UI can show a real error.
"""

from __future__ import annotations

import logging

from google import genai
from google.genai import types

from prism_config import DEFAULT_MODEL, GOOGLE_API_KEY

logger = logging.getLogger("finlens.llm")

_client: genai.Client | None = None


class LLMError(RuntimeError):
    """Raised when Gemini is not configured or the API call fails."""


def gemini_configured() -> bool:
    key = (GOOGLE_API_KEY or "").strip()
    if not key:
        return False
    if key.lower().startswith("your-") or key.startswith("AIza-your"):
        return False
    return len(key) > 10


def get_client() -> genai.Client:
    global _client
    if not gemini_configured():
        raise LLMError(
            "GOOGLE_API_KEY is not set. Add your Gemini API key to backend/.env and restart the server."
        )
    if _client is None:
        _client = genai.Client(api_key=GOOGLE_API_KEY.strip())
    return _client


def _extract_text(response) -> str:
    text = getattr(response, "text", None)
    if text:
        return text.strip()

    candidates = getattr(response, "candidates", None) or []
    chunks: list[str] = []
    for candidate in candidates:
        content = getattr(candidate, "content", None)
        parts = getattr(content, "parts", None) or []
        for part in parts:
            part_text = getattr(part, "text", None)
            if part_text and not getattr(part, "thought", False):
                chunks.append(part_text)
    return "\n".join(chunks).strip()


async def llm_call(system_prompt: str, user_prompt: str) -> str:
    """
    Call Gemini with a system instruction + user prompt.
    Agents expect JSON text back.
    """
    client = get_client()
    last_error: Exception | None = None

    for attempt in range(2):
        try:
            response = await client.aio.models.generate_content(
                model=DEFAULT_MODEL,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    temperature=0.3,
                    max_output_tokens=8192,
                    response_mime_type="application/json",
                    automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
                ),
            )
            text = _extract_text(response)
            if not text:
                raise LLMError("Gemini returned an empty response. Try again or check the model name.")
            return text
        except LLMError:
            raise
        except Exception as e:
            last_error = e
            logger.warning("Gemini call failed (attempt %s): %s", attempt + 1, e)

    raise LLMError(f"Gemini request failed: {last_error}")

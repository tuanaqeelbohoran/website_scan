"""agents/base_agent.py — thin async wrapper around an Ollama-compatible LLM API.

All agents extend this class.  The model is loaded from settings and can be
swapped for any Ollama-served model (llama3, mistral, …) or even a remote
OpenAI-compatible endpoint by updating OLLAMA_BASE_URL + SLM_MODEL.

Important safety constraints:
- The base class sets a hard token cap (MAX_TOKENS_OUT=512) to prevent
  cost blow-outs and prompt-injection amplification.
- System prompts must always be provided explicitly by each sub-agent.
- Responses are trimmed and returned as plain text — agents MUST NOT
  auto-execute any content from LLM output.
"""
from __future__ import annotations

import logging
from typing import Protocol

import httpx

from config.settings import settings

log = logging.getLogger("webscan.agents")

MAX_TOKENS_OUT = 512
REQUEST_TIMEOUT = 60.0


class BaseAgent:
    """Provide a `_prompt(system, user)` coroutine for interacting with Ollama."""

    def __init__(self) -> None:
        self._base_url: str = getattr(settings, "OLLAMA_BASE_URL", "http://127.0.0.1:11434")
        self._model:    str = getattr(settings, "SLM_MODEL",        "llama3")
        self._enabled:  bool = getattr(settings, "ENABLE_SLM_AGENTS", False)

    async def _prompt(self, system: str, user: str) -> str:
        """Call Ollama /api/chat and return stripped response text.

        Returns an empty string if agents are disabled or a network error occurs.
        Never raises — callers must handle empty string gracefully.
        """
        if not self._enabled:
            return ""
        payload = {
            "model": self._model,
            "stream": False,
            "options": {"num_predict": MAX_TOKENS_OUT},
            "messages": [
                {"role": "system",  "content": system},
                {"role": "user",    "content": user},
            ],
        }
        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
                resp = await client.post(f"{self._base_url}/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()
            text: str = data.get("message", {}).get("content", "") or ""
            return text.strip()
        except Exception as exc:
            log.warning("Agent LLM call failed: %s", exc)
            return ""

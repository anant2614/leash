"""Nemotron via Nebius Token Factory (OpenAI-compatible chat completions).

Configuration (environment):
  NEBIUS_API_KEY      Token Factory API key (required for LLM features)
  NEBIUS_BASE_URL     default https://api.tokenfactory.nebius.com/v1
  LEASH_MODEL         model id; if unset or not served, Leash picks the first
                      model whose id contains "nemotron" from GET /models.

Without a key every LLM feature falls back to deterministic heuristics, and
the output says so (`engine: heuristic`) so results are never passed off as
model output.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

DEFAULT_BASE = "https://api.tokenfactory.nebius.com/v1"
DEFAULT_MODEL = "nvidia/nemotron-3-super-120b-a12b"


class LLMError(RuntimeError):
    pass


class Nemotron:
    def __init__(self, api_key: str | None = None, base_url: str | None = None,
                 model: str | None = None, timeout: float = 90.0):
        self.api_key = api_key or os.environ.get("NEBIUS_API_KEY")
        self.base_url = (base_url or os.environ.get("NEBIUS_BASE_URL") or DEFAULT_BASE).rstrip("/")
        self._model = model or os.environ.get("LEASH_MODEL")
        self.timeout = timeout
        self.calls = 0

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def _req(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f"{self.base_url}{path}", data=data, method=method,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise LLMError(f"Token Factory HTTP {e.code}: {e.read()[:300]!r}") from e
        except urllib.error.URLError as e:
            raise LLMError(f"Token Factory unreachable: {e.reason}") from e

    def models(self) -> list[str]:
        return [m["id"] for m in self._req("GET", "/models").get("data", [])]

    @property
    def model(self) -> str:
        if self._model:
            return self._model
        try:
            ids = self.models()
        except LLMError:
            ids = []
        if DEFAULT_MODEL in ids or not ids:
            self._model = DEFAULT_MODEL
        else:
            nemo = [i for i in ids if "nemotron" in i.lower()]
            # prefer the larger "super"/"ultra" models for reasoning quality
            nemo.sort(key=lambda i: (("ultra" not in i.lower()) and ("super" not in i.lower()), i))
            self._model = nemo[0] if nemo else DEFAULT_MODEL
        return self._model

    def chat_json(self, system: str, user: str, *, max_tokens: int = 2000) -> dict[str, Any]:
        """Ask for a JSON object and parse it robustly."""
        if not self.available:
            raise LLMError("NEBIUS_API_KEY is not set")
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0.1,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }
        try:
            out = self._req("POST", "/chat/completions", body)
        except LLMError as e:
            if "response_format" in str(e):
                body.pop("response_format")
                out = self._req("POST", "/chat/completions", body)
            else:
                raise
        self.calls += 1
        text = out["choices"][0]["message"].get("content") or ""
        return extract_json(text)


def extract_json(text: str) -> dict:
    # Reasoning models may prepend <think>...</think>; strip it.
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, flags=re.S)
    if fence:
        text = fence.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < 0:
        raise LLMError(f"model did not return JSON: {text[:200]!r}")
    try:
        return json.loads(text[start:end + 1])
    except ValueError as e:
        raise LLMError(f"invalid JSON from model: {e}") from e

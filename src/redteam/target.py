"""Adapter to the System Under Test. One interface so the campaign can point at
the Project 4 RAG app (HTTP) or a raw model, and support multi-turn escalation.
"""

from __future__ import annotations

from typing import Protocol


class Target(Protocol):
    def send(self, prompt: str, history: list[dict] | None = None) -> str:
        """Send one turn; return the target's text response."""
        ...


class HttpAppTarget:
    """Calls a deployed app like Project 4's POST /ask."""

    def __init__(self, url: str) -> None:
        self.url = url

    def send(self, prompt: str, history: list[dict] | None = None) -> str:
        # TODO(you): httpx.post(self.url, json={"query": prompt}); return data["text"].
        raise NotImplementedError("wire up the HTTP call to your target app")


class ModelTarget:
    """Calls a raw model via LiteLLM/OpenAI for testing a model directly."""

    def __init__(self, model: str, system: str = "") -> None:
        self.model = model
        self.system = system

    def send(self, prompt: str, history: list[dict] | None = None) -> str:
        # TODO(you): build messages (system + history + prompt), call the model.
        raise NotImplementedError("wire up the model call")


def build_target(cfg: dict) -> Target:
    t = cfg["target"]
    if t["type"] == "http_app":
        return HttpAppTarget(t["url"])
    return ModelTarget(t.get("model", "openai/gpt-4o-mini"))

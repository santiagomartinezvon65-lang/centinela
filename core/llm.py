"""Backends de LLM para el agente — Claude (API) u Ollama (local, gratis, offline).

El agente es provider-agnóstico: usa la misma interfaz `Backend` sin importar
quién razona detrás. Ollama no necesita API key ni pip (habla por urllib).
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
DEFAULTS = {"anthropic": "claude-opus-4-8", "ollama": "qwen2.5:7b"}


class Turn:
    def __init__(self, text: str, tool_calls: list[dict]):
        self.text = text                      # narración del modelo
        self.tool_calls = tool_calls          # [{"id","name","input"}]


class Backend:
    name = ""

    def add_user(self, text: str) -> None: ...
    def step(self) -> Turn: ...
    def add_tool_results(self, results: list[dict]) -> None: ...  # [{"id","name","content","is_error"}]
    def usage(self) -> tuple[int, int]:  # (in_tokens, out_tokens)
        return (0, 0)


# ── Claude (Anthropic API) ──────────────────────────────────────────
class AnthropicBackend(Backend):
    name = "anthropic"

    def __init__(self, model: str, system: str, tools: list[dict]):
        import anthropic
        self.client = anthropic.Anthropic()
        self.model = model
        self.system = [{"type": "text", "text": system,
                        "cache_control": {"type": "ephemeral"}}]
        self.tools = tools  # ya en formato Anthropic (name/description/input_schema)
        self.messages: list = []
        self.in_t = 0
        self.out_t = 0
        self._thinking = True

    def add_user(self, text: str) -> None:
        self.messages.append({"role": "user", "content": text})

    def step(self) -> Turn:
        kwargs = dict(model=self.model, max_tokens=8000, system=self.system,
                      tools=self.tools, messages=self.messages)
        if self._thinking:
            kwargs["thinking"] = {"type": "adaptive"}
        try:
            resp = self.client.messages.create(**kwargs)
        except Exception as e:  # noqa: BLE001
            if self._thinking and ("thinking" in str(e).lower()
                                   or "adaptive" in str(e).lower()):
                self._thinking = False
                kwargs.pop("thinking", None)
                resp = self.client.messages.create(**kwargs)
            else:
                raise
        u = resp.usage
        self.in_t += (u.input_tokens + getattr(u, "cache_read_input_tokens", 0)
                      + getattr(u, "cache_creation_input_tokens", 0))
        self.out_t += u.output_tokens
        self.messages.append({"role": "assistant", "content": resp.content})

        text = " ".join(b.text for b in resp.content
                        if b.type == "text" and b.text.strip())
        calls = [{"id": b.id, "name": b.name, "input": b.input}
                 for b in resp.content if b.type == "tool_use"]
        return Turn(text, calls)

    def add_tool_results(self, results: list[dict]) -> None:
        self.messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": r["id"],
             "content": r["content"], "is_error": r["is_error"]} for r in results]})

    def usage(self):
        return (self.in_t, self.out_t)


# ── Ollama (local, sin API key) ─────────────────────────────────────
class OllamaBackend(Backend):
    name = "ollama"

    def __init__(self, model: str, system: str, tools: list[dict]):
        self.model = model
        # Anthropic schema → OpenAI/Ollama function schema
        self.tools = [{"type": "function", "function": {
            "name": t["name"], "description": t["description"],
            "parameters": t["input_schema"]}} for t in tools]
        self.messages = [{"role": "system", "content": system}]
        self.in_t = 0
        self.out_t = 0

    def add_user(self, text: str) -> None:
        self.messages.append({"role": "user", "content": text})

    def _post(self, payload: dict) -> dict:
        req = urllib.request.Request(
            OLLAMA_HOST + "/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=600) as r:
            return json.loads(r.read())

    def step(self) -> Turn:
        data = self._post({"model": self.model, "messages": self.messages,
                           "tools": self.tools, "stream": False})
        msg = data.get("message", {})
        self.in_t += data.get("prompt_eval_count", 0)
        self.out_t += data.get("eval_count", 0)
        self.messages.append(msg)

        calls = []
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc.get("function", {})
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except ValueError:
                    args = {}
            calls.append({"id": f"call_{i}", "name": fn.get("name", ""), "input": args})
        return Turn((msg.get("content") or "").strip(), calls)

    def add_tool_results(self, results: list[dict]) -> None:
        for r in results:
            self.messages.append({"role": "tool", "tool_name": r["name"],
                                  "content": r["content"]})

    def usage(self):
        return (self.in_t, self.out_t)


# ── factory ─────────────────────────────────────────────────────────
def _ollama_up() -> bool:
    try:
        urllib.request.urlopen(OLLAMA_HOST + "/api/tags", timeout=3)
        return True
    except Exception:  # noqa: BLE001
        return False


def make_backend(provider: str, model: str | None, system: str,
                 tools: list[dict]) -> Backend:
    if provider == "auto":
        if os.environ.get("ANTHROPIC_API_KEY"):
            provider = "anthropic"
        elif _ollama_up():
            provider = "ollama"
        else:
            raise RuntimeError(
                "Sin backend disponible: no hay ANTHROPIC_API_KEY ni Ollama corriendo.\n"
                "  • Local/gratis: instalá Ollama (ollama.com), corré `ollama pull qwen2.5:7b`, "
                "y reintenta con --provider ollama.\n"
                "  • Cloud: seteá ANTHROPIC_API_KEY.")
    model = model or DEFAULTS.get(provider)
    if provider == "anthropic":
        return AnthropicBackend(model, system, tools)
    if provider == "ollama":
        if not _ollama_up():
            raise RuntimeError(
                f"Ollama no responde en {OLLAMA_HOST}. ¿Está corriendo? "
                "Instalalo en ollama.com y corré `ollama pull qwen2.5:7b`.")
        return OllamaBackend(model, system, tools)
    raise ValueError(f"provider desconocido: {provider}")

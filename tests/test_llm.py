"""Tests for llm.py. Network is always stubbed via monkeypatching post_json."""
import pytest

from app import llm
from app.models import KnowledgeChunk, LLMRequest


def _chunk(title="CWE-78", text="shell injection guidance"):
    return KnowledgeChunk(id="c1", title=title, source="kb.md", text=text, tags=[title])


def test_provider_status_reflects_env(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    status = llm.provider_status()
    assert status["offline"]["available"] is True
    assert status["ollama"]["available"] is True
    assert status["openai"]["available"] is False
    assert status["openai_compatible"]["available"] is False

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("LLM_BASE_URL", "http://localhost:8001/v1")
    status = llm.provider_status()
    assert status["openai"]["available"] is True
    assert status["openai_compatible"]["available"] is True


def test_offline_generate_is_deterministic():
    resp = llm.generate(LLMRequest(prompt="review this", provider="offline"))
    assert resp.provider == "offline"
    assert resp.model == "deterministic-template"
    assert "Offline review guidance" in resp.text
    assert resp.used_fallback is False


def test_offline_includes_context():
    resp = llm.generate(LLMRequest(prompt="x", provider="offline", context=[_chunk()]))
    assert "CWE-78" in resp.text


def test_build_prompt_with_and_without_context():
    assert llm.build_prompt(LLMRequest(prompt="task only", provider="offline")) == "task only"
    withctx = llm.build_prompt(LLMRequest(prompt="task", provider="offline", context=[_chunk()]))
    assert "Knowledge context:" in withctx and "task" in withctx


def test_openai_without_key_falls_back(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    resp = llm.generate(LLMRequest(prompt="x", provider="openai"))
    assert resp.used_fallback is True
    assert "OPENAI_API_KEY" in (resp.error or "")
    assert resp.provider == "offline"


def test_openai_success(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(llm, "post_json", lambda url, payload, headers: {"output_text": "secure review"})
    resp = llm.generate(LLMRequest(prompt="x", provider="openai"))
    assert resp.provider == "openai" and resp.text == "secure review"
    assert resp.used_fallback is False


def test_openai_extract_response_text(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    payload = {"output": [{"content": [{"type": "output_text", "text": "abc"}]}]}
    monkeypatch.setattr(llm, "post_json", lambda *a, **k: payload)
    resp = llm.generate(LLMRequest(prompt="x", provider="openai"))
    assert resp.text == "abc"


def test_openai_error_falls_back(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    def boom(*a, **k):
        raise RuntimeError("network down")

    monkeypatch.setattr(llm, "post_json", boom)
    resp = llm.generate(LLMRequest(prompt="x", provider="openai"))
    assert resp.used_fallback is True and "network down" in resp.error


def test_ollama_success_and_error(monkeypatch):
    monkeypatch.setattr(llm, "post_json", lambda *a, **k: {"response": "pong"})
    ok = llm.generate(LLMRequest(prompt="x", provider="ollama"))
    assert ok.provider == "ollama" and ok.text == "pong"

    def boom(*a, **k):
        raise RuntimeError("refused")

    monkeypatch.setattr(llm, "post_json", boom)
    fail = llm.generate(LLMRequest(prompt="x", provider="ollama"))
    assert fail.used_fallback is True


def test_openai_compatible(monkeypatch):
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    miss = llm.generate(LLMRequest(prompt="x", provider="openai-compatible"))
    assert miss.used_fallback is True and "LLM_BASE_URL" in miss.error

    monkeypatch.setenv("LLM_BASE_URL", "http://localhost:8001/v1")
    monkeypatch.setattr(llm, "post_json",
                        lambda *a, **k: {"choices": [{"message": {"content": "cc"}}]})
    ok = llm.generate(LLMRequest(prompt="x", provider="openai_compatible"))
    assert ok.provider == "openai_compatible" and ok.text == "cc"

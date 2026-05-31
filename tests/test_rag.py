"""Tests for rag.py (lexical knowledge index)."""
from app import rag

KB = """# Security KB

## CWE-78 OS Command Injection
Avoid passing untrusted input to a shell. Use argument arrays and validation.

## CWE-89 SQL Injection
Use parameterized queries instead of string concatenation.
"""


def test_tokenize_filters_short_tokens():
    toks = rag.tokenize("Use a SQL query")
    assert "sql" in toks and "query" in toks
    assert "a" not in toks  # below the 3-char minimum


def test_build_index_creates_chunks_and_file(isolate_rag):
    (isolate_rag / "kb.md").write_text(KB, encoding="utf-8")
    chunks = rag.build_index()
    titles = {c.title for c in chunks}
    assert "CWE-78 OS Command Injection" in titles
    assert "CWE-89 SQL Injection" in titles
    assert rag.INDEX_PATH.exists()


def test_chunk_tags_extract_cwe(isolate_rag):
    (isolate_rag / "kb.md").write_text(KB, encoding="utf-8")
    chunks = {c.title: c for c in rag.build_index()}
    assert "CWE-78" in chunks["CWE-78 OS Command Injection"].tags


def test_load_index_builds_when_missing(isolate_rag):
    (isolate_rag / "kb.md").write_text(KB, encoding="utf-8")
    assert not rag.INDEX_PATH.exists()
    chunks = rag.load_index()  # should build on demand
    assert chunks and rag.INDEX_PATH.exists()


def test_retrieve_ranks_relevant_chunk_first(isolate_rag):
    (isolate_rag / "kb.md").write_text(KB, encoding="utf-8")
    rag.build_index()
    results = rag.retrieve("shell command injection", limit=5)
    assert results
    assert "Command Injection" in results[0].title
    assert results[0].score > 0


def test_retrieve_empty_query_returns_nothing(isolate_rag):
    (isolate_rag / "kb.md").write_text(KB, encoding="utf-8")
    rag.build_index()
    assert rag.retrieve("   ") == []


def test_add_knowledge_document_then_retrieve(isolate_rag):
    chunk = rag.add_knowledge_document("Custom Topic", "guidance about ssrf and metadata endpoints")
    assert chunk.title == "Custom Topic"
    results = rag.retrieve("ssrf metadata")
    assert any("Custom Topic" == r.title for r in results)

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding, KnowledgeChunk, RagQueryResponse, ScanResult

ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE_DIR = ROOT / 'knowledge'
INDEX_PATH = ROOT / 'data' / 'rag_index.json'
TOKEN_RE = re.compile(r'[a-zA-Z][a-zA-Z0-9_+.-]{1,}')
TAG_RE = re.compile(r'\b(CWE-\d+|A0\d:2021-[A-Za-z -]+|OWASP\s+A0\d|P[0-4]|[A-Z][A-Z0-9_/-]{2,})\b')
MAX_CHUNK_WORDS = 220
CHUNK_OVERLAP_WORDS = 40


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in TOKEN_RE.findall(text)]


def build_index() -> list[KnowledgeChunk]:
    KNOWLEDGE_DIR.mkdir(parents=True, exist_ok=True)
    chunks: list[KnowledgeChunk] = []
    for path in sorted(KNOWLEDGE_DIR.rglob('*.md')):
        chunks.extend(chunks_from_markdown(path))
    INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'chunk_count': len(chunks),
        'sources': sorted({chunk.source for chunk in chunks}),
        'chunks': [chunk.model_dump() for chunk in chunks],
    }
    INDEX_PATH.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    return chunks


def load_index() -> list[KnowledgeChunk]:
    if not INDEX_PATH.exists():
        return build_index()
    payload = json.loads(INDEX_PATH.read_text(encoding='utf-8'))
    if isinstance(payload, list):
        return [KnowledgeChunk.model_validate(item) for item in payload]
    return [KnowledgeChunk.model_validate(item) for item in payload.get('chunks', [])]


def index_stats() -> dict:
    chunks = load_index()
    by_source = Counter(chunk.source for chunk in chunks)
    by_tag = Counter(tag for chunk in chunks for tag in chunk.tags)
    return {
        'chunk_count': len(chunks),
        'source_count': len(by_source),
        'sources': dict(sorted(by_source.items())),
        'top_tags': dict(by_tag.most_common(20)),
        'index_path': str(INDEX_PATH),
    }


def chunks_from_markdown(path: Path) -> list[KnowledgeChunk]:
    text = path.read_text(encoding='utf-8', errors='ignore')
    relative_source = str(path.relative_to(KNOWLEDGE_DIR)).replace('\\', '/')
    document_title = extract_document_title(text, path)
    sections = split_markdown_sections(text, document_title)
    chunks: list[KnowledgeChunk] = []
    for section_title, body in sections:
        for idx, chunk_text in enumerate(split_chunk_text(body or section_title)):
            full_text = chunk_text.strip()
            if not full_text:
                continue
            tags = extract_tags(' '.join([document_title, section_title, full_text]))
            chunk_id = hashlib.sha256(f'{relative_source}:{section_title}:{idx}:{full_text}'.encode('utf-8')).hexdigest()[:16]
            chunks.append(KnowledgeChunk(
                id=chunk_id,
                title=section_title.strip() or document_title,
                section=section_title.strip() or document_title,
                source=relative_source,
                text=full_text,
                tags=tags,
                chunk_index=idx,
                metadata={'document_title': document_title, 'source_type': 'markdown'},
            ))
    return chunks


def extract_document_title(text: str, path: Path) -> str:
    match = re.search(r'(?m)^#\s+(.+)$', text)
    return match.group(1).strip() if match else path.stem.replace('-', ' ').replace('_', ' ').title()


def split_markdown_sections(text: str, document_title: str) -> list[tuple[str, str]]:
    matches = list(re.finditer(r'(?m)^##\s+(.+)$', text))
    if not matches:
        stripped = re.sub(r'(?m)^#\s+.+$', '', text).strip()
        return [(document_title, stripped)]
    sections: list[tuple[str, str]] = []
    for idx, match in enumerate(matches):
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        sections.append((match.group(1).strip(), text[start:end].strip()))
    return sections


def split_chunk_text(text: str) -> list[str]:
    words = text.split()
    if len(words) <= MAX_CHUNK_WORDS:
        return [text]
    chunks = []
    step = MAX_CHUNK_WORDS - CHUNK_OVERLAP_WORDS
    for start in range(0, len(words), step):
        chunk_words = words[start:start + MAX_CHUNK_WORDS]
        if chunk_words:
            chunks.append(' '.join(chunk_words))
        if start + MAX_CHUNK_WORDS >= len(words):
            break
    return chunks


def extract_tags(text: str) -> list[str]:
    found = {tag.strip().replace('OWASP ', '') for tag in TAG_RE.findall(text)}
    for token in tokenize(text):
        if token.startswith('cwe-'):
            found.add(token.upper())
        if token in {'injection', 'xss', 'ssrf', 'secrets', 'secret', 'saml', 'oidc', 'sso', 'dependency', 'dependencies', 'deserialization', 'auth', 'logging'}:
            found.add(token.upper())
    return sorted(found)


def retrieve(query: str, limit: int = 5, tags: list[str] | None = None) -> list[KnowledgeChunk]:
    query_terms = Counter(tokenize(query))
    requested_tags = {tag.upper() for tag in tags or [] if tag}
    if not query_terms and not requested_tags:
        return []
    chunks = load_index()
    doc_freq = document_frequencies(chunks)
    scored: list[KnowledgeChunk] = []
    for chunk in chunks:
        score = score_chunk(chunk, query, query_terms, requested_tags, doc_freq, len(chunks))
        if score > 0:
            scored.append(chunk.model_copy(update={'score': round(score, 3)}))
    return sorted(scored, key=lambda item: (-item.score, item.source, item.chunk_index))[:max(limit, 0)]


def retrieve_response(query: str, limit: int = 5, tags: list[str] | None = None) -> RagQueryResponse:
    results = retrieve(query, limit=limit, tags=tags)
    return RagQueryResponse(query=query, total_indexed=len(load_index()), results=results)


def retrieve_for_finding(finding: Finding, limit: int = 5) -> list[KnowledgeChunk]:
    query_parts = [
        finding.title,
        finding.rule_id,
        finding.message,
        finding.explanation,
        finding.severity,
        finding.risk.tier,
        finding.risk.priority,
        *finding.cwe,
        *finding.owasp,
        *[factor.name for factor in finding.risk.factors],
        *[factor.detail for factor in finding.risk.factors],
    ]
    tags = [*finding.cwe, *finding.owasp, finding.risk.priority, finding.risk.tier]
    return retrieve(' '.join(query_parts), limit=limit, tags=tags)


def finding_context(scan: ScanResult, finding_id: str, limit: int = 5) -> dict:
    finding = next((item for item in scan.findings if item.id == finding_id), None)
    if not finding:
        raise ValueError('finding not found')
    results = retrieve_for_finding(finding, limit=limit)
    return {
        'scan_id': scan.scan_id,
        'finding_id': finding.id,
        'query': ' '.join([finding.title, finding.rule_id, finding.message, *finding.cwe, *finding.owasp]),
        'total_indexed': len(load_index()),
        'results': [chunk.model_dump() for chunk in results],
    }


def document_frequencies(chunks: list[KnowledgeChunk]) -> Counter:
    frequencies: Counter = Counter()
    for chunk in chunks:
        terms = set(tokenize(searchable_text(chunk)))
        frequencies.update(terms)
    return frequencies


def searchable_text(chunk: KnowledgeChunk) -> str:
    return ' '.join([chunk.title, chunk.section or '', chunk.text, ' '.join(chunk.tags), ' '.join(chunk.metadata.values())])


def score_chunk(chunk: KnowledgeChunk, raw_query: str, query_terms: Counter, requested_tags: set[str], doc_freq: Counter, corpus_size: int) -> float:
    title_terms = Counter(tokenize(chunk.title))
    tag_terms = Counter(tokenize(' '.join(chunk.tags)))
    metadata_terms = Counter(tokenize(' '.join(chunk.metadata.values())))
    body_terms = Counter(tokenize(chunk.text))
    score = 0.0
    for term, query_count in query_terms.items():
        idf = math.log((corpus_size + 1) / (doc_freq.get(term, 0) + 1)) + 1
        score += min(query_count, title_terms.get(term, 0)) * 5 * idf
        score += min(query_count, tag_terms.get(term, 0)) * 4 * idf
        score += min(query_count, metadata_terms.get(term, 0)) * 2 * idf
        score += min(query_count, body_terms.get(term, 0)) * idf
    raw_lower = raw_query.lower()
    if raw_lower and raw_lower in searchable_text(chunk).lower():
        score += 6
    if requested_tags:
        chunk_tags = {tag.upper() for tag in chunk.tags}
        score += 8 * len(requested_tags & chunk_tags)
    query_vocab = set(query_terms)
    chunk_vocab = set(tokenize(searchable_text(chunk)))
    if query_vocab:
        score += 3 * (len(query_vocab & chunk_vocab) / len(query_vocab))
    return score


def add_knowledge_document(title: str, text: str) -> KnowledgeChunk:
    KNOWLEDGE_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r'[^a-zA-Z0-9_-]+', '-', title.strip().lower()).strip('-') or 'knowledge'
    path = KNOWLEDGE_DIR / f'{safe}.md'
    path.write_text(f'# {title}\n\n## {title}\n{text.strip()}\n', encoding='utf-8')
    chunks = build_index()
    source = path.name
    matching = [chunk for chunk in chunks if chunk.source == source]
    return matching[0] if matching else chunks[-1]

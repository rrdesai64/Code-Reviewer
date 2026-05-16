from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from .models import KnowledgeChunk

ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE_DIR = ROOT / 'knowledge'
INDEX_PATH = ROOT / 'data' / 'rag_index.json'
TOKEN_RE = re.compile(r'[a-zA-Z][a-zA-Z0-9_+-]{2,}')


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in TOKEN_RE.findall(text)]


def build_index() -> list[KnowledgeChunk]:
    KNOWLEDGE_DIR.mkdir(parents=True, exist_ok=True)
    chunks: list[KnowledgeChunk] = []
    for path in sorted(KNOWLEDGE_DIR.glob('*.md')):
        chunks.extend(chunks_from_markdown(path))
    INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    INDEX_PATH.write_text(json.dumps([chunk.model_dump() for chunk in chunks], indent=2), encoding='utf-8')
    return chunks


def load_index() -> list[KnowledgeChunk]:
    if not INDEX_PATH.exists():
        return build_index()
    return [KnowledgeChunk.model_validate(item) for item in json.loads(INDEX_PATH.read_text(encoding='utf-8'))]


def chunks_from_markdown(path: Path) -> list[KnowledgeChunk]:
    text = path.read_text(encoding='utf-8', errors='ignore')
    sections = re.split(r'(?m)^##\s+', text)
    chunks: list[KnowledgeChunk] = []
    for section in sections:
        section = section.strip()
        if not section or section.startswith('#'):
            continue
        title, _, body = section.partition('\n')
        full_text = body.strip() or title.strip()
        chunk_id = hashlib.sha256(f'{path.name}:{title}:{full_text}'.encode('utf-8')).hexdigest()[:16]
        tags = sorted({token.upper() for token in tokenize(title) if token.lower().startswith(('cwe', 'owasp'))})
        chunks.append(KnowledgeChunk(id=chunk_id, title=title.strip(), source=str(path.name), text=full_text, tags=tags))
    return chunks


def retrieve(query: str, limit: int = 5) -> list[KnowledgeChunk]:
    query_terms = Counter(tokenize(query))
    if not query_terms:
        return []
    scored: list[KnowledgeChunk] = []
    for chunk in load_index():
        chunk_terms = Counter(tokenize(' '.join([chunk.title, chunk.text, ' '.join(chunk.tags)])))
        overlap = sum(min(count, chunk_terms.get(term, 0)) for term, count in query_terms.items())
        tag_bonus = sum(3 for tag in chunk.tags if tag.lower() in query.lower())
        score = overlap + tag_bonus
        if score > 0:
            clone = chunk.model_copy(update={'score': float(score)})
            scored.append(clone)
    return sorted(scored, key=lambda item: item.score, reverse=True)[:limit]


def add_knowledge_document(title: str, text: str) -> KnowledgeChunk:
    KNOWLEDGE_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r'[^a-zA-Z0-9_-]+', '-', title.strip().lower()).strip('-') or 'knowledge'
    path = KNOWLEDGE_DIR / f'{safe}.md'
    path.write_text(f'# {title}\n\n## {title}\n{text.strip()}\n', encoding='utf-8')
    chunks = build_index()
    return chunks[-1]

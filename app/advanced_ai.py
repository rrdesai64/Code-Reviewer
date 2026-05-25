from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import shutil
import subprocess
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .llm import generate, post_json, provider_status
from .models import Finding, LLMRequest, ScanResult
from .paths import data_dir
from .rag import load_index, retrieve, tokenize
from .refactor import build_remediation_plan

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = data_dir() / 'advanced_ai'
EMBEDDING_INDEX_PATH = DATA_DIR / 'embeddings.json'
DEFAULT_EMBEDDING_DIMENSIONS = 384
DEFAULT_AGENT_LIMIT = 5
DEFAULT_TIMEOUT = float(os.getenv('ADVANCED_AI_PROBE_TIMEOUT_SECONDS', '2'))


def advanced_ai_status() -> dict[str, Any]:
    embedding_index = load_embedding_index_payload()
    return {
        'generated_at': now_iso(),
        'features': {
            'embeddings': True,
            'semantic_rag': True,
            'multi_agent_orchestration': True,
            'fine_tune_experiments': True,
            'local_model_runtimes': True,
            'gpu_optimization': True,
        },
        'embedding_providers': embedding_provider_status(),
        'llm_providers': provider_status(),
        'local_runtimes': local_runtime_status(),
        'gpu': gpu_profile(),
        'embedding_index': {
            'exists': bool(embedding_index),
            'path': str(EMBEDDING_INDEX_PATH),
            'chunk_count': int(embedding_index.get('chunk_count', 0)) if embedding_index else 0,
            'provider': embedding_index.get('provider') if embedding_index else None,
            'model': embedding_index.get('model') if embedding_index else None,
            'generated_at': embedding_index.get('generated_at') if embedding_index else None,
        },
    }


def phase_g_report(scan: ScanResult, provider: str = 'offline', model: str | None = None, embedding_provider: str = 'local') -> dict[str, Any]:
    agent_review = run_multi_agent_review(scan, provider=provider, model=model, limit=DEFAULT_AGENT_LIMIT)
    fine_tune = fine_tune_experiment_plan(scan)
    return {
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'generated_at': now_iso(),
        'status': advanced_ai_status(),
        'multi_agent_review': agent_review,
        'fine_tune_experiment': fine_tune,
        'gpu_optimization': gpu_optimization_plan(),
        'embedding_index_recommendation': embedding_index_recommendation(embedding_provider),
    }


def embedding_provider_status() -> dict[str, Any]:
    return {
        'local': {
            'available': True,
            'model': f'hashing-{DEFAULT_EMBEDDING_DIMENSIONS}',
            'privacy': 'offline',
            'description': 'Deterministic hashing embeddings for local semantic search.',
        },
        'ollama': {
            'available': runtime_available(os.getenv('OLLAMA_BASE_URL', 'http://127.0.0.1:11434'), '/api/tags'),
            'base_url': os.getenv('OLLAMA_BASE_URL', 'http://127.0.0.1:11434'),
            'model': os.getenv('OLLAMA_EMBEDDING_MODEL', 'nomic-embed-text'),
        },
        'openai': {
            'available': bool(os.getenv('OPENAI_API_KEY')),
            'model': os.getenv('OPENAI_EMBEDDING_MODEL', 'text-embedding-3-small'),
            'privacy': 'external-api',
        },
        'openai_compatible': {
            'available': bool(os.getenv('EMBEDDING_BASE_URL') or os.getenv('LLM_BASE_URL')),
            'base_url': os.getenv('EMBEDDING_BASE_URL') or os.getenv('LLM_BASE_URL'),
            'model': os.getenv('EMBEDDING_MODEL', os.getenv('LLM_EMBEDDING_MODEL', 'local-embedding-model')),
        },
    }


def build_embedding_index(provider: str = 'local', model: str | None = None, force: bool = False) -> dict[str, Any]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    chunks = load_index()
    existing = load_embedding_index_payload()
    resolved_model = resolve_embedding_model(provider, model)
    if existing and not force and existing.get('provider') == provider and existing.get('model') == resolved_model and existing.get('chunk_count') == len(chunks):
        return existing
    items = []
    provider_used = provider
    fallback_reason = None
    started = time.time()
    for chunk in chunks:
        text = ' '.join([chunk.title, chunk.section or '', ' '.join(chunk.tags), chunk.text])
        try:
            vector = embed_text(text, provider=provider, model=resolved_model)
        except Exception as exc:
            provider_used = 'local'
            fallback_reason = str(exc)
            vector = embed_text(text, provider='local', model=None)
        items.append(
            {
                'chunk_id': chunk.id,
                'title': chunk.title,
                'source': chunk.source,
                'section': chunk.section,
                'chunk_index': chunk.chunk_index,
                'tags': chunk.tags,
                'vector': vector,
                'norm': vector_norm(vector),
            }
        )
    payload = {
        'schema_version': 1,
        'generated_at': now_iso(),
        'provider': provider_used,
        'requested_provider': provider,
        'model': resolve_embedding_model(provider_used, resolved_model if provider_used == provider else None),
        'chunk_count': len(chunks),
        'dimensions': len(items[0]['vector']) if items else 0,
        'duration_seconds': round(time.time() - started, 3),
        'fallback_reason': fallback_reason,
        'items': items,
    }
    EMBEDDING_INDEX_PATH.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    return payload


def semantic_search(query: str, limit: int = 5, provider: str = 'local', model: str | None = None, hybrid: bool = True) -> dict[str, Any]:
    index = build_embedding_index(provider=provider, model=model)
    query_vector = embed_text(query, provider=index.get('provider', 'local'), model=index.get('model'))
    lexical = {chunk.id: chunk.score for chunk in retrieve(query, limit=max(limit * 3, 10))} if hybrid else {}
    vector_norm_value = vector_norm(query_vector)
    chunks_by_id = {chunk.id: chunk for chunk in load_index()}
    results = []
    for item in index.get('items', []):
        semantic_score = cosine_similarity(query_vector, vector_norm_value, item.get('vector', []), item.get('norm', 0))
        lexical_score = lexical.get(item['chunk_id'], 0.0)
        score = semantic_score + (0.08 * lexical_score if hybrid else 0.0)
        if score <= 0:
            continue
        chunk = chunks_by_id.get(item['chunk_id'])
        results.append(
            {
                'chunk_id': item['chunk_id'],
                'title': item.get('title'),
                'source': item.get('source'),
                'section': item.get('section'),
                'tags': item.get('tags', []),
                'semantic_score': round(semantic_score, 4),
                'lexical_score': round(lexical_score, 4),
                'score': round(score, 4),
                'text': chunk.text if chunk else '',
            }
        )
    return {
        'query': query,
        'generated_at': now_iso(),
        'provider': index.get('provider'),
        'model': index.get('model'),
        'hybrid': hybrid,
        'total_indexed': index.get('chunk_count', 0),
        'results': sorted(results, key=lambda item: (-item['score'], item['source'] or '', item['chunk_id']))[:max(limit, 0)],
    }


def embed_text(text: str, provider: str = 'local', model: str | None = None) -> list[float]:
    provider = provider.replace('-', '_').lower().strip()
    if provider == 'ollama':
        return ollama_embedding(text, model=model)
    if provider == 'openai':
        return openai_embedding(text, model=model)
    if provider in {'openai_compatible', 'compatible'}:
        return compatible_embedding(text, model=model)
    return local_hash_embedding(text)


def local_hash_embedding(text: str, dimensions: int = DEFAULT_EMBEDDING_DIMENSIONS) -> list[float]:
    vector = [0.0] * dimensions
    terms = Counter(tokenize(text))
    if not terms:
        return vector
    for term, count in terms.items():
        digest = hashlib.sha256(term.encode('utf-8')).digest()
        idx = int.from_bytes(digest[:4], 'big') % dimensions
        sign = 1.0 if digest[4] % 2 == 0 else -1.0
        vector[idx] += sign * (1.0 + math.log(count))
    norm = vector_norm(vector)
    return [round(value / norm, 6) if norm else 0.0 for value in vector]


def ollama_embedding(text: str, model: str | None = None) -> list[float]:
    base_url = os.getenv('OLLAMA_BASE_URL', 'http://127.0.0.1:11434').rstrip('/')
    resolved_model = model or os.getenv('OLLAMA_EMBEDDING_MODEL', 'nomic-embed-text')
    payload = {'model': resolved_model, 'input': text[:12000]}
    try:
        data = post_json(f'{base_url}/api/embed', payload, {})
        embeddings = data.get('embeddings') or []
        if embeddings and isinstance(embeddings[0], list):
            return normalize_vector([float(value) for value in embeddings[0]])
    except Exception:
        payload = {'model': resolved_model, 'prompt': text[:12000]}
        data = post_json(f'{base_url}/api/embeddings', payload, {})
        embedding = data.get('embedding') or []
        if embedding:
            return normalize_vector([float(value) for value in embedding])
    raise RuntimeError('Ollama embedding response did not include a vector')


def openai_embedding(text: str, model: str | None = None) -> list[float]:
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        raise RuntimeError('OPENAI_API_KEY is not configured')
    resolved_model = model or os.getenv('OPENAI_EMBEDDING_MODEL', 'text-embedding-3-small')
    data = post_json(
        'https://api.openai.com/v1/embeddings',
        {'model': resolved_model, 'input': text[:12000]},
        {'Authorization': f'Bearer {api_key}'},
    )
    embedding = data.get('data', [{}])[0].get('embedding') or []
    if not embedding:
        raise RuntimeError('OpenAI embedding response did not include a vector')
    return normalize_vector([float(value) for value in embedding])


def compatible_embedding(text: str, model: str | None = None) -> list[float]:
    base_url = (os.getenv('EMBEDDING_BASE_URL') or os.getenv('LLM_BASE_URL') or '').rstrip('/')
    if not base_url:
        raise RuntimeError('EMBEDDING_BASE_URL or LLM_BASE_URL is not configured')
    resolved_model = model or os.getenv('EMBEDDING_MODEL', os.getenv('LLM_EMBEDDING_MODEL', 'local-embedding-model'))
    api_key = os.getenv('EMBEDDING_API_KEY') or os.getenv('LLM_API_KEY', '')
    headers = {'Authorization': f'Bearer {api_key}'} if api_key else {}
    data = post_json(f'{base_url}/embeddings', {'model': resolved_model, 'input': text[:12000]}, headers)
    embedding = data.get('data', [{}])[0].get('embedding') or []
    if not embedding:
        raise RuntimeError('OpenAI-compatible embedding response did not include a vector')
    return normalize_vector([float(value) for value in embedding])


def run_multi_agent_review(scan: ScanResult, finding_id: str | None = None, provider: str = 'offline', model: str | None = None, limit: int = DEFAULT_AGENT_LIMIT) -> dict[str, Any]:
    candidates = scan.findings
    if finding_id:
        candidates = [finding for finding in scan.findings if finding.id == finding_id]
    else:
        candidates = [finding for finding in scan.findings if finding.decision not in {'false_positive', 'risk_accepted'}]
        candidates = sorted(candidates, key=lambda item: (-item.risk.score, item.location.path, item.location.line))[:max(limit, 1)]
    if finding_id and not candidates:
        raise ValueError('finding not found')
    agent_outputs = []
    for finding in candidates:
        context = finding_agent_context(scan, finding)
        agent_outputs.append(
            {
                'finding_id': finding.id,
                'title': finding.title,
                'priority': finding.risk.priority,
                'risk_score': finding.risk.score,
                'agents': [
                    risk_triage_agent(scan, finding, context),
                    exploitability_agent(scan, finding, context),
                    remediation_agent(scan, finding, context),
                    compliance_agent(scan, finding, context),
                ],
            }
        )
    synthesis = synthesize_agent_review(scan, agent_outputs, provider=provider, model=model)
    return {
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'generated_at': now_iso(),
        'provider': provider,
        'model': model or provider_status().get(provider, {}).get('model') or 'deterministic-template',
        'finding_count': len(agent_outputs),
        'agents': ['risk-triage', 'exploitability', 'secure-remediation', 'compliance'],
        'findings': agent_outputs,
        'synthesis': synthesis,
    }


def finding_agent_context(scan: ScanResult, finding: Finding) -> dict[str, Any]:
    semantic = semantic_search(' '.join([finding.title, finding.rule_id, finding.message, *finding.cwe, *finding.owasp]), limit=3, provider='local')
    return {
        'scan_id': scan.scan_id,
        'target_path': scan.target_path,
        'semantic_context': semantic['results'],
        'risk_factors': [factor.model_dump() for factor in finding.risk.factors],
        'is_new': finding.fingerprint in set(scan.new_findings),
    }


def risk_triage_agent(scan: ScanResult, finding: Finding, context: dict[str, Any]) -> dict[str, Any]:
    blockers = []
    if finding.risk.priority == 'P0':
        blockers.append('P0 release-blocking risk')
    if finding.severity in {'CRITICAL', 'HIGH'}:
        blockers.append(f'{finding.severity.lower()} scanner severity')
    if context.get('is_new'):
        blockers.append('new since baseline')
    return agent_output(
        'risk-triage',
        'block' if blockers else 'review',
        blockers or ['no release-blocking triage factor detected'],
        ['Triage with security owner before merge.' if blockers else 'Track through normal remediation workflow.'],
    )


def exploitability_agent(scan: ScanResult, finding: Finding, context: dict[str, Any]) -> dict[str, Any]:
    text = ' '.join([finding.rule_id, finding.title, finding.message, finding.explanation]).lower()
    signals = []
    for token in ['user input', 'request', 'shell', 'subprocess', 'sql', 'xss', 'ssrf', 'deserialization', 'secret', 'token', 'password', 'dependency']:
        if token in text:
            signals.append(token)
    status = 'likely-exploitable' if any(token in signals for token in ['user input', 'request', 'shell', 'sql', 'xss', 'ssrf', 'deserialization', 'secret', 'dependency']) else 'needs-human-analysis'
    return agent_output(
        'exploitability',
        status,
        signals or ['no direct exploitability keyword found'],
        ['Validate source-to-sink reachability and external exposure.', 'Check whether the affected path is reachable in production.'],
    )


def remediation_agent(scan: ScanResult, finding: Finding, context: dict[str, Any]) -> dict[str, Any]:
    plan = build_remediation_plan(scan, limit=25)
    step = next((item for item in plan.steps if item.finding_id == finding.id), None)
    actions = [finding.fix.summary, *finding.fix.guidance]
    if step:
        actions.append(f'Use fix proposal endpoint: {step.proposal_endpoint}')
        actions.extend(step.validation_commands)
    return agent_output('secure-remediation', 'proposal-ready' if step else 'manual-review', actions, ['Keep generated fixes as review-only diffs.', 'Run validation commands before accepting.'])


def compliance_agent(scan: ScanResult, finding: Finding, context: dict[str, Any]) -> dict[str, Any]:
    tags = [*finding.cwe, *finding.owasp]
    evidence = []
    if tags:
        evidence.append('Maps to ' + ', '.join(tags))
    if finding.source == 'pip-audit':
        evidence.append('Impacts dependency/SBOM compliance')
    if finding.risk.priority in {'P0', 'P1'}:
        evidence.append('Requires audit evidence before closure')
    return agent_output(
        'compliance',
        'evidence-required' if evidence else 'record-only',
        evidence or ['no explicit compliance mapping beyond scan record'],
        ['Record decision rationale and validation evidence.', 'Keep scan ID and finding ID in audit trail.'],
    )


def agent_output(agent: str, status: str, findings: list[str], recommendations: list[str]) -> dict[str, Any]:
    return {'agent': agent, 'status': status, 'findings': dedupe(findings), 'recommendations': dedupe(recommendations)}


def synthesize_agent_review(scan: ScanResult, agent_outputs: list[dict[str, Any]], provider: str, model: str | None) -> dict[str, Any]:
    blockers = []
    review_required = []
    for item in agent_outputs:
        for agent in item['agents']:
            if agent['status'] in {'block', 'likely-exploitable', 'evidence-required'}:
                blockers.append(f"{item['finding_id']}:{agent['agent']}:{agent['status']}")
            elif agent['status'] != 'record-only':
                review_required.append(f"{item['finding_id']}:{agent['agent']}:{agent['status']}")
    prompt = (
        'Summarize this multi-agent secure code review in 6 bullets or fewer. '
        'Call out blockers, validation evidence, and next actions.\n'
        f'Project: {scan.project_name}\n'
        f'Findings reviewed: {len(agent_outputs)}\n'
        f'Blockers: {blockers[:12]}\n'
        f'Review required: {review_required[:12]}\n'
    )
    response = generate(LLMRequest(prompt=prompt, provider=provider, model=model, system='You are a conservative secure code review lead.'))
    return {
        'status': 'blocked' if blockers else 'review_required' if review_required else 'pass',
        'blockers': blockers,
        'review_required': review_required,
        'summary': response.text[:1800],
        'used_fallback': response.used_fallback,
        'error': response.error,
    }


def fine_tune_experiment_plan(scan: ScanResult, limit: int = 50) -> dict[str, Any]:
    examples = fine_tune_examples(scan, limit=limit)
    return {
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'generated_at': now_iso(),
        'objective': 'Experiment with specialized secure-code-review response style, risk triage, and remediation plan formatting.',
        'status': 'experiment-ready' if len(examples) >= 5 else 'needs-more-reviewed-examples',
        'safety_position': 'Dataset export only; this app does not automatically submit training jobs or deploy fine-tuned models.',
        'recommended_base_models': [
            {'provider': 'openai', 'task': 'review synthesis and remediation notes', 'env_model_key': 'OPENAI_FINE_TUNE_BASE_MODEL'},
            {'provider': 'openai_compatible', 'task': 'local LoRA/adapter experiments', 'env_model_key': 'FINE_TUNE_BASE_MODEL'},
        ],
        'dataset': {
            'format': 'chat-jsonl',
            'example_count': len(examples),
            'quality_gates': [
                'Remove secrets, customer identifiers, and proprietary code before external training.',
                'Prefer accepted-fix and true-positive findings for supervised examples.',
                'Keep false-positive examples in a separate evaluation set.',
                'Require human review of model outputs before using them in remediation proposals.',
            ],
            'examples_preview': examples[:5],
        },
        'evaluation': {
            'holdout_strategy': 'Keep at least 20 percent of reviewed findings as a holdout set.',
            'metrics': ['valid security reasoning', 'false-positive restraint', 'patch safety', 'validation specificity', 'policy compliance'],
            'regression_prompts': fine_tune_eval_prompts(scan),
        },
        'deployment_controls': [
            'Deploy as an optional provider alias, not as the default reviewer.',
            'Compare against offline, base cloud, and local model outputs before enabling for CI.',
            'Log model name, dataset version, and prompt version in audit evidence.',
        ],
    }


def fine_tune_dataset_jsonl(scan: ScanResult, limit: int = 100) -> str:
    return '\n'.join(json.dumps(example, ensure_ascii=True) for example in fine_tune_examples(scan, limit=limit)) + '\n'


def fine_tune_examples(scan: ScanResult, limit: int = 100) -> list[dict[str, Any]]:
    candidates = sorted(scan.findings, key=lambda item: (-item.risk.score, item.location.path, item.location.line))[:limit]
    examples = []
    for finding in candidates:
        user = (
            f'Review finding {finding.id} in project {scan.project_name}.\n'
            f'Rule: {finding.rule_id}\nSeverity: {finding.severity}\nPriority: {finding.risk.priority}\n'
            f'Location: {finding.location.path}:{finding.location.line}\nMessage: {finding.message}\n'
        )
        assistant = (
            f'Risk: {finding.risk.priority} score {finding.risk.score}. '
            f'{finding.fix.summary} '
            f'Validation: rerun the secure scan and targeted tests for {finding.location.path}. '
            'Keep remediation human-reviewed.'
        )
        examples.append(
            {
                'messages': [
                    {'role': 'system', 'content': 'You are a secure code review assistant. Be precise, conservative, and validation-oriented.'},
                    {'role': 'user', 'content': user},
                    {'role': 'assistant', 'content': assistant},
                ],
                'metadata': {
                    'scan_id': scan.scan_id,
                    'finding_id': finding.id,
                    'source': finding.source,
                    'rule_id': finding.rule_id,
                    'severity': finding.severity,
                    'priority': finding.risk.priority,
                    'decision': finding.decision,
                },
            }
        )
    return examples


def fine_tune_eval_prompts(scan: ScanResult) -> list[dict[str, str]]:
    top = sorted(scan.findings, key=lambda item: (-item.risk.score, item.location.path, item.location.line))[:5]
    return [
        {
            'id': finding.id,
            'prompt': f'Classify exploitability, remediation safety, and validation steps for {finding.rule_id} at {finding.location.path}:{finding.location.line}.',
            'expected_focus': ', '.join([finding.risk.priority, finding.severity, finding.source]),
        }
        for finding in top
    ]


def local_runtime_status() -> dict[str, Any]:
    runtimes = {
        'ollama': runtime_probe(os.getenv('OLLAMA_BASE_URL', 'http://127.0.0.1:11434'), '/api/tags'),
        'openai_compatible': runtime_probe(os.getenv('LLM_BASE_URL', ''), '/models'),
        'embedding_compatible': runtime_probe(os.getenv('EMBEDDING_BASE_URL', ''), '/models'),
        'lm_studio': runtime_probe(os.getenv('LM_STUDIO_BASE_URL', 'http://127.0.0.1:1234/v1'), '/models'),
        'vllm': runtime_probe(os.getenv('VLLM_BASE_URL', ''), '/models'),
        'llama_cpp': runtime_probe(os.getenv('LLAMA_CPP_BASE_URL', ''), '/health'),
    }
    return runtimes


def runtime_probe(base_url: str, path: str) -> dict[str, Any]:
    if not base_url:
        return {'configured': False, 'available': False}
    url = base_url.rstrip('/') + path
    try:
        req = urllib.request.Request(url, method='GET')
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as response:
            body = response.read(8000).decode('utf-8', errors='ignore')
        model_count = 0
        try:
            payload = json.loads(body) if body else {}
            models = payload.get('models') or payload.get('data') or []
            model_count = len(models) if isinstance(models, list) else 0
        except json.JSONDecodeError:
            pass
        return {'configured': True, 'available': True, 'url': url, 'status_code': response.status, 'model_count': model_count}
    except Exception as exc:
        return {'configured': True, 'available': False, 'url': url, 'error': str(exc)}


def runtime_available(base_url: str, path: str) -> bool:
    return runtime_probe(base_url, path).get('available', False)


def gpu_profile() -> dict[str, Any]:
    profile = {
        'generated_at': now_iso(),
        'platform': platform.platform(),
        'python': platform.python_version(),
        'nvidia_smi': shutil.which('nvidia-smi') or '',
        'gpus': [],
        'cuda_visible_devices': os.getenv('CUDA_VISIBLE_DEVICES', ''),
        'torch': torch_status(),
    }
    if profile['nvidia_smi']:
        try:
            completed = subprocess.run(
                [profile['nvidia_smi'], '--query-gpu=name,memory.total,memory.free,driver_version,compute_cap', '--format=csv,noheader,nounits'],
                text=True,
                capture_output=True,
                timeout=8,
            )
            if completed.returncode == 0:
                for line in completed.stdout.splitlines():
                    parts = [part.strip() for part in line.split(',')]
                    if len(parts) >= 5:
                        profile['gpus'].append(
                            {
                                'name': parts[0],
                                'memory_total_mb': safe_int(parts[1]),
                                'memory_free_mb': safe_int(parts[2]),
                                'driver_version': parts[3],
                                'compute_capability': parts[4],
                            }
                        )
            else:
                profile['nvidia_smi_error'] = completed.stderr.strip() or str(completed.returncode)
        except Exception as exc:
            profile['nvidia_smi_error'] = str(exc)
    profile['recommendations'] = gpu_optimization_plan(profile)
    return profile


def torch_status() -> dict[str, Any]:
    try:
        import torch
    except Exception as exc:
        return {'installed': False, 'error': str(exc)}
    try:
        cuda_available = bool(torch.cuda.is_available())
        devices = []
        if cuda_available:
            for idx in range(torch.cuda.device_count()):
                props = torch.cuda.get_device_properties(idx)
                devices.append({'index': idx, 'name': props.name, 'memory_total_mb': int(props.total_memory / (1024 * 1024))})
        return {'installed': True, 'version': torch.__version__, 'cuda_available': cuda_available, 'devices': devices}
    except Exception as exc:
        return {'installed': True, 'error': str(exc)}


def gpu_optimization_plan(profile: dict[str, Any] | None = None) -> dict[str, Any]:
    profile = profile or {'gpus': []}
    gpus = profile.get('gpus', []) or []
    max_vram = max((gpu.get('memory_total_mb', 0) for gpu in gpus), default=0)
    if max_vram >= 48000:
        model_class = '34B-70B quantized or 13B-34B higher precision'
        batch = 'embedding batch 64-128; context 16k+ if runtime supports it'
    elif max_vram >= 24000:
        model_class = '13B-34B quantized, 7B-13B higher precision'
        batch = 'embedding batch 32-64; context 8k-16k'
    elif max_vram >= 12000:
        model_class = '7B-13B quantized'
        batch = 'embedding batch 16-32; context 4k-8k'
    elif max_vram >= 8000:
        model_class = '7B quantized, prefer Q4/Q5'
        batch = 'embedding batch 8-16; context 4k'
    else:
        model_class = 'CPU or small local models; prefer cloud/openai-compatible endpoint for heavy review'
        batch = 'embedding batch 1-8; use hashing embeddings by default'
    return {
        'recommended_model_class': model_class,
        'recommended_batching': batch,
        'runtime_settings': {
            'OLLAMA_NUM_GPU': 'auto or number of GPU layers that fit VRAM',
            'CUDA_VISIBLE_DEVICES': 'set to a specific GPU id when sharing the machine',
            'LLM_CONTEXT_WINDOW': 'keep below available VRAM; increase only after latency tests',
            'EMBEDDING_BATCH_SIZE': batch.split(';')[0].replace('embedding batch ', ''),
        },
        'guardrails': [
            'Keep deterministic local embeddings available as a fallback.',
            'Do not send sensitive repositories to cloud embedding or fine-tuning providers without approval.',
            'Benchmark latency on representative scans before enabling agent review in CI.',
            'Keep generated fixes human-reviewed even when a GPU model is available.',
        ],
    }


def embedding_index_recommendation(provider: str) -> dict[str, Any]:
    status = embedding_provider_status().get(provider.replace('-', '_'), {})
    return {
        'provider': provider,
        'available': status.get('available', False),
        'recommended_action': 'build index with this provider' if status.get('available') else 'use local hashing embeddings until provider is configured',
        'command': f'.\\.venv\\Scripts\\python.exe -m app.cli --path . --embedding-provider {provider} --embedding-index-out embeddings.json',
    }


def resolve_embedding_model(provider: str, model: str | None) -> str:
    provider = provider.replace('-', '_').lower().strip()
    if model:
        return model
    if provider == 'ollama':
        return os.getenv('OLLAMA_EMBEDDING_MODEL', 'nomic-embed-text')
    if provider == 'openai':
        return os.getenv('OPENAI_EMBEDDING_MODEL', 'text-embedding-3-small')
    if provider in {'openai_compatible', 'compatible'}:
        return os.getenv('EMBEDDING_MODEL', os.getenv('LLM_EMBEDDING_MODEL', 'local-embedding-model'))
    return f'hashing-{DEFAULT_EMBEDDING_DIMENSIONS}'


def load_embedding_index_payload() -> dict[str, Any]:
    if not EMBEDDING_INDEX_PATH.exists():
        return {}
    try:
        return json.loads(EMBEDDING_INDEX_PATH.read_text(encoding='utf-8'))
    except Exception:
        return {}


def normalize_vector(vector: list[float]) -> list[float]:
    norm = vector_norm(vector)
    return [round(value / norm, 6) if norm else 0.0 for value in vector]


def vector_norm(vector: list[float]) -> float:
    return math.sqrt(sum(float(value) * float(value) for value in vector))


def cosine_similarity(left: list[float], left_norm: float, right: list[float], right_norm: float) -> float:
    if not left_norm or not right_norm or not left or not right:
        return 0.0
    size = min(len(left), len(right))
    return sum(float(left[idx]) * float(right[idx]) for idx in range(size)) / (left_norm * right_norm)


def safe_int(value: str) -> int:
    try:
        return int(float(value))
    except Exception:
        return 0


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def dedupe(items: list[str]) -> list[str]:
    seen = set()
    result = []
    for item in items:
        clean = str(item).strip()
        if clean and clean not in seen:
            seen.add(clean)
            result.append(clean)
    return result

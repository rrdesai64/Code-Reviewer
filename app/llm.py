from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .models import LLMRequest, LLMResponse

DEFAULT_TIMEOUT = 45


def provider_status() -> dict:
    return {
        'offline': {'available': True, 'description': 'Deterministic local template fallback'},
        'openai': {'available': bool(os.getenv('OPENAI_API_KEY')), 'model': os.getenv('OPENAI_MODEL', 'gpt-5.2')},
        'ollama': {'available': True, 'base_url': os.getenv('OLLAMA_BASE_URL', 'http://127.0.0.1:11434'), 'model': os.getenv('OLLAMA_MODEL', 'codellama')},
        'openai_compatible': {'available': bool(os.getenv('LLM_BASE_URL')), 'base_url': os.getenv('LLM_BASE_URL'), 'model': os.getenv('LLM_MODEL', 'local-model')},
    }


def generate(request: LLMRequest) -> LLMResponse:
    provider = request.provider.lower().strip()
    if provider == 'openai':
        return call_openai(request)
    if provider == 'ollama':
        return call_ollama(request)
    if provider in {'openai-compatible', 'openai_compatible', 'compatible'}:
        return call_openai_compatible(request)
    return offline_response(request)


def call_openai(request: LLMRequest) -> LLMResponse:
    api_key = os.getenv('OPENAI_API_KEY')
    model = request.model or os.getenv('OPENAI_MODEL', 'gpt-5.2')
    if not api_key:
        response = offline_response(request)
        response.used_fallback = True
        response.error = 'OPENAI_API_KEY is not configured'
        return response
    payload = {
        'model': model,
        'instructions': request.system or 'You are a secure code review assistant. Be concise, specific, and conservative.',
        'input': build_prompt(request),
    }
    try:
        data = post_json('https://api.openai.com/v1/responses', payload, {'Authorization': f'Bearer {api_key}'})
        text = data.get('output_text') or extract_response_text(data) or ''
        return LLMResponse(provider='openai', model=model, text=text.strip())
    except Exception as exc:
        response = offline_response(request)
        response.used_fallback = True
        response.error = str(exc)
        return response


def call_ollama(request: LLMRequest) -> LLMResponse:
    base_url = os.getenv('OLLAMA_BASE_URL', 'http://127.0.0.1:11434').rstrip('/')
    model = request.model or os.getenv('OLLAMA_MODEL', 'codellama')
    payload = {'model': model, 'prompt': build_prompt(request), 'stream': False, 'system': request.system or ''}
    try:
        data = post_json(f'{base_url}/api/generate', payload, {})
        return LLMResponse(provider='ollama', model=model, text=(data.get('response') or '').strip())
    except Exception as exc:
        response = offline_response(request)
        response.used_fallback = True
        response.error = str(exc)
        return response


def call_openai_compatible(request: LLMRequest) -> LLMResponse:
    base_url = os.getenv('LLM_BASE_URL', '').rstrip('/')
    api_key = os.getenv('LLM_API_KEY', '')
    model = request.model or os.getenv('LLM_MODEL', 'local-model')
    if not base_url:
        response = offline_response(request)
        response.used_fallback = True
        response.error = 'LLM_BASE_URL is not configured'
        return response
    payload = {'model': model, 'messages': [{'role': 'system', 'content': request.system or ''}, {'role': 'user', 'content': build_prompt(request)}]}
    headers = {'Authorization': f'Bearer {api_key}'} if api_key else {}
    try:
        data = post_json(f'{base_url}/chat/completions', payload, headers)
        text = data.get('choices', [{}])[0].get('message', {}).get('content', '')
        return LLMResponse(provider='openai_compatible', model=model, text=text.strip())
    except Exception as exc:
        response = offline_response(request)
        response.used_fallback = True
        response.error = str(exc)
        return response


def offline_response(request: LLMRequest) -> LLMResponse:
    context = '\n'.join(f'- {chunk.title}: {chunk.text[:220]}' for chunk in request.context[:4])
    text = 'Offline review guidance:\n'
    if context:
        text += context + '\n'
    text += 'Recommended action: verify the finding, apply the smallest safe change, add or update a regression test, and keep human approval in the loop.'
    return LLMResponse(provider='offline', model='deterministic-template', text=text)


def build_prompt(request: LLMRequest) -> str:
    context = '\n\n'.join(f'[{chunk.title}]\n{chunk.text}' for chunk in request.context)
    if context:
        return f'Knowledge context:\n{context}\n\nTask:\n{request.prompt}'
    return request.prompt


def post_json(url: str, payload: dict, headers: dict) -> dict:
    body = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=body, method='POST')
    req.add_header('Content-Type', 'application/json')
    for key, value in headers.items():
        req.add_header(key, value)
    with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as response:
        return json.loads(response.read().decode('utf-8'))


def extract_response_text(data: dict) -> str:
    parts: list[str] = []
    for item in data.get('output', []):
        for content in item.get('content', []) if isinstance(item, dict) else []:
            if content.get('type') == 'output_text' and content.get('text'):
                parts.append(content['text'])
    return '\n'.join(parts)

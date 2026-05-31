from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Protocol

from .models import ExecutionEvidence
from .scope import normalize_path


class ExecutionEvidenceProvider(Protocol):
    def evidence(self, file: str, line: int) -> ExecutionEvidence: ...


class NullExecutionEvidenceProvider:
    def evidence(self, file: str, line: int) -> ExecutionEvidence:
        del file, line
        return ExecutionEvidence()


class CoverageExecutionEvidenceProvider:
    def __init__(self, files: dict[str, dict[str, Any]]) -> None:
        self.files = files

    @classmethod
    def from_paths(cls, paths: list[Path] | None) -> ExecutionEvidenceProvider:
        provider = cls({})
        for path in paths or []:
            provider.add_path(Path(path))
        return provider if provider.files else NullExecutionEvidenceProvider()

    def add_path(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            return
        text = path.read_text(encoding='utf-8', errors='ignore')
        lower_name = path.name.lower()
        if lower_name.endswith('.xml') or text.lstrip().startswith('<?xml'):
            self.merge(parse_cobertura_xml(text))
        elif lower_name.endswith('.json'):
            self.merge(parse_istanbul_json(text))
        else:
            self.merge(parse_lcov_or_go_coverprofile(text))

    def merge(self, files: dict[str, dict[str, Any]]) -> None:
        for file, lines in files.items():
            record = self.files.setdefault(file, {'known': set(), 'covered': set(), 'hits': {}})
            record['known'].update(lines.get('known', set()))
            record['covered'].update(lines.get('covered', set()))
            record['hits'].update(lines.get('hits', {}))

    def evidence(self, file: str, line: int) -> ExecutionEvidence:
        normalized = normalize_coverage_path(file)
        record = self.files.get(normalized) or self.files.get(Path(normalized).name)
        if record is None:
            record = next((value for key, value in self.files.items() if normalized.endswith('/' + key) or key.endswith('/' + normalized)), None)
        if record is None:
            return ExecutionEvidence()
        line_number = max(1, int(line or 1))
        if line_number not in record.get('known', set()):
            return ExecutionEvidence()
        hits = record.get('hits', {}).get(line_number)
        if line_number in record.get('covered', set()):
            return ExecutionEvidence(state='executed', source='test-coverage', hits=hits if hits is not None else 1)
        return ExecutionEvidence(state='not_executed', source='test-coverage', hits=hits if hits is not None else 0)


def coverage_provider_from_paths(paths: list[Path] | None) -> ExecutionEvidenceProvider:
    return CoverageExecutionEvidenceProvider.from_paths(paths)


def parse_cobertura_xml(text: str) -> dict[str, dict[str, Any]]:
    files: dict[str, dict[str, Any]] = {}
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return files
    for class_node in root.findall('.//class'):
        filename = normalize_coverage_path(class_node.attrib.get('filename', ''))
        if not filename:
            continue
        record = files.setdefault(filename, {'known': set(), 'covered': set(), 'hits': {}})
        files.setdefault(Path(filename).name, {'known': set(), 'covered': set(), 'hits': {}})
        for line_node in class_node.findall('.//line'):
            try:
                number = int(line_node.attrib.get('number', '0'))
                hits = int(float(line_node.attrib.get('hits', '0')))
            except ValueError:
                continue
            if number <= 0:
                continue
            add_line(record, number, hits)
            add_line(files[Path(filename).name], number, hits)
    return files


def parse_istanbul_json(text: str) -> dict[str, dict[str, Any]]:
    files: dict[str, dict[str, Any]] = {}
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return files
    for raw_path, item in (payload or {}).items():
        if not isinstance(item, dict):
            continue
        filename = normalize_coverage_path(raw_path)
        record = files.setdefault(filename, {'known': set(), 'covered': set(), 'hits': {}})
        files.setdefault(Path(filename).name, {'known': set(), 'covered': set(), 'hits': {}})
        statements = item.get('statementMap') or {}
        counts = item.get('s') or {}
        for statement_id, location in statements.items():
            start = (location or {}).get('start') or {}
            end = (location or {}).get('end') or start
            try:
                start_line = int(start.get('line') or 0)
                end_line = int(end.get('line') or start_line)
                hits = int(counts.get(statement_id, 0))
            except (TypeError, ValueError):
                continue
            for number in range(max(1, start_line), max(start_line, end_line) + 1):
                add_line(record, number, hits)
                add_line(files[Path(filename).name], number, hits)
    return files


def parse_lcov_or_go_coverprofile(text: str) -> dict[str, dict[str, Any]]:
    if any(line.startswith('SF:') for line in text.splitlines()):
        return parse_lcov(text)
    return parse_go_coverprofile(text)


def parse_lcov(text: str) -> dict[str, dict[str, Any]]:
    files: dict[str, dict[str, Any]] = {}
    current = ''
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith('SF:'):
            current = normalize_coverage_path(line[3:])
            files.setdefault(current, {'known': set(), 'covered': set(), 'hits': {}})
            files.setdefault(Path(current).name, {'known': set(), 'covered': set(), 'hits': {}})
        elif current and line.startswith('DA:'):
            try:
                number_text, hits_text = line[3:].split(',', 1)
                number = int(number_text)
                hits = int(float(hits_text.split(',', 1)[0]))
            except ValueError:
                continue
            add_line(files[current], number, hits)
            add_line(files[Path(current).name], number, hits)
    return files


def parse_go_coverprofile(text: str) -> dict[str, dict[str, Any]]:
    files: dict[str, dict[str, Any]] = {}
    pattern = re.compile(r'^(?P<path>[^:]+):(?P<start>\d+)\.\d+,(?P<end>\d+)\.\d+\s+\d+\s+(?P<count>\d+)$')
    for raw_line in text.splitlines():
        match = pattern.match(raw_line.strip())
        if not match:
            continue
        filename = normalize_coverage_path(match.group('path'))
        record = files.setdefault(filename, {'known': set(), 'covered': set(), 'hits': {}})
        files.setdefault(Path(filename).name, {'known': set(), 'covered': set(), 'hits': {}})
        hits = int(match.group('count'))
        for number in range(int(match.group('start')), int(match.group('end')) + 1):
            add_line(record, number, hits)
            add_line(files[Path(filename).name], number, hits)
    return files


def add_line(record: dict[str, Any], number: int, hits: int) -> None:
    record['known'].add(number)
    record.setdefault('hits', {})[number] = max(hits, record.setdefault('hits', {}).get(number, 0))
    if hits > 0:
        record['covered'].add(number)


def normalize_coverage_path(path: str) -> str:
    normalized = normalize_path(str(path or '').replace('\\', '/'))
    parts = [part for part in normalized.split('/') if part not in {'', '.'}]
    if len(parts) > 1 and re.match(r'^[A-Za-z]:$', parts[0]):
        parts = parts[1:]
    return '/'.join(parts)

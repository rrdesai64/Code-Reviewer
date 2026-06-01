from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import ScanResult

SCHEMA_VERSION = 'runtime-build-plan-v1'
MAX_SCAN_DEPTH = 3
MAX_READ_BYTES = 512_000
EXCLUDED_DIRS = {
    '.git',
    '.hg',
    '.svn',
    '.venv',
    'venv',
    'env',
    'node_modules',
    'dist',
    'build',
    'target',
    'bin',
    'obj',
    '__pycache__',
    '.pytest_cache',
    '.mypy_cache',
}
MANIFEST_NAMES = {
    'package.json',
    'pyproject.toml',
    'requirements.txt',
    'requirements-dev.txt',
    'manage.py',
    'go.mod',
    'pom.xml',
    'build.gradle',
    'build.gradle.kts',
    'settings.gradle',
    'settings.gradle.kts',
    'composer.json',
    'Gemfile',
}
CS_PROJECT_RE = re.compile(r'.+\.(csproj|fsproj|vbproj)$', re.IGNORECASE)
SLN_RE = re.compile(r'.+\.sln$', re.IGNORECASE)


@dataclass
class RuntimeCandidate:
    runtime: str
    framework: str
    language: str
    root: Path
    detected_from: list[str]
    package_manager: str
    build_commands: list[str]
    start_command: str
    expected_port: int
    health_paths: list[str] = field(default_factory=lambda: ['/health', '/healthz', '/api/health', '/'])
    required_env: list[str] = field(default_factory=list)
    optional_env: dict[str, str] = field(default_factory=dict)
    test_commands: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    score: int = 0


def build_runtime_plan(scan: ScanResult) -> dict[str, Any]:
    target = Path(scan.target_path).resolve()
    generated_at = datetime.now(timezone.utc).isoformat()
    if not target.exists():
        return empty_plan(
            scan,
            generated_at,
            status='blocked',
            blockers=['scan target path does not exist; runtime planning could not inspect manifests'],
        )

    manifests = discover_manifests(target)
    candidates = detect_runtime_candidates(target, manifests)
    profiles = [profile_record(candidate, target) for candidate in sorted(candidates, key=candidate_sort_key)]
    primary = profiles[0] if profiles else None
    status = plan_status(profiles)
    blockers = plan_blockers(profiles)
    runtimes = sorted({profile['runtime'] for profile in profiles})
    frameworks = sorted({profile['framework'] for profile in profiles})
    return {
        'schema_version': SCHEMA_VERSION,
        'phase': '3A',
        'generated_at': generated_at,
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'target': {
            'target_path_hash': stable_id(str(target)),
            'target_name_hint': sanitize_name(target.name or scan.project_name),
            'manifest_count': len(manifests),
        },
        'policy': {
            'planning_only': True,
            'runs_commands': False,
            'starts_services': False,
            'raw_code_included': False,
            'sandbox_required_for_execution': True,
            'next_phase': '3B disposable/container build-run worker',
        },
        'summary': {
            'status': status,
            'profile_count': len(profiles),
            'primary_profile_id': primary['profile_id'] if primary else '',
            'confidence': primary['confidence'] if primary else 'none',
            'runtime_families': runtimes,
            'frameworks': frameworks,
            'blocker_count': len(blockers),
        },
        'primary_plan': primary_plan_record(primary),
        'profiles': profiles,
        'blockers': blockers,
        'warnings': sorted_unique(warning for profile in profiles for warning in profile.get('warnings', [])),
    }


def empty_plan(scan: ScanResult, generated_at: str, status: str, blockers: list[str]) -> dict[str, Any]:
    return {
        'schema_version': SCHEMA_VERSION,
        'phase': '3A',
        'generated_at': generated_at,
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'target': {'target_path_hash': stable_id(scan.target_path), 'target_name_hint': sanitize_name(scan.project_name), 'manifest_count': 0},
        'policy': {
            'planning_only': True,
            'runs_commands': False,
            'starts_services': False,
            'raw_code_included': False,
            'sandbox_required_for_execution': True,
            'next_phase': '3B disposable/container build-run worker',
        },
        'summary': {
            'status': status,
            'profile_count': 0,
            'primary_profile_id': '',
            'confidence': 'none',
            'runtime_families': [],
            'frameworks': [],
            'blocker_count': len(blockers),
        },
        'primary_plan': {},
        'profiles': [],
        'blockers': blockers,
        'warnings': [],
    }


def discover_manifests(target: Path) -> list[Path]:
    discovered: list[Path] = []
    for path in limited_files(target):
        if path.name in MANIFEST_NAMES or CS_PROJECT_RE.match(path.name) or SLN_RE.match(path.name):
            discovered.append(path)
    return sorted(discovered, key=lambda item: relative_path(target, item))


def limited_files(target: Path) -> list[Path]:
    files: list[Path] = []
    stack = [(target, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_SCAN_DEPTH:
            continue
        try:
            children = sorted(current.iterdir(), key=lambda item: item.name.lower())
        except OSError:
            continue
        for child in children:
            if child.is_dir():
                if child.name in EXCLUDED_DIRS:
                    continue
                stack.append((child, depth + 1))
            elif child.is_file():
                files.append(child)
    return files


def detect_runtime_candidates(target: Path, manifests: list[Path]) -> list[RuntimeCandidate]:
    candidates: list[RuntimeCandidate] = []
    seen: set[tuple[str, str, str]] = set()
    for root in sorted({path.parent for path in manifests}, key=lambda item: relative_path(target, item)):
        root_manifests = [path for path in manifests if path.parent == root]
        for candidate in [
            detect_node(target, root, root_manifests),
            detect_python(target, root, root_manifests),
            detect_go(target, root, root_manifests),
            detect_java_kotlin(target, root, root_manifests),
            detect_dotnet(target, root, root_manifests),
            detect_php(target, root, root_manifests),
            detect_ruby(target, root, root_manifests),
        ]:
            if not candidate:
                continue
            key = (relative_path(target, candidate.root), candidate.runtime, candidate.framework)
            if key not in seen:
                seen.add(key)
                candidates.append(candidate)
    if not candidates and any((target / name).exists() for name in ('Dockerfile', 'docker-compose.yml', 'compose.yml')):
        candidates.append(RuntimeCandidate(
            runtime='container',
            framework='docker',
            language='mixed',
            root=target,
            detected_from=[name for name in ('Dockerfile', 'docker-compose.yml', 'compose.yml') if (target / name).exists()],
            package_manager='docker',
            build_commands=[],
            start_command='',
            expected_port=0,
            blockers=['containerized app detected but Phase 3A does not infer or execute container runtime commands'],
            warnings=['Use Phase 3B sandbox/container worker to build and run containerized apps.'],
            score=30,
        ))
    return candidates


def detect_node(target: Path, root: Path, manifests: list[Path]) -> RuntimeCandidate | None:
    package_json = root / 'package.json'
    if package_json not in manifests:
        return None
    data = read_json(package_json)
    scripts = {str(key): str(value) for key, value in (data.get('scripts') or {}).items()} if isinstance(data, dict) else {}
    deps = package_names(data)
    framework = node_framework(deps, scripts)
    port = {'nextjs': 3000, 'vite-react': 5173, 'react': 3000, 'express': 3000}.get(framework, 3000)
    package_manager = node_package_manager(root)
    install = node_install_command(package_manager)
    build_commands = [install]
    if 'build' in scripts:
        build_commands.append(f'{package_manager} run build')
    start_command = node_start_command(package_manager, scripts, framework, port)
    blockers = [] if start_command else ['package.json does not expose a supported start/dev/preview script']
    return RuntimeCandidate(
        runtime='node',
        framework=framework,
        language='javascript/typescript',
        root=root,
        detected_from=[relative_path(target, package_json)],
        package_manager=package_manager,
        build_commands=build_commands,
        start_command=start_command,
        expected_port=port,
        optional_env={'PORT': str(port)},
        test_commands=[f'{package_manager} test'] if 'test' in scripts and 'no test specified' not in scripts.get('test', '').lower() else [],
        blockers=blockers,
        score=90 if framework != 'node' and not blockers else 70,
    )


def detect_python(target: Path, root: Path, manifests: list[Path]) -> RuntimeCandidate | None:
    marker_names = {path.name for path in manifests}
    if not marker_names.intersection({'pyproject.toml', 'requirements.txt', 'requirements-dev.txt', 'manage.py'}):
        return None
    deps = python_dependencies(root)
    if (root / 'manage.py').exists() or 'django' in deps:
        framework = 'django'
        start = 'python manage.py runserver 0.0.0.0:${PORT:-8000}'
        port = 8000
        score = 95 if (root / 'manage.py').exists() else 75
    elif 'fastapi' in deps:
        framework = 'fastapi'
        module = python_asgi_module(root)
        start = f'python -m uvicorn {module}:app --host 0.0.0.0 --port ${{PORT:-8000}}' if module else ''
        port = 8000
        score = 90 if module else 65
    elif 'flask' in deps:
        framework = 'flask'
        app_module = python_flask_app(root)
        start = f'python -m flask --app {app_module} run --host 0.0.0.0 --port ${{PORT:-5000}}' if app_module else ''
        port = 5000
        score = 85 if app_module else 60
    else:
        framework = 'python'
        start = ''
        port = 8000
        score = 40
    build_commands = python_build_commands(root)
    blockers = [] if start else [f'Python {framework} project detected but no safe start command could be inferred']
    tests = ['python -m pytest -q'] if (root / 'tests').exists() or any((root / name).exists() for name in ('pytest.ini', 'tox.ini')) else []
    return RuntimeCandidate(
        runtime='python',
        framework=framework,
        language='python',
        root=root,
        detected_from=[relative_path(target, path) for path in manifests if path.parent == root and path.name in {'pyproject.toml', 'requirements.txt', 'requirements-dev.txt', 'manage.py'}],
        package_manager='pip',
        build_commands=build_commands,
        start_command=start,
        expected_port=port,
        optional_env={'PORT': str(port)},
        test_commands=tests,
        blockers=blockers,
        score=score,
    )


def detect_go(target: Path, root: Path, manifests: list[Path]) -> RuntimeCandidate | None:
    go_mod = root / 'go.mod'
    if go_mod not in manifests:
        return None
    entry = go_entrypoint(root)
    start = f'go run {entry}' if entry else ''
    return RuntimeCandidate(
        runtime='go',
        framework='go-http',
        language='go',
        root=root,
        detected_from=[relative_path(target, go_mod)],
        package_manager='go',
        build_commands=['go mod download', 'go build ./...'],
        start_command=start,
        expected_port=8080,
        optional_env={'PORT': '8080'},
        test_commands=['go test ./...'],
        blockers=[] if start else ['go.mod detected but no main package entrypoint found within Phase 3A scan depth'],
        score=85 if start else 55,
    )


def detect_java_kotlin(target: Path, root: Path, manifests: list[Path]) -> RuntimeCandidate | None:
    names = {path.name for path in manifests}
    if not names.intersection({'pom.xml', 'build.gradle', 'build.gradle.kts', 'settings.gradle', 'settings.gradle.kts'}):
        return None
    is_maven = (root / 'pom.xml').exists()
    text = read_text(root / 'pom.xml') if is_maven else '\n'.join(read_text(root / name) for name in ('build.gradle', 'build.gradle.kts') if (root / name).exists())
    spring = 'spring-boot' in text.lower() or 'org.springframework.boot' in text.lower()
    if is_maven:
        build = ['mvn test package']
        start = 'mvn spring-boot:run' if spring else ''
        package_manager = 'maven'
    else:
        runner = 'gradlew.bat' if (root / 'gradlew.bat').exists() else './gradlew' if (root / 'gradlew').exists() else 'gradle'
        build = [f'{runner} build']
        start = f'{runner} bootRun' if spring else ''
        package_manager = 'gradle'
    return RuntimeCandidate(
        runtime='jvm',
        framework='spring-boot' if spring else 'java-kotlin',
        language='java/kotlin',
        root=root,
        detected_from=[relative_path(target, path) for path in manifests if path.parent == root and path.name in {'pom.xml', 'build.gradle', 'build.gradle.kts', 'settings.gradle', 'settings.gradle.kts'}],
        package_manager=package_manager,
        build_commands=build,
        start_command=start,
        expected_port=8080,
        optional_env={'PORT': '8080', 'SERVER_PORT': '8080'},
        test_commands=['mvn test'] if is_maven else [build[0].replace(' build', ' test')],
        blockers=[] if start else ['JVM project detected but no Spring Boot start command could be inferred'],
        score=85 if start else 50,
    )


def detect_dotnet(target: Path, root: Path, manifests: list[Path]) -> RuntimeCandidate | None:
    project_files = [path for path in manifests if path.parent == root and (CS_PROJECT_RE.match(path.name) or SLN_RE.match(path.name))]
    if not project_files:
        return None
    csproj = next((path for path in project_files if CS_PROJECT_RE.match(path.name)), project_files[0])
    start = f'dotnet run --project {quote_rel(root, csproj)}' if CS_PROJECT_RE.match(csproj.name) else 'dotnet run'
    return RuntimeCandidate(
        runtime='dotnet',
        framework='aspnetcore',
        language='csharp/dotnet',
        root=root,
        detected_from=[relative_path(target, path) for path in project_files],
        package_manager='dotnet',
        build_commands=['dotnet restore', 'dotnet build'],
        start_command=start,
        expected_port=5000,
        optional_env={'ASPNETCORE_URLS': 'http://0.0.0.0:5000', 'PORT': '5000'},
        test_commands=['dotnet test'],
        blockers=[],
        score=80,
    )


def detect_php(target: Path, root: Path, manifests: list[Path]) -> RuntimeCandidate | None:
    composer = root / 'composer.json'
    if composer not in manifests:
        return None
    data = read_json(composer)
    deps = package_names(data)
    laravel = 'laravel/framework' in deps or (root / 'artisan').exists()
    start = 'php artisan serve --host=0.0.0.0 --port=${PORT:-8000}' if laravel else ''
    return RuntimeCandidate(
        runtime='php',
        framework='laravel' if laravel else 'php',
        language='php',
        root=root,
        detected_from=[relative_path(target, composer)],
        package_manager='composer',
        build_commands=['composer install --no-interaction --prefer-dist'],
        start_command=start,
        expected_port=8000,
        optional_env={'PORT': '8000'},
        test_commands=['composer test'] if 'test' in (data.get('scripts') or {}) else [],
        blockers=[] if start else ['composer.json detected but no Laravel/artisan start command could be inferred'],
        score=80 if start else 45,
    )


def detect_ruby(target: Path, root: Path, manifests: list[Path]) -> RuntimeCandidate | None:
    gemfile = root / 'Gemfile'
    if gemfile not in manifests:
        return None
    text = read_text(gemfile).lower()
    rails = "gem 'rails'" in text or 'gem "rails"' in text or (root / 'bin' / 'rails').exists()
    start = 'bundle exec rails server -b 0.0.0.0 -p ${PORT:-3000}' if rails else ''
    return RuntimeCandidate(
        runtime='ruby',
        framework='rails' if rails else 'ruby',
        language='ruby',
        root=root,
        detected_from=[relative_path(target, gemfile)],
        package_manager='bundler',
        build_commands=['bundle install'],
        start_command=start,
        expected_port=3000,
        optional_env={'PORT': '3000', 'RAILS_ENV': 'development'},
        test_commands=['bundle exec rails test'] if rails else [],
        blockers=[] if start else ['Gemfile detected but no Rails start command could be inferred'],
        score=80 if start else 45,
    )


def profile_record(candidate: RuntimeCandidate, target: Path) -> dict[str, Any]:
    rel_root = relative_path(target, candidate.root)
    health = health_urls(candidate.expected_port, candidate.health_paths)
    return {
        'profile_id': profile_id(candidate, target),
        'runtime': candidate.runtime,
        'framework': candidate.framework,
        'language': candidate.language,
        'root': rel_root,
        'root_hash': stable_id(str(candidate.root)),
        'confidence': confidence_label(candidate.score, candidate.blockers),
        'confidence_score': candidate.score,
        'detected_from': sorted_unique(candidate.detected_from),
        'package_manager': candidate.package_manager,
        'build': {
            'commands': candidate.build_commands,
            'safe_to_run_on_host': False,
            'requires_sandbox': True,
        },
        'start': {
            'command': candidate.start_command,
            'working_directory': rel_root,
            'expected_port': candidate.expected_port,
            'health_url_candidates': health,
            'safe_to_run_on_host': False,
            'requires_sandbox': True,
        },
        'tests': {
            'commands': candidate.test_commands,
            'safe_to_run_on_host': False,
            'requires_sandbox': True,
        },
        'required_env': candidate.required_env,
        'optional_env': candidate.optional_env,
        'blockers': candidate.blockers,
        'warnings': candidate.warnings,
    }


def primary_plan_record(primary: dict[str, Any] | None) -> dict[str, Any]:
    if not primary:
        return {}
    return {
        'profile_id': primary['profile_id'],
        'runtime': primary['runtime'],
        'framework': primary['framework'],
        'confidence': primary['confidence'],
        'build_commands': primary['build']['commands'],
        'start_command': primary['start']['command'],
        'working_directory': primary['start']['working_directory'],
        'expected_port': primary['start']['expected_port'],
        'health_url_candidates': primary['start']['health_url_candidates'],
        'required_env': primary['required_env'],
        'optional_env': primary['optional_env'],
        'blockers': primary['blockers'],
    }


def plan_status(profiles: list[dict[str, Any]]) -> str:
    if not profiles:
        return 'blocked'
    if any(not profile['blockers'] and profile['start']['command'] for profile in profiles):
        return 'ready'
    return 'partial'


def plan_blockers(profiles: list[dict[str, Any]]) -> list[str]:
    if not profiles:
        return ['No supported runtime manifest was detected within the Phase 3A scan depth.']
    blockers = [
        f"{profile['runtime']}:{profile['framework']}:{profile['root']}: {blocker}"
        for profile in profiles
        for blocker in profile.get('blockers', [])
    ]
    return sorted_unique(blockers)


def candidate_sort_key(candidate: RuntimeCandidate) -> tuple[int, int, str]:
    return (
        0 if not candidate.blockers and candidate.start_command else 1,
        -candidate.score,
        str(candidate.root),
    )


def node_framework(deps: set[str], scripts: dict[str, str]) -> str:
    joined_scripts = ' '.join(scripts.values()).lower()
    if 'next' in deps or 'next ' in joined_scripts:
        return 'nextjs'
    if 'vite' in deps or 'vite' in joined_scripts:
        return 'vite-react' if {'react', '@vitejs/plugin-react'}.intersection(deps) else 'vite'
    if 'react-scripts' in deps or 'react' in deps:
        return 'react'
    if 'express' in deps:
        return 'express'
    return 'node'


def node_package_manager(root: Path) -> str:
    if (root / 'pnpm-lock.yaml').exists():
        return 'pnpm'
    if (root / 'yarn.lock').exists():
        return 'yarn'
    return 'npm'


def node_install_command(package_manager: str) -> str:
    return {'npm': 'npm install', 'yarn': 'yarn install --frozen-lockfile', 'pnpm': 'pnpm install --frozen-lockfile'}[package_manager]


def node_start_command(package_manager: str, scripts: dict[str, str], framework: str, port: int) -> str:
    if 'start' in scripts:
        return f'{package_manager} start'
    if framework == 'nextjs':
        return f'{package_manager} exec next start -p ${{PORT:-{port}}}'
    if framework in {'vite-react', 'vite'} and 'preview' in scripts:
        return f'{package_manager} run preview -- --host 0.0.0.0 --port ${{PORT:-{port}}}'
    if 'dev' in scripts:
        return f'{package_manager} run dev'
    return ''


def python_dependencies(root: Path) -> set[str]:
    deps: set[str] = set()
    for name in ('requirements.txt', 'requirements-dev.txt'):
        deps.update(requirements_dependencies(root / name))
    deps.update(pyproject_dependencies(root / 'pyproject.toml'))
    return deps


def requirements_dependencies(path: Path) -> set[str]:
    deps: set[str] = set()
    for line in read_text(path).splitlines():
        text = line.strip()
        if not text or text.startswith('#') or text.startswith('-'):
            continue
        match = re.match(r'([A-Za-z0-9_.-]+)', text)
        if match:
            deps.add(match.group(1).lower().replace('_', '-'))
    return deps


def pyproject_dependencies(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        data = tomllib.loads(read_text(path))
    except Exception:
        return set()
    deps: set[str] = set()
    project = data.get('project') or {}
    for item in project.get('dependencies') or []:
        match = re.match(r'([A-Za-z0-9_.-]+)', str(item))
        if match:
            deps.add(match.group(1).lower().replace('_', '-'))
    optional = project.get('optional-dependencies') or {}
    for values in optional.values():
        for item in values or []:
            match = re.match(r'([A-Za-z0-9_.-]+)', str(item))
            if match:
                deps.add(match.group(1).lower().replace('_', '-'))
    poetry = ((data.get('tool') or {}).get('poetry') or {}).get('dependencies') or {}
    deps.update(str(name).lower().replace('_', '-') for name in poetry if str(name).lower() != 'python')
    return deps


def python_build_commands(root: Path) -> list[str]:
    if (root / 'requirements.txt').exists():
        return ['python -m pip install -r requirements.txt']
    if (root / 'pyproject.toml').exists():
        return ['python -m pip install .']
    return []


def python_asgi_module(root: Path) -> str:
    candidates = [
        ('main.py', 'main'),
        ('app.py', 'app'),
        ('app/main.py', 'app.main'),
        ('src/main.py', 'src.main'),
    ]
    for rel, module in candidates:
        text = read_text(root / rel)
        if 'FastAPI(' in text or 'fastapi import FastAPI' in text:
            return module
    return 'main' if (root / 'main.py').exists() else ''


def python_flask_app(root: Path) -> str:
    for rel, module in [('app.py', 'app'), ('wsgi.py', 'wsgi'), ('main.py', 'main')]:
        text = read_text(root / rel)
        if 'Flask(' in text or 'flask import Flask' in text or (root / rel).exists():
            return module
    return ''


def go_entrypoint(root: Path) -> str:
    if (root / 'main.go').exists():
        return '.'
    cmd = root / 'cmd'
    if cmd.exists():
        for path in sorted(cmd.glob('*/main.go')):
            return './' + relative_path(root, path.parent)
    for path in sorted(root.glob('*/main.go')):
        return './' + relative_path(root, path.parent)
    return ''


def package_names(data: Any) -> set[str]:
    if not isinstance(data, dict):
        return set()
    names: set[str] = set()
    for section in ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies', 'require'):
        values = data.get(section) or {}
        if isinstance(values, dict):
            names.update(str(name).lower() for name in values)
    return names


def health_urls(port: int, paths: list[str]) -> list[str]:
    if not port:
        return []
    return [f'http://127.0.0.1:{port}{path if path.startswith("/") else "/" + path}' for path in sorted_unique(paths)]


def confidence_label(score: int, blockers: list[str]) -> str:
    adjusted = min(score, 65) if blockers else score
    if adjusted >= 80:
        return 'high'
    if adjusted >= 50:
        return 'medium'
    if adjusted > 0:
        return 'low'
    return 'none'


def profile_id(candidate: RuntimeCandidate, target: Path) -> str:
    payload = '|'.join([relative_path(target, candidate.root), candidate.runtime, candidate.framework, ','.join(candidate.detected_from)])
    return f'rt-{stable_id(payload)[:16]}'


def quote_rel(root: Path, path: Path) -> str:
    rel = relative_path(root, path)
    return f'"{rel}"' if ' ' in rel else rel


def relative_path(root: Path, path: Path) -> str:
    try:
        rel = path.resolve().relative_to(root.resolve())
        text = str(rel).replace('\\', '/')
        return text or '.'
    except Exception:
        return str(path).replace('\\', '/')


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(read_text(path))
    except Exception:
        return {}


def read_text(path: Path) -> str:
    if not path.exists() or not path.is_file():
        return ''
    try:
        if path.stat().st_size > MAX_READ_BYTES:
            return ''
        return path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return ''


def stable_id(value: str) -> str:
    return hashlib.sha256(str(value or '').encode('utf-8')).hexdigest()[:24]


def sanitize_name(value: str) -> str:
    return re.sub(r'[^A-Za-z0-9_.-]+', '_', str(value or '').strip()).strip('._-')[:120]


def sorted_unique(values: list[str] | Any) -> list[str]:
    return sorted({str(value) for value in values if str(value)})

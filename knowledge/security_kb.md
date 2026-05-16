# Secure Code Review Knowledge Base

## CWE-78 OS Command Injection
OS command injection happens when untrusted input reaches shell execution. Prefer argument arrays over shell strings, avoid `shell=True`, validate user-selectable commands with allowlists, and treat process output as untrusted.

## CWE-94 Dynamic Code Execution
Dynamic execution APIs such as `eval`, `exec`, and JavaScript `Function` convert data into executable code. Replace them with parsers, schema validation, dispatch tables, or purpose-built expression evaluators.

## CWE-79 Cross-Site Scripting
XSS occurs when untrusted data is rendered as executable HTML or script. Avoid `innerHTML` for user content, use framework escaping defaults, sanitize trusted rich text, and enforce content security policy.

## CWE-798 Hardcoded Credentials
Hardcoded secrets can leak through source control, build artifacts, logs, and screenshots. Rotate exposed credentials, load secrets from environment variables or a vault, and add secret scanning to CI.

## OWASP A05 Security Misconfiguration
Misconfiguration includes debug mode, verbose errors, unsafe defaults, permissive CORS, and missing headers. Production settings should fail closed and be validated in CI or deployment checks.

## OWASP A06 Vulnerable and Outdated Components
Known-vulnerable dependencies are a common compromise path. Pin direct dependencies, commit lockfiles for applications, audit dependencies in CI, and upgrade to fixed versions when advisories are published.

## Secure Refactoring Guardrails
Generated code changes should be reviewed by a human, applied as a diff, and verified with tests. Security patches should prefer narrow changes, preserve behavior, and include regression checks for the fixed vulnerability.

## Enterprise Audit Guidance
Enterprise security programs need traceable decisions. Store finding decisions, baseline comparisons, scan history, actor/action audit events, and compliance summaries mapped to OWASP, CWE, and internal policy controls.

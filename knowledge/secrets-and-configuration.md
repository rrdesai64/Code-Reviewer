# Secrets And Configuration Guidance

## CWE-798 Hardcoded Credential Remediation
Remove hardcoded passwords, tokens, API keys, private keys, and connection strings from source code. Rotate exposed secrets because Git history and build logs may already contain them. Load runtime secrets from environment variables, cloud secret managers, or enterprise vaults. Add pre-commit and CI secret scanning so future leaks are caught before merge.

## CWE-295 TLS Certificate Validation
Do not disable certificate verification in production HTTP clients. Pin only when there is a clear operational model for rotation. Make test-only insecure TLS settings impossible to enable by default, and log configuration state during startup without printing secrets.

## OWASP A05 Security Misconfiguration
Production configuration should fail closed. Disable debug mode, remove default credentials, restrict CORS, set secure cookies, enable security headers, and separate development settings from deployable settings. Add deployment checks that fail when unsafe flags are enabled.

## Environment Variable Safety
Environment variables are appropriate for local development and simple deployments, but production systems should avoid printing them, committing `.env` files, or sharing them through screenshots. Use `.env.example` for non-secret names and documentation only.

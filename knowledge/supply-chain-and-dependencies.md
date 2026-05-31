# Supply Chain And Dependency Guidance

## OWASP A06 Vulnerable And Outdated Components
Known-vulnerable packages should be upgraded to the nearest fixed version that preserves compatibility. Pin direct dependencies, commit lockfiles for applications, and run dependency audits in CI. For transitive vulnerabilities, prefer upgrading the parent package before forcing overrides.

## Dependency Pinning
Loose version ranges can make builds non-reproducible and can unexpectedly introduce vulnerable versions. Pin application dependencies exactly where practical, review lockfile diffs, and keep a scheduled update process so pinned versions do not become stale.

## SBOM Readiness
SPDX and CycloneDX outputs help enterprise review, procurement, and incident response. Generate SBOMs from the same dependency manifests used for scanning, store them as build artifacts, and link vulnerability findings to package identifiers when possible.

## CI Security Gates
Use severity, risk score, and baseline status together. New P0 or P1 findings should require security review. Existing accepted risks should carry an expiry or review date. Audit logs should record who accepted a risk and why.

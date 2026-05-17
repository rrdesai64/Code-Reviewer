# Identity And Enterprise Controls

## OIDC Production Enforcement
OIDC login should use the provider discovery URL, a confidential client secret, HTTPS redirect URIs, secure cookies, and a strong server-side session secret. Validate issuer, audience, expiry, and nonce/state protections. Map IdP groups to local roles rather than hardcoding users in the application.

## SAML Production Enforcement
SAML login should validate signed assertions, IdP entity ID, ACS URL, NameID format, and certificate rotation procedures. Require HTTPS for metadata, ACS, and logout endpoints. Treat unsigned or unexpected assertions as authentication failures.

## RBAC For Secure Review
Use least privilege: developers can run scans and propose fixes, security reviewers can manage baselines and decisions, auditors can read reports, and admins can manage enterprise settings. Sensitive actions should be audit logged.

## Audit Evidence
Enterprise review needs traceable scan IDs, actor names, timestamps, policy outcomes, baseline changes, risk decisions, and exported reports. Retain enough context to explain why a finding was fixed, accepted, or marked false positive.

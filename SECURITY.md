# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

Only the latest minor release of each artifact in this monorepo (`ai.authplane.sdk:authplane-sdk`, `authplane-mcp`, `authplane-spring`) receives security patches.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, use [GitHub Private Vulnerability Reporting](https://github.com/AuthPlane/java-sdk/security/advisories/new) to submit your report. This ensures:

- Your report is confidential and only visible to maintainers
- We can coordinate a fix before public disclosure
- You receive credit for responsible disclosure

### What to Include

- Which artifact is affected (`authplane-sdk`, `authplane-mcp`, `authplane-spring`) and installed version
- Description of the vulnerability
- Steps to reproduce (or proof of concept)
- Impact assessment (what an attacker could do)
- Relevant environment details (JDK version, framework version, `authserver` version if applicable)

### Response Timeline

- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 5 business days
- **Fix timeline:** depends on severity (critical: < 7 days, high: < 14 days)

### What We Consider In-Scope

Vulnerabilities in the SDK or its adapters that affect correctness of authentication or authorization decisions, including:

- JWT verification bypass (signature, issuer, audience, expiry, `nbf`, algorithm confusion)
- DPoP proof verification flaws (binding, replay, key mismatch, `htm`/`htu` mishandling)
- PKCE / state / nonce handling flaws in the OAuth client
- Token replay or confusion between access, refresh, and exchange tokens
- JWKS handling flaws (fetch, caching, key rotation) where the SDK owns the logic
- Leakage of tokens, client secrets, or key material via logs, error messages, or caches
- Dependency-chain vulnerabilities that become exploitable through normal SDK usage

### Out of Scope

- User integration mistakes (misconfigured issuer URL, missing HTTPS, reused client secrets)
- Issues in the `authserver` authorization server itself — report those at <https://github.com/AuthPlane/authserver/security/advisories/new>
- Issues in `nimbus-jose-jwt`, Spring Security, or other third-party dependencies — report upstream, then notify us
- Denial of service unless trivially triggerable (< 10 requests)
- Social engineering

## Contact

For non-vulnerability security questions, open a [discussion](https://github.com/AuthPlane/java-sdk/discussions).

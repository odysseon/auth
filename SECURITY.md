# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest  | ✅        |
| Older   | ❌        |

Only the latest published version receives security fixes.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report privately via GitHub's
[Security Advisories](../../security/advisories/new) feature, or by
emailing the maintainer directly (address in the npm package metadata).

Include:
- A description of the vulnerability
- Steps to reproduce or a proof-of-concept
- The potential impact
- Any suggested mitigations

You will receive a response within **72 hours**. We aim to release a patch
within **14 days** of confirmation for critical issues.

## Scope

This module handles **authentication** (identity verification and token
issuance). Vulnerabilities in the following areas are in scope:

- JWT signing or verification bypass
- Refresh token reuse or replay
- Password hash weaknesses in default adapters
- Dependency supply-chain issues affecting the above

Authorisation logic is out of scope — this module does not implement it.

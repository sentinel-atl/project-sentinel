# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email **security@sentineltrust.dev** with:

1. Description of the vulnerability
2. Steps to reproduce
3. Impact assessment
4. Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for resolution.

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Security Practices

- All cryptographic operations use audited libraries (`@noble/ed25519`, `@noble/hashes`)
- Ed25519 signatures for all identity and credential operations
- AES-256-GCM with scrypt key derivation for encrypted key storage
- SHA-256 hash chains for tamper-evident audit logs
- Rate limiting and circuit breakers to prevent abuse
- Content safety pipeline to detect prompt injection and PII leaks
- No secrets are logged or included in error messages

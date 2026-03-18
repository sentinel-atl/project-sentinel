## Overview
Sentinel Trust Certificates (STCs) are Verifiable Credentials encoding the results of an MCP server trust scan.

## STC Format
```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1", "https://sentinel.trust/v1"],
  "type": ["VerifiableCredential", "SentinelTrustCertificate"],
  "issuer": "did:sentinel:scanner-<id>",
  "issuanceDate": "2026-03-18T...",
  "expirationDate": "2026-04-18T...",
  "credentialSubject": {
    "id": "mcp://npm/@modelcontextprotocol/server-filesystem@1.2.0",
    "type": "MCPServer",
    "trustScore": 87,
    "scan": {
      "version": "1.0.0",
      "timestamp": "2026-03-18T...",
      "dependencies": { "total": 12, "vulnerabilities": 0 },
      "permissions": ["filesystem:read", "filesystem:write"],
      "codeAnalysis": { "obfuscation": false, "exfiltration": false },
      "tools": ["read_file", "write_file", "list_directory"],
      "publisher": { "verified": true, "name": "Anthropic" }
    }
  },
  "proof": { "type": "Ed25519Signature2020", "...": "..." }
}
```

## Features
- Issue STCs using existing `@sentinel-atl/attestation`
- Verify STCs using existing `@sentinel-atl/core`
- Revoke STCs using existing `@sentinel-atl/revocation`
- Cache STCs locally (offline mode via `@sentinel-atl/offline`)
- Custom MCP URI scheme: `mcp://npm/package@version`

## Acceptance Criteria
- [ ] STC schema definition
- [ ] Issue STC from scan results
- [ ] Verify STC signature
- [ ] Revoke STC
- [ ] STC expiration handling
- [ ] MCP URI scheme
- [ ] Serialize/deserialize
- [ ] Integration with scanner

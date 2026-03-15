# @sentinel-atl/mcp-plugin

Sentinel middleware for MCP servers — identity verification at the tool-call boundary.

## Features

- **10-step verification** — identity → revocation → attestation → auth → credentials → scope → reputation → intent → offline → safety
- **Drop-in guard** — wrap your MCP tool handler with `SentinelGuard`
- **Content safety** — pre-dispatch prompt injection/PII scanning
- **Offline mode** — cached trust decisions when connectivity is degraded
- **Full audit trail** — every decision logged with hash-chain integrity

## Install

```bash
npm install @sentinel-atl/mcp-plugin
```

## Quick Start

```ts
import { SentinelGuard } from '@sentinel-atl/mcp-plugin';

const guard = new SentinelGuard({
  auditLog,
  serverDid: 'did:key:z6MkServer...',
  requiredCredentials: ['AgentAuthorizationCredential'],
  revocationManager,
  reputationEngine,
  safetyPipeline,
});

// In your MCP tool handler:
const result = await guard.verifyToolCall({
  toolName: 'read_file',
  callerDid: 'did:key:z6MkCaller...',
  credentials: [vc],
  intent,
});

if (result.allowed) {
  // proceed with tool execution
} else {
  console.log(result.reason); // e.g. "credential_revoked"
}
```

## Verification Pipeline

1. **Identity** — caller DID is valid
2. **Revocation** — DID not revoked
3. **Attestation** — code hash matches (if configured)
4. **Auth** — valid credentials presented
5. **Credentials** — required VC types present and valid
6. **Scope** — requested tool within VC scope
7. **Reputation** — not quarantined, meets threshold
8. **Intent** — matches declared constraints
9. **Offline** — degraded-mode policy evaluation
10. **Safety** — content safety pre-dispatch scan

## License

MIT

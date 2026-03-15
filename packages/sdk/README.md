# @sentinel-atl/sdk

Developer-friendly SDK for the Agent Trust Layer — add trust to your agent in ~5 lines.

## Features

- **Single entry point** — `createTrustedAgent()` wires up identity, audit, reputation, revocation, offline, and safety
- **Offline mode** — `goOffline()` / `goOnline()` with cached trust decisions and CRDT merge
- **Content safety** — `checkSafety()` with pluggable classifiers (regex, keyword, custom)
- **Re-exports** all core types for convenience

## Install

```bash
npm install @sentinel-atl/sdk
```

## Quick Start

```ts
import { createTrustedAgent } from '@sentinel-atl/sdk';

const agent = await createTrustedAgent({
  label: 'my-agent',
  enableSafety: true,
});

// Issue a credential
const vc = await agent.issueVC({
  subjectDid: 'did:key:z6Mk...',
  scope: ['files:read'],
  maxDelegationDepth: 0,
});

// Verify trust
const result = await agent.verifyVC(vc);

// Check content safety
const safety = await agent.checkSafety('user input text');

// Go offline with cached decisions
agent.goOffline();
const decision = agent.evaluateTrust(vc);
agent.goOnline();
```

## API

| Method | Description |
|---|---|
| `createTrustedAgent(config)` | Factory — returns a `TrustedAgent` with all subsystems |
| `agent.issueVC(options)` | Issue a Verifiable Credential |
| `agent.verifyVC(vc)` | Verify a VC |
| `agent.vouch(targetDid, score, evidence)` | Submit a reputation vouch |
| `agent.getReputation(did)` | Get reputation score |
| `agent.checkSafety(content)` | Run content safety pipeline |
| `agent.goOffline()` / `goOnline()` | Toggle offline mode |
| `agent.evaluateTrust(vc)` | Evaluate trust using cached data |
| `agent.mergeReputationState(remote)` | CRDT merge remote reputation |
| `agent.revokeVC(vcId, reason)` | Revoke a credential |
| `agent.backup()` / `recover(shares)` | Shamir key backup/recovery |

## License

MIT

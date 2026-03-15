# @sentinel-atl/core

DID identity, Verifiable Credentials, crypto primitives, and KeyProvider interface for the Agent Trust Layer.

## Features

- **DID generation** — `did:key` method with Ed25519 (multicodec `0xed01`, base58btc)
- **Verifiable Credentials** — W3C VC Data Model v2.0 with `Ed25519Signature2020` proofs
- **KeyProvider** abstraction — pluggable key storage (in-memory, HSM, etc.)
- **Crypto utilities** — sign/verify, SHA-256 hashing, deterministic canonicalization
- **Intent declarations** — structured intent constraints for tool calls
- **Agent Passport** — portable agent identity bundle

## Install

```bash
npm install @sentinel-atl/core
```

## Quick Start

```ts
import { InMemoryKeyProvider, createIdentity, issueVC, verifyVC } from '@sentinel-atl/core';

const kp = new InMemoryKeyProvider();
const agent = await createIdentity(kp, 'my-agent');
console.log(agent.did); // did:key:z6Mk...

const vc = await issueVC(kp, {
  type: 'AgentAuthorizationCredential',
  issuerDid: agent.did,
  issuerKeyId: agent.keyId,
  subjectDid: 'did:key:z6Mk...',
  scope: ['files:read'],
  maxDelegationDepth: 1,
  expiresInMs: 3600_000,
});

const result = await verifyVC(vc);
console.log(result.valid); // true
```

## API

| Export | Description |
|---|---|
| `createIdentity(kp, label)` | Generate a new DID + key pair |
| `issueVC(kp, options)` | Issue a W3C Verifiable Credential |
| `verifyVC(vc)` | Verify a VC's signature and expiration |
| `InMemoryKeyProvider` | In-memory `KeyProvider` implementation |
| `createIntent(options)` | Create an intent declaration |
| `verifyIntent(intent)` | Verify intent signature and constraints |
| `createPassport(options)` | Bundle identity + VCs into a portable passport |
| `verifyPassport(passport)` | Verify passport integrity |

## License

MIT

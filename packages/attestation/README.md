# @sentinel-atl/attestation

Code attestation — cryptographic proof that an agent is running verified code.

## Features

- **Code hashing** — deterministic SHA-256 hash of source code
- **Directory hashing** — recursive, sorted directory content hashing
- **Attestation signing** — signed proof binding agent DID to code hash
- **Verification** — verify attestation signatures and compare hashes

## Install

```bash
npm install @sentinel-atl/attestation
```

## Quick Start

```ts
import { AttestationManager, hashCode, hashDirectory } from '@sentinel-atl/attestation';

// Hash individual code
const hash = hashCode('console.log("hello")');

// Hash an entire directory
const dirHash = await hashDirectory('./src', { exclude: ['node_modules'] });

// Create and verify attestation
const mgr = new AttestationManager(auditLog);
const attestation = await mgr.createAttestation(keyProvider, {
  agentDid,
  keyId,
  codeHash: dirHash,
  description: 'v1.0.0 release',
});

const result = await mgr.verifyAttestation(attestation);
console.log(result.valid); // true
```

## API

| Export | Description |
|---|---|
| `hashCode(code)` | SHA-256 hash of a string or Uint8Array |
| `hashDirectory(path, options)` | Recursive directory hash |
| `AttestationManager` | Create, verify, and manage attestations |

## License

MIT

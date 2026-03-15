# @sentinel-atl/revocation

DID and VC revocation, key rotation, and emergency kill switch for the Agent Trust Layer.

## Features

- **VC revocation** — revoke individual credentials with signed proof
- **DID revocation** — revoke an entire agent identity
- **Key rotation** — dual-signature rotation with automatic DID resolution
- **Kill switch** — emergency cascade termination with signed evidence
- **Signed revocation lists** — publishable, verifiable revocation state

## Install

```bash
npm install @sentinel-atl/revocation
```

## Quick Start

```ts
import { RevocationManager } from '@sentinel-atl/revocation';
import { AuditLog } from '@sentinel-atl/audit';

const auditLog = new AuditLog({ logPath: './audit.jsonl' });
const revMgr = new RevocationManager(auditLog);

// Revoke a credential
await revMgr.revokeVC(keyProvider, keyId, issuerDid, vcId, 'policy_violation', 'Unauthorized access');

// Check revocation
revMgr.isVCRevoked(vcId); // true

// Emergency kill switch
await revMgr.killSwitch(keyProvider, keyId, issuerDid, targetDid, 'Data breach', { cascade: true });

// Key rotation
const rotation = await revMgr.rotateKey(oldKP, oldKeyId, newKP, newKeyId, oldDid, newDid);
revMgr.resolveCurrentDid(oldDid); // returns newDid

// Publish signed revocation list
const list = await revMgr.publishRevocationList(keyProvider, keyId, issuerDid);
```

## API

| Method | Description |
|---|---|
| `revokeVC(...)` | Revoke a Verifiable Credential |
| `revokeDID(...)` | Revoke an entire DID |
| `isVCRevoked(vcId)` | Check if a VC is revoked |
| `isTrusted(did)` | Check if a DID is trusted |
| `killSwitch(...)` | Emergency kill switch |
| `verifyKillSwitch(event)` | Verify kill switch signature |
| `rotateKey(...)` | Rotate agent key pair |
| `verifyKeyRotation(notice)` | Verify key rotation |
| `resolveCurrentDid(did)` | Resolve to latest DID after rotation |
| `publishRevocationList(...)` | Publish signed revocation list |
| `verifyRevocationList(list)` | Verify revocation list |
| `getStats()` | Get revocation statistics |

## License

MIT

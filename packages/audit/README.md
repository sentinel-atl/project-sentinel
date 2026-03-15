# @sentinel/audit

Append-only, hash-chain integrity audit logging for the Agent Trust Layer.

## Features

- **Hash-chain integrity** — each entry links to the previous via SHA-256 hash
- **18+ event types** — identity, VC, reputation, revocation, handshake, safety, and more
- **Tamper detection** — `verifyIntegrity()` detects any modifications
- **File-backed storage** — JSONL format for easy streaming and analysis

## Install

```bash
npm install @sentinel/audit
```

## Quick Start

```ts
import { AuditLog } from '@sentinel/audit';

const log = new AuditLog({ logPath: './audit.jsonl' });

await log.append({
  eventType: 'identity_created',
  actorDid: 'did:key:z6Mk...',
  result: 'success',
  metadata: { label: 'my-agent' },
});

const result = await log.verifyIntegrity();
console.log(result.valid); // true
console.log(result.totalEntries); // 1
```

## API

| Method | Description |
|---|---|
| `new AuditLog(config)` | Create a new audit log |
| `append(entry)` | Append an entry to the log |
| `readAll()` | Read all entries |
| `verifyIntegrity()` | Verify hash-chain integrity |

## License

MIT

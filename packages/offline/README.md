# @sentinel-atl/offline

Offline and degraded mode for the Agent Trust Layer — cached trust decisions, configurable policies, CRDT-style reputation merge.

## Features

- **LRU caches** — VC, reputation, and revocation caches with configurable TTLs
- **Degraded policies** — `allow`, `warn`, or `deny` per scenario (stale cache, missing data, etc.)
- **CRDT reputation merge** — last-writer-wins with nodeId tiebreaking for eventual consistency
- **Pending transaction queue** — queue operations while offline, drain when reconnected
- **Online/offline toggling** — explicit state management

## Install

```bash
npm install @sentinel-atl/offline
```

## Quick Start

```ts
import { OfflineManager } from '@sentinel-atl/offline';

const mgr = new OfflineManager({
  policy: { staleTrust: 'warn', missingData: 'deny', degradedReputation: 'allow' },
});

// Cache trust data while online
mgr.cacheVC('vc-id', vcData);
mgr.cacheReputation('did:key:z6Mk...', repScore);

// Go offline
mgr.goOffline();

// Evaluate trust using cached data
const decision = mgr.evaluateTrustDecision('vc-id');
console.log(decision.action); // 'allow' | 'warn' | 'deny'

// Queue operations for later sync
mgr.queueTransaction({ type: 'vouch', payload: { ... } });

// CRDT merge remote reputation state
mgr.recordVouch('did:key:z6Mk...', 0.8, 'node-a', Date.now());
const result = mgr.mergeRemoteState(remoteVouchState);

// Go back online
mgr.goOnline();
const synced = mgr.drainSynced();
```

## API

| Method | Description |
|---|---|
| `goOffline()` / `goOnline()` | Toggle connectivity state |
| `cacheVC(id, data)` | Cache a VC for offline use |
| `cacheReputation(did, score)` | Cache a reputation score |
| `cacheRevocation(vcId, revoked)` | Cache revocation status |
| `evaluateTrustDecision(vcId)` | Evaluate trust from cache |
| `evaluateReputationAccess(did)` | Evaluate reputation from cache |
| `queueTransaction(op)` | Queue an operation for sync |
| `drainSynced()` | Drain completed transactions |
| `recordVouch(did, score, nodeId, ts)` | Record CRDT vouch |
| `mergeRemoteState(state)` | Merge remote CRDT state |
| `exportVouchState()` | Export local CRDT state |
| `getStats()` | Get cache and queue statistics |

## License

MIT

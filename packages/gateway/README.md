# @sentinel/gateway

**MCP Security Gateway** — a drop-in proxy that adds identity, credentials, reputation, content safety, and audit to any MCP server.

```
Client → [Gateway: identity + credentials + reputation + safety + audit] → Server
```

## Install

```bash
npm install @sentinel/gateway
```

## Quick Start

```typescript
import { createGateway } from '@sentinel/gateway';

const gw = await createGateway({
  name: 'my-gateway',
  enableSafety: true,
  minReputation: 30,
  rateLimitMax: 100,
});

// Block dangerous tools
gw.addToolPolicy('delete_all', { blocked: true });

// Require high reputation for admin tools
gw.addToolPolicy('exec_code', { minReputation: 80 });

// Process every incoming tool call
const result = await gw.processToolCall({
  toolName: 'search',
  callerDid: agent.did,
  credentials: [vc],
  authPayload: payload,
  authSignature: signature,
});

if (result.allowed) {
  const output = await upstreamServer.callTool('search', args);

  // Check output safety before returning
  const safety = await gw.checkResponseSafety(agent.did, 'search', JSON.stringify(output));
  if (safety.allowed) return output;
}
```

## Features

| Feature | Description |
|---------|-------------|
| **Per-caller rate limiting** | Configurable max requests per window |
| **Tool policies** | Block, scope-restrict, or reputation-gate any tool |
| **Pre-hooks** | Custom async functions for per-tool authorization |
| **Content safety** | Pre-dispatch and post-response content filtering |
| **Kill switch** | Emergency revocation cascading to all delegates |
| **Reputation tracking** | Automatic scoring with vouch support |
| **Offline mode** | Degraded trust decisions when disconnected |
| **Full audit trail** | Hash-chained, tamper-evident log of every call |
| **Stats & observability** | Per-tool and per-caller metrics |

## API

### `createGateway(config: GatewayConfig): Promise<MCPSecurityGateway>`

Factory function that creates a fully initialized gateway.

### `gateway.processToolCall(request): Promise<GatewayResult>`

Run the full Sentinel pipeline on an incoming tool call.

### `gateway.checkResponseSafety(callerDid, toolName, response): Promise<{allowed, safetyResult?}>`

Check a tool response for content safety violations.

### `gateway.addToolPolicy(toolName, policy): void`

Register per-tool policies (block, scopes, reputation, hooks).

### `gateway.revokeCaller(targetDid, reason): Promise<void>`

Revoke a caller so they can no longer pass through the gateway.

### `gateway.killSwitch(targetDid, reason, downstreamDids?): Promise<KillSwitchEvent>`

Emergency cascading revocation.

### `gateway.getStats(): GatewayStats`

Per-tool and per-caller statistics.

## License

Apache-2.0

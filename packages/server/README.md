# @sentinel-atl/server

**STP-compliant HTTP server** — exposes the full Sentinel Trust Protocol as a language-agnostic REST API.

Any language. Any framework. Just HTTP.

## Install

```bash
npm install @sentinel-atl/server
```

## Quick Start

```typescript
import { createSTPServer } from '@sentinel-atl/server';

const server = await createSTPServer({
  name: 'my-trust-server',
  port: 3100,
  enableSafety: true,
});
await server.start();
```

Your server is now live at `http://localhost:3100` with all STP endpoints.

## Discovery

```bash
curl http://localhost:3100/.well-known/sentinel-configuration
```

Returns the full server configuration, DID, endpoints, capabilities, and supported credential types — everything a client needs to interact with this server.

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/.well-known/sentinel-configuration` | — | STP discovery |
| POST | `/v1/identity` | — | Create agent identity |
| GET | `/v1/identity/{did}` | — | Resolve DID document |
| POST | `/v1/token` | — | Issue STP auth token |
| POST | `/v1/credentials` | STP | Issue Verifiable Credential |
| POST | `/v1/credentials/verify` | — | Verify a credential |
| POST | `/v1/credentials/revoke` | STP | Revoke a credential |
| GET | `/v1/reputation/{did}` | — | Query reputation score |
| POST | `/v1/reputation/vouch` | STP | Submit a vouch |
| POST | `/v1/intents` | STP | Create intent envelope |
| POST | `/v1/intents/validate` | — | Validate an intent |
| GET | `/v1/revocation/status/{did}` | — | Check revocation status |
| GET | `/v1/revocation/list` | — | Get signed revocation list |
| POST | `/v1/revocation/kill-switch` | STP | Emergency kill switch |
| POST | `/v1/safety/check` | — | Content safety check |
| GET | `/v1/audit` | — | Fetch audit entries |
| POST | `/v1/audit/verify` | — | Verify audit integrity |

## Using from Any Language

### Python
```python
import requests

# Discovery
config = requests.get("http://localhost:3100/.well-known/sentinel-configuration").json()

# Create identity
agent = requests.post("http://localhost:3100/v1/identity", json={"label": "my-agent"}).json()

# Get token
token = requests.post("http://localhost:3100/v1/token", json={"did": agent["did"]}).json()["token"]

# Query reputation
rep = requests.get(f"http://localhost:3100/v1/reputation/{agent['did']}").json()
print(f"Score: {rep['score']}")

# Issue credential
vc = requests.post("http://localhost:3100/v1/credentials",
    json={"type": "AgentAuthorizationCredential", "subjectDid": other_did, "scope": ["flights:book"]},
    headers={"Authorization": f"STP {token}"}
).json()
```

### curl
```bash
# Create identity
curl -X POST http://localhost:3100/v1/identity -H "Content-Type: application/json" -d '{"label": "my-agent"}'

# Check reputation
curl http://localhost:3100/v1/reputation/did:key:z6Mk...

# Verify a credential
curl -X POST http://localhost:3100/v1/credentials/verify -H "Content-Type: application/json" -d '{"credential": {...}}'
```

## OpenAPI Spec

The full OpenAPI 3.1 specification is at [specs/openapi-v1.0.yaml](../../specs/openapi-v1.0.yaml). Use it to generate clients in any language:

```bash
# Generate Python client
openapi-generator generate -i specs/openapi-v1.0.yaml -g python -o clients/python

# Generate Go client
openapi-generator generate -i specs/openapi-v1.0.yaml -g go -o clients/go

# Generate Java client
openapi-generator generate -i specs/openapi-v1.0.yaml -g java -o clients/java
```

## STP Token Authentication

Authenticated endpoints require an `Authorization: STP <token>` header. Tokens are Ed25519-signed, non-replayable, and time-bounded:

```
STP.<header-base64url>.<payload-base64url>.<signature-base64url>
```

Use the `/v1/token` endpoint to issue tokens, or create them client-side using `@sentinel-atl/core`:

```typescript
import { createSTPToken, InMemoryKeyProvider, createIdentity } from '@sentinel-atl/core';

const kp = new InMemoryKeyProvider();
const id = await createIdentity(kp, 'my-agent');
const token = await createSTPToken(kp, {
  issuerDid: id.did,
  keyId: id.keyId,
  audience: 'http://localhost:3100',
  scope: ['flights:book'],
});
```

## License

Apache-2.0

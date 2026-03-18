# Sentinel ATL — Python SDK

The Agent Trust Layer for AI agents. Identity, credentials, and reputation.

```bash
pip install sentinel-atl
```

## Quick Start

```python
from sentinel_atl import create_trusted_agent

# Create a trusted agent identity (Ed25519 DID)
agent = create_trusted_agent("my-agent")

print(f"Agent DID: {agent.did}")
print(f"Key ID:    {agent.key_id}")

# Issue a Verifiable Credential
vc = agent.issue_credential(
    subject_did=agent.did,
    credential_type="AgentAuthorization",
    scope=["read", "write"],
)

# Verify the credential
result = agent.verify_credential(vc)
assert result["valid"]

# Reputation vouching
agent.vouch(peer_did="did:key:z6Mk...", polarity="positive", weight=0.8)
score = agent.get_reputation("did:key:z6Mk...")

# Content safety
safety_result = agent.check_safety("some text to check")

# Audit logging
entries = agent.get_audit_entries()
```

## Framework Integrations

### LangChain

```python
from sentinel_atl.langchain import SentinelCallbackHandler

handler = SentinelCallbackHandler(agent)
# Pass to any LangChain chain as a callback
```

## With STP Server (for multi-language interop)

```python
from sentinel_atl.client import STPClient

client = STPClient("http://localhost:3000")
identity = await client.create_identity()
vc = await client.issue_credential(subject_did=identity["did"], scope=["read"])
```

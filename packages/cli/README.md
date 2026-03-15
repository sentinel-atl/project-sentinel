# @sentinel/cli

CLI tool for the Agent Trust Layer — identity, credentials, signing, and trust operations.

## Install

```bash
npm install -g @sentinel/cli
```

## Commands

| Command | Description |
|---|---|
| `sentinel init` | Generate a new DID identity |
| `sentinel whoami` | Display current DID and key info |
| `sentinel sign <file>` | Sign a file with your key |
| `sentinel verify <file> <sig>` | Verify a signature |
| `sentinel issue-vc` | Issue a Verifiable Credential |
| `sentinel verify-vc <vc>` | Verify a VC |
| `sentinel create-intent` | Create an intent declaration |
| `sentinel backup-key` | Backup key via Shamir's Secret Sharing |
| `sentinel audit verify` | Verify audit log integrity |

## Quick Start

```bash
# Initialize a new agent identity
sentinel init --label my-agent

# Show your DID
sentinel whoami

# Issue a credential
sentinel issue-vc --subject did:key:z6Mk... --scope files:read

# Verify audit integrity
sentinel audit verify --path ./audit.jsonl
```

## License

MIT

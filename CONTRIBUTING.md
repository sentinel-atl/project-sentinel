# Contributing to Project Sentinel

Thank you for your interest in the Agent Trust Layer. This guide will help you get started.

## Development Setup

```bash
# Clone and install
git clone https://github.com/YOUR_ORG/project-sentinel.git
cd project-sentinel
npm install

# Build all packages
npm run build

# Run all tests
npx vitest run

# Run the demo
npx tsx examples/two-agent-handshake/demo.ts
```

## Project Structure

```
packages/
  core/          — DID, VC, crypto, Proof of Intent, Agent Passport
  handshake/     — Zero-trust 5-step mutual verification protocol
  reputation/    — Weighted scoring with negative vouches + quarantine
  audit/         — Append-only hash-chain integrity logging
  recovery/      — Shamir's Secret Sharing for key backup
  revocation/    — DID + VC revocation, key rotation, kill switch
  mcp-plugin/    — MCP server middleware (identity at tool-call boundary)
  sdk/           — Developer-facing SDK (5-line integration)
  cli/           — sentinel CLI tool
specs/           — Protocol specifications
examples/        — Working demos
```

## Making Changes

1. **Fork** the repo and create a feature branch from `main`
2. **Write code** — follow existing patterns (TypeScript, ESM, Ed25519)
3. **Write tests** — every new feature needs tests. Run `npx vitest run` to verify
4. **Build** — `npm run build` must pass with zero errors
5. **Submit a PR** — describe what and why

## Code Conventions

- **TypeScript** with strict mode
- **ESM** (`"type": "module"`) — use `.js` extensions in imports
- **Ed25519** for all signing operations (`@noble/ed25519`)
- **SHA-256** for all hashing (`@noble/hashes`)
- **DID method:** `did:key` with Ed25519 multicodec
- **VCs:** W3C Verifiable Credentials Data Model v2.0
- **Canonicalization:** Recursive deep-sort of object keys before signing

## Security

If you discover a security vulnerability, please email it privately instead of opening a public issue. Refer to [SECURITY.md](SECURITY.md) when available.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.

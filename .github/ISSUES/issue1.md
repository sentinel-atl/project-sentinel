## Overview
Build `sentinel verify <server>` CLI command — the "npm audit" for MCP servers.

## What it does
Given an MCP server (npm package name, GitHub URL, or local path), it:
1. Resolves the server package and downloads/clones it
2. Runs static analysis (dependency audit, permission detection, code patterns)
3. Spins up a sandboxed instance and probes its tool declarations
4. Issues a Sentinel Trust Certificate (STC) — a signed VC with the scan results
5. Outputs a human-readable trust report + machine-readable JSON

## Technical Details
- New package: `packages/scanner/` — the core scanning engine
- Extends `packages/cli/` — adds `verify` subcommand
- Uses `@sentinel-atl/core` for DID signing of certificates
- Uses `@sentinel-atl/attestation` for VC issuance
- Uses `@sentinel-atl/reputation` for trust scoring

## Acceptance Criteria
- [ ] `sentinel verify npm-package` works end-to-end
- [ ] Static analysis detects: network calls, fs access, child_process, eval, obfuscated code
- [ ] Dependency audit via npm audit integration
- [ ] Tool declaration analysis (what tools does the server expose?)
- [ ] Trust score 0-100 based on weighted signals
- [ ] STC (Sentinel Trust Certificate) issued as signed VC
- [ ] JSON output mode for CI/CD integration
- [ ] Tests covering all scanner modules

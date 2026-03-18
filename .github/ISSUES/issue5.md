## Overview
The core static analysis and behavior probing engine for MCP servers.

## Analysis Modules

### 1. Dependency Scanner
- Run `npm audit` on package
- Check for known vulnerable dependencies
- Flag outdated packages

### 2. Permission Detector
- AST parsing to find: fs, net, http, child_process, eval, Function
- Map permissions to tool declarations
- Flag undeclared capabilities

### 3. Code Pattern Analyzer
- Detect obfuscated code (high entropy strings, eval chains)
- Find data exfiltration patterns
- Check for credential handling

### 4. Tool Probe
- Start server in sandbox
- Call tools/list to enumerate capabilities
- Validate tool schemas

### 5. Publisher Verifier
- Check npm/GitHub publisher identity
- Verify package signing if available
- Check maintainer reputation

### 6. Trust Scorer
- Weighted scoring algorithm
- 0-100 scale
- Configurable weights per category

## Technical Details
- New package: `packages/scanner/`
- Uses `typescript` + `@typescript-eslint/parser` for AST
- Uses `vm` module for sandboxed execution
- Uses `npm-registry-fetch` for package resolution

## Acceptance Criteria
- [ ] Dependency scanner integration
- [ ] AST-based permission detection
- [ ] Obfuscation detection
- [ ] Sandboxed tool probing
- [ ] Publisher identity verification
- [ ] Trust score calculation
- [ ] Comprehensive test suite
- [ ] Performance: scan under 30 seconds

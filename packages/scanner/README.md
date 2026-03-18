# @sentinel-atl/scanner

MCP server security scanner — npm audit meets AI agent trust verification.

Analyzes MCP server packages for dependency vulnerabilities, dangerous code patterns, permission requirements, and publisher identity. Produces a 0–100 trust score and can issue/verify Sentinel Trust Certificates (STCs).

## Install

```bash
npm install @sentinel-atl/scanner
```

## Quick Start

```ts
import { scan, issueSTC } from '@sentinel-atl/scanner';

// Full security scan
const report = await scan({ packageName: 'some-mcp-server' });
console.log(report.trustScore.overall); // 0-100
console.log(report.trustScore.grade);   // A-F

// Issue a Sentinel Trust Certificate
const stc = await issueSTC({
  issuer: { did: 'did:key:z6Mk...' },
  subject: { packageName: 'some-mcp-server', packageVersion: '1.0.0' },
  findings: report.findings,
});
```

## Security Analysis

The scanner runs 4 sub-scanners and aggregates results into a single trust score:

### 1. Dependency Vulnerabilities

```ts
import { scanDependencies } from '@sentinel-atl/scanner';
const result = await scanDependencies('/path/to/package');
// Integrates with npm audit
```

### 2. Code Pattern Analysis

```ts
import { scanCodePatterns } from '@sentinel-atl/scanner';
const result = await scanCodePatterns('/path/to/package');
// Detects: eval, child_process, fs, net, exfiltration, obfuscation
```

### 3. Permission Analysis

```ts
import { scanPermissions } from '@sentinel-atl/scanner';
const result = await scanPermissions('/path/to/package');
// Analyzes: filesystem, network, process, crypto, environment, native
```

### 4. Publisher Identity

```ts
import { scanPublisher } from '@sentinel-atl/scanner';
const result = await scanPublisher('express');
// Checks npm registry: maintainers, downloads, repository presence
```

## Trust Score

```ts
import { computeTrustScore } from '@sentinel-atl/scanner';

const score = computeTrustScore(findings);
// { overall: 82, grade: 'B', breakdown: { dependencies, codePatterns, permissions, publisher } }
```

Grading scale: **A** (90–100), **B** (80–89), **C** (70–79), **D** (60–69), **F** (0–59).

## Sentinel Trust Certificates (STC)

STCs are signed attestations of a scan result — the core artifact of the Sentinel trust ecosystem.

```ts
import { issueSTC, verifySTC } from '@sentinel-atl/scanner';

// Issue
const stc = await issueSTC({ issuer, subject, findings });

// Verify
const result = verifySTC(stc);
// { valid: true, expired: false, ... }
```

## MCP Tool Probing

```ts
import { probeTools } from '@sentinel-atl/scanner';

const result = await probeTools('http://localhost:4000/sse');
// Returns tool definitions with permission analysis
```

## License

MIT

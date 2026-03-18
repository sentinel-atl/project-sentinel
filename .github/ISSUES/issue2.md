## Overview
Runtime trust enforcement proxy that sits between MCP clients and servers.

## What it does
1. All MCP traffic flows through the gateway
2. Every tool call is verified against trust policies before execution
3. Real-time behavior monitoring detects anomalous patterns
4. DLP (Data Loss Prevention) blocks sensitive data exfiltration
5. Full audit trail with cryptographic proofs

## Features
- Trust verification: reject unverified/low-reputation servers
- Budget enforcement: per-server daily spend limits
- Human approval: require confirmation for high-risk operations
- Content safety: pre/post content filtering
- Rate limiting: per-caller limits
- Kill switch: emergency revocation

## Configuration
```yaml
gateway:
  mode: strict  # strict = reject unverified, permissive = warn
  budget: 10/day
  compliance: [SOC2, GDPR]
  
servers:
  - name: filesystem
    trust: verified
    permissions: [read]
    rate_limit: 100/min
```

## Technical Details
- Extends existing `packages/gateway/` and `packages/mcp-proxy/`
- Adds trust verification before tool dispatch
- Uses `@sentinel-atl/budget` for cost control
- Uses `@sentinel-atl/approval` for human-in-the-loop
- Uses `@sentinel-atl/safety` for content filtering
- YAML config for declarative policy

## Acceptance Criteria
- [ ] Gateway proxies MCP stdio/SSE traffic
- [ ] Trust verification: checks STC before forwarding
- [ ] Budget enforcement: tracks and limits spend
- [ ] Human approval flow for sensitive ops
- [ ] Content safety pre/post checks
- [ ] Docker deployment ready
- [ ] YAML configuration
- [ ] Tests for all enforcement modes

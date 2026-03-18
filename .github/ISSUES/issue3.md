## Overview
Public trust registry API for publishing and querying MCP server trust certificates.

## What it does
1. Publishers submit STCs (Sentinel Trust Certificates) after scanning
2. Consumers query trust status before using MCP servers
3. Provides trust badges for README embedding
4. REST API for programmatic access

## API Endpoints
```
POST   /api/v1/certificates          Submit a new STC
GET    /api/v1/certificates/:id      Get certificate by ID
GET    /api/v1/servers/:name         Get all certs for a server
GET    /api/v1/servers/:name/badge   Get trust badge SVG/PNG
GET    /api/v1/servers/:name/score   Get current trust score
GET    /api/v1/search                Search servers by name/tags
POST   /api/v1/verify                Verify a certificate signature
```

## Technical Details
- New package: `packages/registry/`
- Uses `@sentinel-atl/core` for signature verification
- Uses `@sentinel-atl/attestation` for VC verification
- SQLite for local dev, Postgres/Turso for production
- Cloudflare Workers or Node.js deployment

## Acceptance Criteria
- [ ] REST API endpoints implemented
- [ ] Certificate submission with DID signature verification
- [ ] Query by server name/version
- [ ] Trust badge generation (SVG)
- [ ] Search functionality
- [ ] Rate limiting and abuse prevention
- [ ] OpenAPI spec
- [ ] Tests with in-memory database

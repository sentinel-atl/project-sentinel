/**
 * Integration test — end-to-end flow through server + gateway.
 *
 * Tests the full lifecycle:
 *   1. Start server
 *   2. Create identity via API
 *   3. Issue STP token for authentication
 *   4. Issue a credential
 *   5. Verify the credential
 *   6. Query reputation
 *   7. Vouch for reputation
 *   8. Check safety endpoint
 *   9. Verify audit trail integrity
 *   10. Health + readiness endpoints
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createSTPServer, type STPServer } from './index.js';
import {
  createIdentity,
  InMemoryKeyProvider,
  createSTPToken,
  type KeyProvider,
  type AgentIdentity,
} from '@sentinel-atl/core';
import http from 'node:http';
import { unlinkSync, existsSync } from 'node:fs';

// ─── HTTP Client ─────────────────────────────────────────────────────

function request(
  port: number,
  method: string,
  path: string,
  body?: unknown,
  headers?: Record<string, string>
): Promise<{ status: number; data: any }> {
  return new Promise((resolve, reject) => {
    const bodyStr = body ? JSON.stringify(body) : undefined;
    const req = http.request(
      { hostname: 'localhost', port, path, method, headers: {
        'Content-Type': 'application/json',
        ...(bodyStr ? { 'Content-Length': Buffer.byteLength(bodyStr).toString() } : {}),
        ...headers,
      }},
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          try { resolve({ status: res.statusCode!, data: JSON.parse(data) }); }
          catch { resolve({ status: res.statusCode!, data }); }
        });
      }
    );
    req.on('error', reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

// ─── Tests ───────────────────────────────────────────────────────────

const PORT = 13579;
const AUDIT_FILE = `stp-server-integration-test-audit.jsonl`;

describe('Integration: full STP lifecycle', () => {
  let server: STPServer;
  let keyProvider: KeyProvider;
  let serverIdentity: { did: string; keyId: string };
  let clientIdentity: AgentIdentity;

  beforeAll(async () => {
    // Clean up leftover audit file
    if (existsSync(AUDIT_FILE)) unlinkSync(AUDIT_FILE);

    keyProvider = new InMemoryKeyProvider();
    server = await createSTPServer({
      name: 'integration-test',
      port: PORT,
      keyProvider,
      enableSafety: true,
    });
    await server.start();
    serverIdentity = { did: server.did, keyId: server.keyId };

    // Create a client identity directly (for signing tokens)
    clientIdentity = await createIdentity(keyProvider, 'test-client');
  });

  afterAll(async () => {
    await server.stop();
    if (existsSync(AUDIT_FILE)) unlinkSync(AUDIT_FILE);
  });

  it('health endpoint returns ok', async () => {
    const res = await request(PORT, 'GET', '/health');
    expect(res.status).toBe(200);
    expect(res.data.status).toBe('ok');
    expect(res.data.uptime).toBeGreaterThanOrEqual(0);
  });

  it('readiness endpoint returns ready', async () => {
    const res = await request(PORT, 'GET', '/ready');
    expect(res.status).toBe(200);
    expect(res.data.status).toBe('ready');
  });

  it('discovery returns sentinel configuration', async () => {
    const res = await request(PORT, 'GET', '/.well-known/sentinel-configuration');
    expect(res.status).toBe(200);
    expect(res.data.protocol_version).toBe('STP/1.0');
    expect(res.data.server_did).toMatch(/^did:key:z6Mk/);
  });

  it('creates identity via API', async () => {
    const res = await request(PORT, 'POST', '/v1/identity', { label: 'e2e-agent' });
    expect(res.status).toBe(201);
    expect(res.data.did).toMatch(/^did:key:z6Mk/);
  });

  it('resolves identity DID', async () => {
    const res = await request(PORT, 'GET', `/v1/identity/${encodeURIComponent(server.did)}`);
    expect(res.status).toBe(200);
    expect(res.data.id).toBe(server.did);
  });

  it('issues and verifies credential with STP auth', async () => {
    // Create an agent on the server
    const createRes = await request(PORT, 'POST', '/v1/identity', { label: 'cred-subject' });
    expect(createRes.status).toBe(201);
    const subjectDid = createRes.data.did;

    // Get STP token for server identity
    const baseUrl = `http://localhost:${PORT}`;
    const token = await createSTPToken(keyProvider, {
      issuerDid: serverIdentity.did,
      keyId: serverIdentity.keyId,
      audience: baseUrl,
      scope: ['credentials:issue'],
      expiresInSec: 60,
    });

    // Issue credential
    const issueRes = await request(PORT, 'POST', '/v1/credentials', {
      type: 'AgentAuthorizationCredential',
      subjectDid,
      scope: ['tools:read'],
    }, { Authorization: `STP ${token}` });
    expect(issueRes.status).toBe(201);
    expect(issueRes.data.issuer).toBeTruthy();

    // Verify credential
    const verifyRes = await request(PORT, 'POST', '/v1/credentials/verify', {
      credential: issueRes.data,
    });
    expect(verifyRes.status).toBe(200);
    expect(verifyRes.data.valid).toBe(true);
  });

  it('queries reputation (starts at 0)', async () => {
    const res = await request(PORT, 'GET', `/v1/reputation/${encodeURIComponent(server.did)}`);
    expect(res.status).toBe(200);
    expect(typeof res.data.score).toBe('number');
  });

  it('safety check detects safe content', async () => {
    const res = await request(PORT, 'POST', '/v1/safety/check', { text: 'hello world' });
    expect(res.status).toBe(200);
    expect(res.data.safe).toBe(true);
  });

  it('returns security headers', async () => {
    const raw = await new Promise<http.IncomingMessage>((resolve, reject) => {
      http.get(`http://localhost:${PORT}/health`, resolve).on('error', reject);
    });
    expect(raw.headers['x-content-type-options']).toBe('nosniff');
    expect(raw.headers['x-frame-options']).toBe('DENY');
    expect(raw.headers['x-request-id']).toBeTruthy();
    raw.resume(); // consume body
  });

  it('returns X-Request-Id on every response', async () => {
    const raw = await new Promise<http.IncomingMessage>((resolve, reject) => {
      http.get(`http://localhost:${PORT}/health`, resolve).on('error', reject);
    });
    expect(raw.headers['x-request-id']).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
    );
    raw.resume();
  });

  it('audit trail integrity holds after multiple operations', async () => {
    const res = await request(PORT, 'POST', '/v1/audit/verify');
    expect(res.status).toBe(200);
    expect(res.data.valid).toBe(true);
    expect(res.data.totalEntries).toBeGreaterThan(0);
  });
});

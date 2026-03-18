import { describe, it, expect, afterEach } from 'vitest';
import { TrustGatewayProxy, TrustStore, type GatewayConfig } from '../index.js';
import { InMemoryKeyProvider, publicKeyToDid } from '@sentinel-atl/core';
import { scan, issueSTC } from '@sentinel-atl/scanner';
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// ─── Helpers ──────────────────────────────────────────────────────────

async function createTempPackage(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'sentinel-proxy-'));
  for (const [name, content] of Object.entries(files)) {
    const dirPath = join(dir, name.split('/').slice(0, -1).join('/'));
    if (name.includes('/')) await mkdir(dirPath, { recursive: true });
    await writeFile(join(dir, name), content, 'utf-8');
  }
  return dir;
}

function makeConfig(overrides?: Partial<GatewayConfig['gateway']>): GatewayConfig {
  return {
    gateway: {
      name: 'test-proxy',
      port: 0, // will be overridden
      mode: 'strict',
      ...overrides,
    },
    servers: [
      {
        name: 'test-server',
        upstream: 'http://localhost:19999/sse',
        trust: { minScore: 60, requireCertificate: true },
      },
    ],
  };
}

// Dynamic port allocation helper
let nextPort = 18100;
function getPort(): number {
  return nextPort++;
}

// ─── Tests ────────────────────────────────────────────────────────────

let proxy: TrustGatewayProxy | null = null;

afterEach(async () => {
  if (proxy) {
    await proxy.stop();
    proxy = null;
  }
});

describe('TrustGatewayProxy', () => {
  it('starts and responds to /health', async () => {
    const port = getPort();
    const config = makeConfig({ port });
    proxy = new TrustGatewayProxy({ config });
    await proxy.start();

    const res = await fetch(`http://localhost:${port}/health`);
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.status).toBe('ok');
    expect(body.gateway).toBe('test-proxy');
    expect(body.servers).toContain('test-server');
  });

  it('responds to /stats', async () => {
    const port = getPort();
    const config = makeConfig({ port });
    proxy = new TrustGatewayProxy({ config });
    await proxy.start();

    const res = await fetch(`http://localhost:${port}/stats`);
    expect(res.status).toBe(200);
    const stats = await res.json() as any;
    expect(stats.totalRequests).toBe(0);
  });

  it('returns 404 for unknown routes', async () => {
    const port = getPort();
    const config = makeConfig({ port });
    proxy = new TrustGatewayProxy({ config });
    await proxy.start();

    const res = await fetch(`http://localhost:${port}/nonexistent`);
    expect(res.status).toBe(404);
  });

  it('denies tool call when no certificate loaded', async () => {
    const port = getPort();
    const config = makeConfig({ port });
    proxy = new TrustGatewayProxy({ config });
    await proxy.start();

    const res = await fetch(`http://localhost:${port}/message?server=test-server`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'read_file', arguments: { path: '/tmp/test' } },
      }),
    });

    expect(res.status).toBe(403);
    const body = await res.json() as any;
    expect(body.error.data.decision).toBe('deny-no-cert');
  });

  it('allows tool call with valid certificate in permissive mode', async () => {
    const port = getPort();
    const config: GatewayConfig = {
      gateway: { name: 'test-permissive', port, mode: 'permissive' },
      servers: [{
        name: 'test-server',
        upstream: 'http://localhost:19999/sse',
        trust: { minScore: 60, requireCertificate: true },
      }],
    };

    proxy = new TrustGatewayProxy({ config });
    await proxy.start();

    // In permissive mode, even without a cert, it should warn but allow
    // But the upstream won't be available, so we expect a 502 (upstream error)
    const res = await fetch(`http://localhost:${port}/message?server=test-server`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'read_file', arguments: {} },
      }),
    });

    // Should be 502 (upstream unavailable) rather than 403 (denied)
    expect(res.status).toBe(502);
  });

  it('returns SSE stream with endpoint info', async () => {
    const port = getPort();
    const config = makeConfig({ port });
    proxy = new TrustGatewayProxy({ config });
    await proxy.start();

    const res = await fetch(`http://localhost:${port}/sse?server=test-server`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('text/event-stream');

    // Read first event
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    const { value } = await reader.read();
    const text = decoder.decode(value);
    expect(text).toContain('event: endpoint');
    expect(text).toContain('/message?sessionId=');

    reader.cancel();
  });

  it('handles invalid JSON in POST /message', async () => {
    const port = getPort();
    const config = makeConfig({ port });
    proxy = new TrustGatewayProxy({ config });
    await proxy.start();

    const res = await fetch(`http://localhost:${port}/message?server=test-server`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not json',
    });

    expect(res.status).toBe(400);
  });

  it('handles CORS preflight', async () => {
    const port = getPort();
    const config = makeConfig({ port });
    proxy = new TrustGatewayProxy({ config });
    await proxy.start();

    const res = await fetch(`http://localhost:${port}/message`, {
      method: 'OPTIONS',
    });

    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
  });
});

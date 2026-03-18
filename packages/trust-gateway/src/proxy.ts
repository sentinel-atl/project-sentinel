/**
 * Trust Gateway HTTP Proxy — sits between MCP client and server,
 * enforcing trust policies on every tool call.
 *
 * Supports upstream protocols:
 *   - http:// / https://  → SSE-based MCP server
 *   - stdio://             → stdio-based MCP server (spawns child process)
 *
 * Endpoints exposed:
 *   GET  /sse              → SSE stream (proxied from upstream)
 *   POST /message          → JSON-RPC message relay (tool calls pass through trust engine)
 *   GET  /health           → Proxy health
 *   GET  /stats            → Gateway stats
 */

import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { spawn, type ChildProcess } from 'node:child_process';
import { TrustGateway, type GatewayResponse } from './gateway.js';
import type { GatewayConfig, ServerPolicy } from './config.js';
import { TrustStore } from './trust-store.js';
import { randomUUID } from 'node:crypto';
import {
  authenticate, sendUnauthorized,
  applyCors, defaultCorsConfig,
  createSecureServer,
  setRateLimitHeaders, sendRateLimited,
  RateLimiter as HardenedRateLimiter, parseRateLimit as hardenedParseRateLimit,
  type AuthConfig, type CorsConfig, type TlsConfig,
} from '@sentinel-atl/hardening';

// ─── Types ───────────────────────────────────────────────────────────

export interface ProxyOptions {
  /** Gateway config */
  config: GatewayConfig;
  /** Pre-configured trust store (optional) */
  trustStore?: TrustStore;
  /** Default caller ID when none provided */
  defaultCallerId?: string;
  /** API key authentication config */
  auth?: AuthConfig;
  /** CORS configuration */
  cors?: CorsConfig;
  /** TLS configuration */
  tls?: TlsConfig;
}

interface SSEClient {
  id: string;
  res: ServerResponse;
  serverName: string;
}

interface StdioUpstream {
  process: ChildProcess;
  pending: Map<string | number, { resolve: (data: unknown) => void; reject: (err: Error) => void }>;
  buffer: string;
}

// ─── Proxy ───────────────────────────────────────────────────────────

export class TrustGatewayProxy {
  private server: Server | null = null;
  private gateway: TrustGateway;
  private config: GatewayConfig;
  private sseClients = new Set<SSEClient>();
  private stdioUpstreams = new Map<string, StdioUpstream>();
  private defaultCallerId: string;
  private authConfig: AuthConfig;
  private corsConfig: CorsConfig;
  private tlsConfig?: TlsConfig;
  private globalRateLimiter?: HardenedRateLimiter;

  constructor(options: ProxyOptions) {
    this.config = options.config;
    this.defaultCallerId = options.defaultCallerId ?? 'anonymous';
    this.authConfig = options.auth ?? { enabled: false, keys: [] };
    this.corsConfig = options.cors ?? defaultCorsConfig();
    this.tlsConfig = options.tls;
    const trustStore = options.trustStore ?? new TrustStore();
    this.gateway = new TrustGateway(this.config, trustStore);

    // Public paths: health + stats + SSE are readable without auth
    if (this.authConfig.enabled && !this.authConfig.publicPaths) {
      this.authConfig.publicPaths = ['/health', '/stats', '/sse'];
    }
  }

  getGateway(): TrustGateway {
    return this.gateway;
  }

  /**
   * Start the HTTP proxy server.
   */
  async start(): Promise<{ port: number }> {
    const port = this.config.gateway.port ?? 3100;

    // Pre-connect to stdio upstreams
    for (const server of this.config.servers) {
      if (server.upstream.startsWith('stdio://')) {
        this.connectStdio(server);
      }
    }

    return new Promise((resolve, reject) => {
      this.server = createSecureServer(
        (req, res) => this.handleRequest(req, res),
        this.tlsConfig
      );

      this.server.on('error', reject);
      this.server.listen(port, () => {
        resolve({ port });
      });
    });
  }

  /**
   * Stop the proxy and clean up.
   */
  async stop(): Promise<void> {
    // Close SSE clients
    for (const client of this.sseClients) {
      client.res.end();
    }
    this.sseClients.clear();

    // Kill stdio upstreams
    for (const [, upstream] of this.stdioUpstreams) {
      upstream.process.kill();
      for (const [, pending] of upstream.pending) {
        pending.reject(new Error('Proxy shutting down'));
      }
    }
    this.stdioUpstreams.clear();

    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  // ─── HTTP Router ────────────────────────────────────────────────

  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
    const url = new URL(req.url ?? '/', `http://localhost`);
    const path = url.pathname;

    // CORS (configurable origins)
    if (applyCors(req, res, this.corsConfig)) return; // preflight handled

    // Authentication
    const authResult = authenticate(req, this.authConfig);
    if (!authResult.authenticated) {
      sendUnauthorized(res, this.authConfig, authResult.error);
      return;
    }

    if (path === '/health' && req.method === 'GET') {
      this.handleHealth(res);
    } else if (path === '/stats' && req.method === 'GET') {
      this.handleStats(res);
    } else if (path === '/sse' && req.method === 'GET') {
      this.handleSSE(req, res, url);
    } else if (path === '/message' && req.method === 'POST') {
      this.handleMessage(req, res);
    } else {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
    }
  }

  // ─── Health ──────────────────────────────────────────────────────

  private handleHealth(res: ServerResponse): void {
    const payload = {
      status: 'ok',
      gateway: this.config.gateway.name,
      mode: this.config.gateway.mode,
      servers: this.config.servers.map(s => s.name),
      sseClients: this.sseClients.size,
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(payload));
  }

  // ─── Stats ───────────────────────────────────────────────────────

  private handleStats(res: ServerResponse): void {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(this.gateway.getStats()));
  }

  // ─── SSE Stream ──────────────────────────────────────────────────

  private handleSSE(req: IncomingMessage, res: ServerResponse, url: URL): void {
    const serverName = url.searchParams.get('server') ?? this.config.servers[0]?.name;
    if (!serverName) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'No server configured' }));
      return;
    }

    const client: SSEClient = { id: randomUUID(), res, serverName };

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    });

    // Send endpoint info
    res.write(`event: endpoint\ndata: /message?sessionId=${client.id}&server=${serverName}\n\n`);

    this.sseClients.add(client);

    req.on('close', () => {
      this.sseClients.delete(client);
    });
  }

  private sendSSEEvent(client: SSEClient, data: unknown): void {
    client.res.write(`event: message\ndata: ${JSON.stringify(data)}\n\n`);
  }

  // ─── Message (JSON-RPC) ──────────────────────────────────────────

  private async handleMessage(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://localhost`);
    const serverName = url.searchParams.get('server')
      ?? req.headers['x-server-name'] as string
      ?? this.config.servers[0]?.name;

    if (!serverName) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'No server specified' }));
      return;
    }

    const callerId = req.headers['x-caller-id'] as string ?? this.defaultCallerId;

    let body: string;
    try {
      body = await readBody(req);
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid request body' }));
      return;
    }

    let jsonRpc: any;
    try {
      jsonRpc = JSON.parse(body);
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
      return;
    }

    // Extract tool name from JSON-RPC method
    const method: string = jsonRpc.method ?? '';
    const toolName = method === 'tools/call'
      ? jsonRpc.params?.name ?? 'unknown'
      : method;

    // ── Trust check ──
    const gatewayResult = await this.gateway.processRequest({
      serverName,
      toolName,
      callerId,
      arguments: jsonRpc.params?.arguments,
    });

    // ── Global rate-limit check (with RFC 6585 headers) ──
    if (this.globalRateLimiter) {
      const rlResult = this.globalRateLimiter.check(callerId);
      if (!rlResult.allowed) {
        sendRateLimited(res, rlResult.info);
        return;
      }
      setRateLimitHeaders(res, rlResult.info);
    }

    if (!gatewayResult.allowed) {
      // Per-server rate-limit denial from gateway uses 429
      const statusCode = gatewayResult.decision === 'deny-rate-limit' ? 429 : 403;
      res.writeHead(statusCode, { 'Content-Type': 'application/json' });
      if (statusCode === 429) {
        res.setHeader('Retry-After', '60');
      }
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: jsonRpc.id,
        error: {
          code: -32600,
          message: `Trust gateway denied: ${gatewayResult.reason}`,
          data: {
            decision: gatewayResult.decision,
            trustScore: gatewayResult.trustScore,
            grade: gatewayResult.grade,
          },
        },
      }));

      // Notify SSE clients
      const sessionId = url.searchParams.get('sessionId');
      if (sessionId) {
        const client = [...this.sseClients].find(c => c.id === sessionId);
        if (client) {
          this.sendSSEEvent(client, {
            jsonrpc: '2.0',
            id: jsonRpc.id,
            error: { code: -32600, message: `Trust gateway denied: ${gatewayResult.reason}` },
          });
        }
      }
      return;
    }

    // ── Forward to upstream ──
    try {
      const upstream = this.findUpstream(serverName);
      const upstreamResult = await this.forwardToUpstream(upstream, serverName, jsonRpc);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(upstreamResult));

      // Notify SSE clients
      const sessionId = url.searchParams.get('sessionId');
      if (sessionId) {
        const client = [...this.sseClients].find(c => c.id === sessionId);
        if (client) {
          this.sendSSEEvent(client, upstreamResult);
        }
      }
    } catch (err) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: jsonRpc.id,
        error: { code: -32603, message: `Upstream error: ${(err as Error).message}` },
      }));
    }
  }

  // ─── Upstream Management ─────────────────────────────────────────

  private findUpstream(serverName: string): ServerPolicy {
    const server = this.config.servers.find(s => s.name === serverName);
    if (!server) throw new Error(`Unknown server: ${serverName}`);
    return server;
  }

  private async forwardToUpstream(
    server: ServerPolicy,
    serverName: string,
    jsonRpc: unknown
  ): Promise<unknown> {
    if (server.upstream.startsWith('stdio://')) {
      return this.forwardStdio(serverName, jsonRpc);
    } else {
      return this.forwardHttp(server.upstream, jsonRpc);
    }
  }

  // ─── HTTP Upstream ───────────────────────────────────────────────

  private async forwardHttp(upstream: string, jsonRpc: unknown): Promise<unknown> {
    // Resolve message endpoint from upstream URL
    const baseUrl = upstream.replace(/\/sse$/, '');
    const messageUrl = `${baseUrl}/message`;

    const response = await fetch(messageUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(jsonRpc),
      signal: AbortSignal.timeout(30_000),
    });

    if (!response.ok) {
      throw new Error(`Upstream returned ${response.status}`);
    }

    return response.json();
  }

  // ─── Stdio Upstream ──────────────────────────────────────────────

  private connectStdio(server: ServerPolicy): void {
    const command = server.upstream.replace('stdio://', '');
    const parts = command.split(' ');
    const proc = spawn(parts[0], parts.slice(1), {
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const upstream: StdioUpstream = {
      process: proc,
      pending: new Map(),
      buffer: '',
    };

    proc.stdout!.on('data', (chunk: Buffer) => {
      upstream.buffer += chunk.toString();
      // Process complete JSON-RPC messages (newline-delimited)
      const lines = upstream.buffer.split('\n');
      upstream.buffer = lines.pop() ?? '';

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const msg = JSON.parse(line);
          if (msg.id !== undefined && upstream.pending.has(msg.id)) {
            const { resolve } = upstream.pending.get(msg.id)!;
            upstream.pending.delete(msg.id);
            resolve(msg);
          }
        } catch {
          // Ignore malformed lines
        }
      }
    });

    proc.on('error', (err) => {
      for (const [, { reject }] of upstream.pending) {
        reject(err);
      }
      upstream.pending.clear();
    });

    proc.on('exit', () => {
      for (const [, { reject }] of upstream.pending) {
        reject(new Error('Process exited'));
      }
      upstream.pending.clear();
      this.stdioUpstreams.delete(server.name);
    });

    this.stdioUpstreams.set(server.name, upstream);
  }

  private forwardStdio(serverName: string, jsonRpc: unknown): Promise<unknown> {
    const upstream = this.stdioUpstreams.get(serverName);
    if (!upstream) throw new Error(`No stdio connection for server: ${serverName}`);

    return new Promise((resolve, reject) => {
      const msg = jsonRpc as { id?: string | number };
      const id = msg.id ?? randomUUID();

      const timer = setTimeout(() => {
        upstream.pending.delete(id);
        reject(new Error('Stdio upstream timeout'));
      }, 30_000);

      upstream.pending.set(id, {
        resolve: (data) => { clearTimeout(timer); resolve(data); },
        reject: (err) => { clearTimeout(timer); reject(err); },
      });

      upstream.process.stdin!.write(JSON.stringify(jsonRpc) + '\n');
    });
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const MAX_BODY = 1_048_576; // 1 MB

    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new Error('Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}

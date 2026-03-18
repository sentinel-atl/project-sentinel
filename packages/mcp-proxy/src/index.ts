/**
 * @sentinel-atl/mcp-proxy — Real MCP Transport Proxy
 *
 * A network proxy that intercepts MCP stdio/SSE traffic, applies
 * Sentinel trust checks, and forwards to the upstream MCP server.
 *
 * Deployment:
 *   npx sentinel-proxy --listen 3100 --upstream stdio://node my-mcp-server.js
 *   npx sentinel-proxy --listen 3100 --upstream http://localhost:3000/sse
 *
 * Works with Claude Desktop, Cursor, and any MCP client. Clients connect
 * to the proxy via SSE; the proxy connects to the upstream via stdio or SSE.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { spawn, type ChildProcess } from 'node:child_process';
import { createInterface } from 'node:readline';
import { randomUUID } from 'node:crypto';

// ─── Types ───────────────────────────────────────────────────────────

export interface ProxyConfig {
  /** Port to listen on (default: 3100) */
  port: number;
  /** Upstream MCP server connection string */
  upstream: string;
  /** Blocked tools (deny list) */
  blockedTools?: string[];
  /** Rate limit per caller per minute (default: 100) */
  rateLimit?: number;
  /** Enable audit logging (default: true) */
  enableAudit?: boolean;
  /** Enable content safety checks (default: false) */
  enableSafety?: boolean;
  /** CORS origin (default: '*') */
  corsOrigin?: string;
}

export interface MCPMessage {
  jsonrpc: '2.0';
  id?: string | number;
  method?: string;
  params?: any;
  result?: any;
  error?: any;
}

export interface ProxyStats {
  totalRequests: number;
  blockedRequests: number;
  activeConnections: number;
  uptime: number;
  byTool: Record<string, { calls: number; blocked: number }>;
}

// ─── Rate Limiter ────────────────────────────────────────────────────

class SlidingWindowRateLimiter {
  private windows = new Map<string, number[]>();
  private maxRequests: number;
  private windowMs: number;

  constructor(maxRequests: number, windowMs = 60_000) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
  }

  check(key: string): boolean {
    const now = Date.now();
    const timestamps = this.windows.get(key)?.filter(t => now - t < this.windowMs) ?? [];
    this.windows.set(key, timestamps);
    if (timestamps.length >= this.maxRequests) return false;
    timestamps.push(now);
    return true;
  }
}

// ─── Stdio Transport ─────────────────────────────────────────────────

class StdioTransport {
  private process: ChildProcess;
  private pending = new Map<string | number, (msg: MCPMessage) => void>();
  private notificationHandler?: (msg: MCPMessage) => void;

  constructor(command: string, args: string[]) {
    this.process = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'inherit'],
    });

    const rl = createInterface({ input: this.process.stdout! });
    let buffer = '';

    rl.on('line', (line) => {
      // MCP stdio uses newline-delimited JSON
      try {
        const msg: MCPMessage = JSON.parse(line);
        if (msg.id !== undefined && this.pending.has(msg.id)) {
          const resolve = this.pending.get(msg.id)!;
          this.pending.delete(msg.id);
          resolve(msg);
        } else if (msg.method && this.notificationHandler) {
          this.notificationHandler(msg);
        }
      } catch {
        // Not JSON — append to buffer for content-length framing
        buffer += line + '\n';
        try {
          const msg: MCPMessage = JSON.parse(buffer);
          buffer = '';
          if (msg.id !== undefined && this.pending.has(msg.id)) {
            const resolve = this.pending.get(msg.id)!;
            this.pending.delete(msg.id);
            resolve(msg);
          }
        } catch { /* incomplete */ }
      }
    });
  }

  async send(msg: MCPMessage): Promise<MCPMessage> {
    return new Promise((resolve, reject) => {
      const id = msg.id ?? randomUUID();
      const fullMsg = { ...msg, id };
      this.pending.set(id, resolve);

      const data = JSON.stringify(fullMsg) + '\n';
      this.process.stdin!.write(data, (err) => {
        if (err) {
          this.pending.delete(id);
          reject(err);
        }
      });

      // Timeout after 30s
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`MCP request timed out (id: ${id})`));
        }
      }, 30_000);
    });
  }

  onNotification(handler: (msg: MCPMessage) => void): void {
    this.notificationHandler = handler;
  }

  async close(): Promise<void> {
    this.process.kill('SIGTERM');
  }
}

// ─── HTTP/SSE Transport ──────────────────────────────────────────────

class SSETransport {
  private baseUrl: string;

  constructor(url: string) {
    this.baseUrl = url.replace(/\/sse$/, '');
  }

  async send(msg: MCPMessage): Promise<MCPMessage> {
    const response = await fetch(`${this.baseUrl}/message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(msg),
    });
    return response.json() as Promise<MCPMessage>;
  }

  onNotification(_handler: (msg: MCPMessage) => void): void {
    // SSE notifications come from the event stream
  }

  async close(): Promise<void> {
    // Nothing to clean up for HTTP transport
  }
}

// ─── Audit Logger (simple JSONL) ─────────────────────────────────────

class ProxyAuditLog {
  private entries: Array<{
    timestamp: string;
    method: string;
    tool?: string;
    clientId: string;
    allowed: boolean;
    reason?: string;
    latencyMs: number;
  }> = [];

  log(entry: {
    method: string;
    tool?: string;
    clientId: string;
    allowed: boolean;
    reason?: string;
    latencyMs: number;
  }) {
    this.entries.push({ timestamp: new Date().toISOString(), ...entry });
  }

  getEntries(limit = 100) {
    return this.entries.slice(-limit);
  }

  getStats(): { total: number; blocked: number; byTool: Record<string, { calls: number; blocked: number }> } {
    const byTool: Record<string, { calls: number; blocked: number }> = {};
    let blocked = 0;
    for (const e of this.entries) {
      if (!e.allowed) blocked++;
      if (e.tool) {
        const t = byTool[e.tool] ?? { calls: 0, blocked: 0 };
        t.calls++;
        if (!e.allowed) t.blocked++;
        byTool[e.tool] = t;
      }
    }
    return { total: this.entries.length, blocked, byTool };
  }
}

// ─── MCP Security Proxy ──────────────────────────────────────────────

export class MCPSecurityProxy {
  private config: Required<ProxyConfig>;
  private transport: StdioTransport | SSETransport | null = null;
  private server: ReturnType<typeof createServer> | null = null;
  private rateLimiter: SlidingWindowRateLimiter;
  private auditLog = new ProxyAuditLog();
  private startTime = Date.now();
  private sseClients = new Map<string, ServerResponse>();

  constructor(config: ProxyConfig) {
    this.config = {
      port: config.port,
      upstream: config.upstream,
      blockedTools: config.blockedTools ?? [],
      rateLimit: config.rateLimit ?? 100,
      enableAudit: config.enableAudit ?? true,
      enableSafety: config.enableSafety ?? false,
      corsOrigin: config.corsOrigin ?? '*',
    };
    this.rateLimiter = new SlidingWindowRateLimiter(this.config.rateLimit);
  }

  /**
   * Start the proxy server.
   */
  async start(): Promise<void> {
    // Connect to upstream
    if (this.config.upstream.startsWith('stdio://')) {
      const cmd = this.config.upstream.slice('stdio://'.length);
      const parts = cmd.split(' ');
      this.transport = new StdioTransport(parts[0], parts.slice(1));
    } else if (this.config.upstream.startsWith('http://') || this.config.upstream.startsWith('https://')) {
      this.transport = new SSETransport(this.config.upstream);
    } else {
      throw new Error(`Unsupported upstream: ${this.config.upstream}. Use stdio:// or http(s)://`);
    }

    // Forward notifications from upstream to all SSE clients
    this.transport.onNotification((msg) => {
      for (const [, res] of this.sseClients) {
        res.write(`data: ${JSON.stringify(msg)}\n\n`);
      }
    });

    // Start HTTP server for client connections
    this.server = createServer(async (req, res) => {
      // CORS
      res.setHeader('Access-Control-Allow-Origin', this.config.corsOrigin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      const url = new URL(req.url ?? '/', `http://localhost:${this.config.port}`);

      try {
        if (url.pathname === '/sse' && req.method === 'GET') {
          await this.handleSSE(req, res);
        } else if (url.pathname === '/message' && req.method === 'POST') {
          await this.handleMessage(req, res);
        } else if (url.pathname === '/health' && req.method === 'GET') {
          this.handleHealth(res);
        } else if (url.pathname === '/stats' && req.method === 'GET') {
          this.handleStats(res);
        } else if (url.pathname === '/audit' && req.method === 'GET') {
          this.handleAuditEndpoint(res);
        } else {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Not found' }));
        }
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: (err as Error).message }));
      }
    });

    return new Promise((resolve) => {
      this.server!.listen(this.config.port, () => {
        resolve();
      });
    });
  }

  /**
   * Stop the proxy.
   */
  async stop(): Promise<void> {
    // Close SSE connections
    for (const [, res] of this.sseClients) {
      res.end();
    }
    this.sseClients.clear();

    // Close upstream transport
    if (this.transport) {
      await this.transport.close();
    }

    // Close HTTP server
    if (this.server) {
      return new Promise((resolve) => {
        this.server!.close(() => resolve());
      });
    }
  }

  /**
   * Get proxy stats.
   */
  getStats(): ProxyStats {
    const auditStats = this.auditLog.getStats();
    return {
      totalRequests: auditStats.total,
      blockedRequests: auditStats.blocked,
      activeConnections: this.sseClients.size,
      uptime: Date.now() - this.startTime,
      byTool: auditStats.byTool,
    };
  }

  // ─── Request Handlers ────────────────────────────────────────────

  private async handleSSE(_req: IncomingMessage, res: ServerResponse): Promise<void> {
    const clientId = randomUUID();
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    });

    // Send endpoint event (MCP SSE handshake)
    res.write(`event: endpoint\ndata: /message?clientId=${clientId}\n\n`);
    this.sseClients.set(clientId, res);

    res.on('close', () => {
      this.sseClients.delete(clientId);
    });
  }

  private async handleMessage(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://localhost:${this.config.port}`);
    const clientId = url.searchParams.get('clientId') ?? 'unknown';
    const start = Date.now();

    // Read body
    const body = await this.readBody(req);
    let msg: MCPMessage;
    try {
      msg = JSON.parse(body);
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
      return;
    }

    // Rate limit check
    if (!this.rateLimiter.check(clientId)) {
      this.auditLog.log({
        method: msg.method ?? 'unknown',
        tool: this.extractToolName(msg),
        clientId,
        allowed: false,
        reason: 'Rate limit exceeded',
        latencyMs: Date.now() - start,
      });
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        error: { code: -32000, message: 'Rate limit exceeded' },
      }));
      return;
    }

    // Tool blocking check
    const toolName = this.extractToolName(msg);
    if (toolName && this.config.blockedTools.includes(toolName)) {
      this.auditLog.log({
        method: msg.method ?? 'unknown',
        tool: toolName,
        clientId,
        allowed: false,
        reason: `Tool '${toolName}' is blocked`,
        latencyMs: Date.now() - start,
      });
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        error: { code: -32000, message: `Tool '${toolName}' is blocked by security policy` },
      }));
      return;
    }

    // Forward to upstream
    try {
      const response = await this.transport!.send(msg);

      this.auditLog.log({
        method: msg.method ?? 'unknown',
        tool: toolName ?? undefined,
        clientId,
        allowed: true,
        latencyMs: Date.now() - start,
      });

      // Also send via SSE if client is connected
      const sseClient = this.sseClients.get(clientId);
      if (sseClient) {
        sseClient.write(`data: ${JSON.stringify(response)}\n\n`);
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(response));
    } catch (err) {
      this.auditLog.log({
        method: msg.method ?? 'unknown',
        tool: toolName ?? undefined,
        clientId,
        allowed: true,
        reason: `Upstream error: ${(err as Error).message}`,
        latencyMs: Date.now() - start,
      });
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: msg.id,
        error: { code: -32000, message: `Upstream error: ${(err as Error).message}` },
      }));
    }
  }

  private handleHealth(res: ServerResponse): void {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'healthy',
      uptime: Date.now() - this.startTime,
      connections: this.sseClients.size,
    }));
  }

  private handleStats(res: ServerResponse): void {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(this.getStats()));
  }

  private handleAuditEndpoint(res: ServerResponse): void {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(this.auditLog.getEntries(200)));
  }

  // ─── Helpers ─────────────────────────────────────────────────────

  private extractToolName(msg: MCPMessage): string | undefined {
    if (msg.method === 'tools/call' && msg.params?.name) {
      return msg.params.name;
    }
    return undefined;
  }

  private readBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      const MAX_BODY = 1_048_576; // 1MB
      req.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_BODY) {
          reject(new Error('Request body too large'));
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
      req.on('error', reject);
    });
  }
}

// ─── Convenience: createProxy ────────────────────────────────────────

export async function createProxy(config: ProxyConfig): Promise<MCPSecurityProxy> {
  const proxy = new MCPSecurityProxy(config);
  await proxy.start();
  return proxy;
}

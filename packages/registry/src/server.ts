/**
 * Trust Registry HTTP API — REST endpoints for publishing and querying STCs.
 *
 * Endpoints:
 *   POST   /api/v1/certificates          Register a new STC
 *   GET    /api/v1/certificates/:id       Get certificate by ID
 *   GET    /api/v1/certificates           Query certificates
 *   DELETE /api/v1/certificates/:id       Remove a certificate
 *
 *   GET    /api/v1/packages/:name         Get latest certificate for a package
 *   GET    /api/v1/packages/:name/history Get all certificates for a package
 *   GET    /api/v1/packages/:name/badge   SVG badge for a package
 *   GET    /api/v1/packages/:name/badge/score   Score badge
 *
 *   GET    /api/v1/stats                  Registry stats
 *   GET    /health                        Health check
 */

import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { CertificateStore, type RegistryEntry } from './store.js';
import { gradeBadge, scoreBadge, verifiedBadge, notFoundBadge, type BadgeStyle } from './badge.js';
import {
  authenticate, hasScope, sendUnauthorized, sendForbidden,
  applyCors, defaultCorsConfig,
  createSecureServer,
  type AuthConfig, type CorsConfig, type TlsConfig,
} from '@sentinel-atl/hardening';
import type { SentinelTrustCertificate } from '@sentinel-atl/scanner';

// ─── Types ───────────────────────────────────────────────────────────

export interface RegistryServerOptions {
  /** Port to listen on */
  port?: number;
  /** Pre-configured certificate store */
  store?: CertificateStore;
  /** API key authentication config */
  auth?: AuthConfig;
  /** CORS configuration */
  cors?: CorsConfig;
  /** TLS configuration */
  tls?: TlsConfig;
}

// ─── Server ──────────────────────────────────────────────────────────

export class RegistryServer {
  private server: Server | null = null;
  private store: CertificateStore;
  private port: number;
  private authConfig: AuthConfig;
  private corsConfig: CorsConfig;
  private tlsConfig?: TlsConfig;

  constructor(options?: RegistryServerOptions) {
    this.port = options?.port ?? 3200;
    this.store = options?.store ?? new CertificateStore();
    this.authConfig = options?.auth ?? { enabled: false, keys: [] };
    this.corsConfig = options?.cors ?? defaultCorsConfig();
    this.tlsConfig = options?.tls;

    // Badge endpoints are always public (for README embeds)
    if (this.authConfig.enabled && !this.authConfig.publicPaths) {
      this.authConfig.publicPaths = ['/health'];
    }
  }

  getStore(): CertificateStore {
    return this.store;
  }

  async start(): Promise<{ port: number }> {
    return new Promise((resolve, reject) => {
      this.server = createSecureServer(
        (req, res) => this.handleRequest(req, res),
        this.tlsConfig
      );
      this.server.on('error', reject);
      this.server.listen(this.port, () => {
        resolve({ port: this.port });
      });
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  isTLS(): boolean {
    return !!this.tlsConfig?.certPath || !!this.tlsConfig?.cert;
  }

  // ─── Router ────────────────────────────────────────────────────

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://localhost`);
    const path = url.pathname;
    const method = req.method ?? 'GET';

    // CORS (configurable origins)
    if (applyCors(req, res, this.corsConfig)) return; // preflight handled

    // Authentication
    const authResult = authenticate(req, this.authConfig);

    // Badge endpoints are public even when auth is enabled
    const isBadgePath = path.includes('/badge');
    if (!authResult.authenticated && !isBadgePath) {
      return sendUnauthorized(res, this.authConfig, authResult.error);
    }

    try {
      // Health
      if (path === '/health' && method === 'GET') {
        return this.sendJson(res, 200, { status: 'ok', certificates: this.store.count() });
      }

      // Stats
      if (path === '/api/v1/stats' && method === 'GET') {
        return this.sendJson(res, 200, this.store.getStats());
      }

      // POST /api/v1/certificates — register (requires write scope)
      if (path === '/api/v1/certificates' && method === 'POST') {
        if (!hasScope(authResult, 'write')) return sendForbidden(res, 'Write scope required');
        return await this.handleRegister(req, res);
      }

      // GET /api/v1/certificates — query
      if (path === '/api/v1/certificates' && method === 'GET') {
        return this.handleQuery(url, res);
      }

      // GET/DELETE /api/v1/certificates/:id
      const certMatch = path.match(/^\/api\/v1\/certificates\/(.+)$/);
      if (certMatch) {
        const id = decodeURIComponent(certMatch[1]);
        if (method === 'GET') return this.handleGetById(id, res);
        if (method === 'DELETE') {
          if (!hasScope(authResult, 'admin')) return sendForbidden(res, 'Admin scope required');
          return this.handleDelete(id, res);
        }
      }

      // Package routes: /api/v1/packages/:name[/history|/badge|/badge/score]
      const pkgMatch = path.match(/^\/api\/v1\/packages\/(@[^/]+\/[^/]+|[^/]+)(\/.*)?$/);
      if (pkgMatch) {
        const packageName = decodeURIComponent(pkgMatch[1]);
        const suffix = pkgMatch[2] ?? '';

        if (suffix === '' && method === 'GET') return this.handleGetPackage(packageName, res);
        if (suffix === '/history' && method === 'GET') return this.handlePackageHistory(packageName, res);
        if (suffix === '/badge' && method === 'GET') return this.handleBadge(packageName, url, res);
        if (suffix === '/badge/score' && method === 'GET') return this.handleScoreBadge(packageName, url, res);
      }

      this.sendJson(res, 404, { error: 'Not found' });
    } catch (err) {
      this.sendJson(res, 500, { error: 'Internal server error' });
    }
  }

  // ─── Handlers ──────────────────────────────────────────────────

  private async handleRegister(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readBody(req);
    let certificate: SentinelTrustCertificate;

    try {
      certificate = JSON.parse(body);
    } catch {
      return this.sendJson(res, 400, { error: 'Invalid JSON' });
    }

    if (!certificate.id || !certificate.type || certificate.type !== 'SentinelTrustCertificate') {
      return this.sendJson(res, 400, { error: 'Invalid STC: missing id or type' });
    }

    // Check for duplicates
    if (this.store.get(certificate.id)) {
      return this.sendJson(res, 409, { error: 'Certificate already registered', id: certificate.id });
    }

    const entry = await this.store.register(certificate);

    this.sendJson(res, 201, {
      id: entry.id,
      packageName: entry.packageName,
      trustScore: entry.trustScore,
      grade: entry.grade,
      verified: entry.verified,
      registeredAt: entry.registeredAt,
    });
  }

  private handleGetById(id: string, res: ServerResponse): void {
    const entry = this.store.get(id);
    if (!entry) {
      return this.sendJson(res, 404, { error: 'Certificate not found' });
    }
    this.sendJson(res, 200, this.formatEntry(entry));
  }

  private handleDelete(id: string, res: ServerResponse): void {
    const removed = this.store.remove(id);
    if (!removed) {
      return this.sendJson(res, 404, { error: 'Certificate not found' });
    }
    this.sendJson(res, 200, { deleted: true, id });
  }

  private handleQuery(url: URL, res: ServerResponse): void {
    const q = {
      packageName: url.searchParams.get('package') ?? undefined,
      minScore: url.searchParams.has('minScore') ? parseInt(url.searchParams.get('minScore')!) : undefined,
      minGrade: url.searchParams.get('minGrade') ?? undefined,
      verified: url.searchParams.has('verified') ? url.searchParams.get('verified') === 'true' : undefined,
      limit: url.searchParams.has('limit') ? parseInt(url.searchParams.get('limit')!) : undefined,
      offset: url.searchParams.has('offset') ? parseInt(url.searchParams.get('offset')!) : undefined,
    };

    const results = this.store.query(q);
    this.sendJson(res, 200, {
      total: this.store.count(),
      count: results.length,
      certificates: results.map(e => this.formatEntry(e)),
    });
  }

  private handleGetPackage(packageName: string, res: ServerResponse): void {
    const entry = this.store.getLatestForPackage(packageName);
    if (!entry) {
      return this.sendJson(res, 404, { error: 'No certificates found for package', packageName });
    }
    this.sendJson(res, 200, this.formatEntry(entry));
  }

  private handlePackageHistory(packageName: string, res: ServerResponse): void {
    const entries = this.store.getForPackage(packageName);
    this.sendJson(res, 200, {
      packageName,
      count: entries.length,
      certificates: entries.map(e => this.formatEntry(e)),
    });
  }

  private handleBadge(packageName: string, url: URL, res: ServerResponse): void {
    const style = (url.searchParams.get('style') ?? 'flat') as BadgeStyle;
    const entry = this.store.getLatestForPackage(packageName);

    let svg: string;
    if (!entry) {
      svg = notFoundBadge(style);
    } else if (entry.verified) {
      svg = gradeBadge(entry.grade, style);
    } else {
      svg = verifiedBadge(false, style);
    }

    res.writeHead(200, {
      'Content-Type': 'image/svg+xml',
      'Cache-Control': 'max-age=300',
    });
    res.end(svg);
  }

  private handleScoreBadge(packageName: string, url: URL, res: ServerResponse): void {
    const style = (url.searchParams.get('style') ?? 'flat') as BadgeStyle;
    const entry = this.store.getLatestForPackage(packageName);

    let svg: string;
    if (!entry) {
      svg = notFoundBadge(style);
    } else {
      svg = scoreBadge(entry.trustScore, style);
    }

    res.writeHead(200, {
      'Content-Type': 'image/svg+xml',
      'Cache-Control': 'max-age=300',
    });
    res.end(svg);
  }

  // ─── Helpers ───────────────────────────────────────────────────

  private formatEntry(entry: RegistryEntry) {
    return {
      id: entry.id,
      packageName: entry.packageName,
      packageVersion: entry.packageVersion,
      trustScore: entry.trustScore,
      grade: entry.grade,
      verified: entry.verified,
      registeredAt: entry.registeredAt,
      issuerDid: entry.issuerDid,
      certificate: entry.certificate,
    };
  }

  private sendJson(res: ServerResponse, status: number, data: unknown): void {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
  }
}

// ─── Body Reader ──────────────────────────────────────────────────────

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const MAX_BODY = 2_097_152; // 2 MB (STC max)

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

/**
 * @sentinel/server — STP-Compliant HTTP Server
 *
 * Exposes the full Sentinel Trust Protocol as a language-agnostic REST API.
 * Any language or framework can authenticate agents, verify credentials,
 * query reputation, and audit actions over HTTP.
 *
 * Zero external dependencies — uses Node.js built-in `http` module.
 *
 * Usage:
 *   const server = await createSTPServer({ name: 'my-trust-server', port: 3100 });
 *   await server.start();
 *   // Server is now at http://localhost:3100
 *   // Discovery: GET http://localhost:3100/.well-known/sentinel-configuration
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'node:http';
import {
  createIdentity,
  InMemoryKeyProvider,
  verifySTPToken,
  createSTPToken,
  issueVC,
  verifyVC,
  resolveDid,
  didToPublicKey,
  createIntent,
  validateIntent,
  type KeyProvider,
  type AgentIdentity,
  type VerifiableCredential,
  type IssueVCOptions,
  type CredentialType,
  type SensitivityLevel,
  type IntentEnvelope,
} from '@sentinel/core';
import { AuditLog } from '@sentinel/audit';
import { ReputationEngine, type ReputationScore } from '@sentinel/reputation';
import { RevocationManager, type RevocationReason } from '@sentinel/revocation';
import { SafetyPipeline, RegexClassifier, type ContentClassifier } from '@sentinel/safety';

// ─── Types ───────────────────────────────────────────────────────────

export interface STPServerConfig {
  /** Server name */
  name: string;
  /** Port to listen on (default: 3100) */
  port?: number;
  /** Hostname (default: '0.0.0.0') */
  hostname?: string;
  /** Base URL for self-referencing (auto-detected if not set) */
  baseUrl?: string;
  /** Custom KeyProvider */
  keyProvider?: KeyProvider;
  /** Minimum reputation for access (default: 0) */
  minReputation?: number;
  /** Enable content safety */
  enableSafety?: boolean;
  /** Custom safety classifiers */
  safetyClassifiers?: ContentClassifier[];
  /** Capabilities to expose (default: all) */
  capabilities?: string[];
  /** CORS allowed origins (default: ['*']) */
  corsOrigins?: string[];
}

export interface STPServer {
  /** Server's DID */
  readonly did: string;
  /** Server's key ID */
  readonly keyId: string;
  /** Start listening */
  start(): Promise<void>;
  /** Stop listening */
  stop(): Promise<void>;
  /** Get the Node.js HTTP server (for testing or custom middleware) */
  getHttpServer(): Server;
  /** Get the server's KeyProvider (for issuing tokens/credentials) */
  getKeyProvider(): KeyProvider;
  /** Get the audit log */
  getAuditLog(): AuditLog;
  /** Get the reputation engine */
  getReputationEngine(): ReputationEngine;
  /** Get the revocation manager */
  getRevocationManager(): RevocationManager;
}

interface RouteHandler {
  (req: IncomingMessage, res: ServerResponse, body: unknown): Promise<void>;
}

// ─── Helpers ─────────────────────────────────────────────────────────

function jsonResponse(res: ServerResponse, status: number, data: unknown): void {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function errorResponse(res: ServerResponse, status: number, code: string, message: string, details?: unknown): void {
  jsonResponse(res, status, { error: { code, message, ...(details ? { details } : {}) } });
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const MAX_BODY = 1_048_576; // 1 MB
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        req.destroy();
        reject(new Error('Body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf-8');
      if (!raw) { resolve(undefined); return; }
      try { resolve(JSON.parse(raw)); } catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

// ─── Server Implementation ───────────────────────────────────────────

class STPServerImpl implements STPServer {
  readonly did: string;
  readonly keyId: string;

  private httpServer: Server;
  private config: Required<Pick<STPServerConfig, 'name' | 'port' | 'hostname' | 'corsOrigins'>> & STPServerConfig;
  private keyProvider: KeyProvider;
  private auditLog: AuditLog;
  private reputationEngine: ReputationEngine;
  private revocationManager: RevocationManager;
  private safetyPipeline: SafetyPipeline | undefined;
  private seenNonces = new Set<string>();
  private routes = new Map<string, RouteHandler>();
  private identities = new Map<string, AgentIdentity>();

  constructor(
    identity: AgentIdentity,
    keyProvider: KeyProvider,
    auditLog: AuditLog,
    reputationEngine: ReputationEngine,
    revocationManager: RevocationManager,
    safetyPipeline: SafetyPipeline | undefined,
    config: STPServerConfig
  ) {
    this.did = identity.did;
    this.keyId = identity.keyId;
    this.keyProvider = keyProvider;
    this.auditLog = auditLog;
    this.reputationEngine = reputationEngine;
    this.revocationManager = revocationManager;
    this.safetyPipeline = safetyPipeline;
    this.config = {
      ...config,
      port: config.port ?? 3100,
      hostname: config.hostname ?? '0.0.0.0',
      corsOrigins: config.corsOrigins ?? ['*'],
    };

    this.identities.set(identity.did, identity);

    // Build routes
    this.registerRoutes();

    // Create HTTP server
    this.httpServer = createServer(async (req, res) => {
      await this.handleRequest(req, res);
    });
  }

  // ─── Lifecycle ───────────────────────────────────────────────

  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.httpServer.listen(this.config.port, this.config.hostname, () => {
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.httpServer.close((err) => {
        if (err) reject(err); else resolve();
      });
    });
  }

  getHttpServer(): Server { return this.httpServer; }
  getKeyProvider(): KeyProvider { return this.keyProvider; }
  getAuditLog(): AuditLog { return this.auditLog; }
  getReputationEngine(): ReputationEngine { return this.reputationEngine; }
  getRevocationManager(): RevocationManager { return this.revocationManager; }

  // ─── Request Handling ────────────────────────────────────────

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // CORS
    const origin = req.headers.origin ?? '*';
    const allowedOrigins = this.config.corsOrigins;
    if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const method = req.method ?? 'GET';
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const routeKey = `${method} ${url.pathname}`;

    // Check for parameterized routes
    const handler = this.findRoute(method, url.pathname);

    if (!handler) {
      errorResponse(res, 404, 'NOT_FOUND', `No route for ${routeKey}`);
      return;
    }

    try {
      let body: unknown;
      if (method === 'POST') {
        body = await readBody(req);
      }
      await handler.fn(req, res, body);
    } catch (e) {
      errorResponse(res, 500, 'INTERNAL_ERROR', (e as Error).message);
    }
  }

  private findRoute(method: string, pathname: string): { fn: RouteHandler; params: Record<string, string> } | null {
    // Exact match first
    const exact = this.routes.get(`${method} ${pathname}`);
    if (exact) return { fn: exact, params: {} };

    // Parameterized match
    for (const [pattern, handler] of this.routes) {
      const [routeMethod, routePath] = pattern.split(' ', 2);
      if (routeMethod !== method) continue;

      const routeParts = routePath.split('/');
      const pathParts = pathname.split('/');
      if (routeParts.length !== pathParts.length) continue;

      const params: Record<string, string> = {};
      let match = true;
      for (let i = 0; i < routeParts.length; i++) {
        if (routeParts[i].startsWith(':')) {
          params[routeParts[i].slice(1)] = pathParts[i];
        } else if (routeParts[i] !== pathParts[i]) {
          match = false;
          break;
        }
      }
      if (match) return { fn: handler, params };
    }

    return null;
  }

  // ─── Auth Middleware ─────────────────────────────────────────

  private async authenticateRequest(req: IncomingMessage): Promise<{
    authenticated: boolean;
    did?: string;
    error?: string;
    code?: string;
  }> {
    const authHeader = req.headers.authorization;
    if (!authHeader) return { authenticated: false, error: 'No Authorization header', code: 'INVALID_SIGNATURE' };

    const [scheme, token] = authHeader.split(' ', 2);
    if (scheme !== 'STP' || !token) {
      return { authenticated: false, error: 'Expected Authorization: STP <token>', code: 'INVALID_SIGNATURE' };
    }

    const baseUrl = this.config.baseUrl ??
      `http://${this.config.hostname === '0.0.0.0' ? 'localhost' : this.config.hostname}:${this.config.port}`;
    const result = await verifySTPToken(token, this.seenNonces, baseUrl);

    if (!result.valid) {
      const code = result.error?.includes('expired') ? 'TOKEN_EXPIRED' :
                   result.error?.includes('replay') ? 'NONCE_REUSE' : 'INVALID_SIGNATURE';
      return { authenticated: false, error: result.error, code };
    }

    return { authenticated: true, did: result.payload!.iss };
  }

  // ─── Route Registration ─────────────────────────────────────

  private registerRoutes(): void {
    const capabilities = this.config.capabilities ?? [
      'identity', 'credentials', 'reputation', 'handshake',
      'intent', 'revocation', 'safety', 'audit', 'gateway',
    ];

    // Discovery
    this.routes.set('GET /.well-known/sentinel-configuration', async (_req, res) => {
      const baseUrl = this.config.baseUrl ??
        `http://${this.config.hostname === '0.0.0.0' ? 'localhost' : this.config.hostname}:${this.config.port}`;
      jsonResponse(res, 200, {
        issuer: baseUrl,
        protocol_version: 'STP/1.0',
        server_did: this.did,
        endpoints: {
          identity: '/v1/identity',
          credentials_issue: '/v1/credentials',
          credentials_verify: '/v1/credentials/verify',
          credentials_revoke: '/v1/credentials/revoke',
          reputation_query: '/v1/reputation',
          reputation_vouch: '/v1/reputation/vouch',
          handshake: '/v1/handshake',
          intent_create: '/v1/intents',
          intent_validate: '/v1/intents/validate',
          revocation_status: '/v1/revocation/status',
          revocation_list: '/v1/revocation/list',
          safety_check: '/v1/safety/check',
          audit: '/v1/audit',
          gateway: '/v1/gateway/verify',
        },
        supported_credential_types: [
          'AgentAuthorizationCredential', 'DelegationCredential',
          'ComplianceCredential', 'ReputationCredential',
          'NegativeReputationCredential', 'CodeAttestationCredential',
        ],
        supported_did_methods: ['did:key'],
        cryptographic_suites: ['Ed25519Signature2020'],
        reputation_algorithm: 'sentinel-weighted-decay-v1',
        safety_categories: [
          'prompt_injection', 'jailbreak', 'pii_exposure',
          'harmful_content', 'data_exfiltration',
        ],
        capabilities,
      });
    });

    // ─── Identity ──────────────────────────────────────────────

    if (capabilities.includes('identity')) {
      this.routes.set('POST /v1/identity', async (_req, res, body) => {
        const { label } = body as { label?: string } ?? {};
        const id = await createIdentity(this.keyProvider, label);
        this.identities.set(id.did, id);

        await this.auditLog.log({
          eventType: 'identity_created',
          actorDid: id.did,
          result: 'success',
          reason: `Identity created: ${label ?? id.keyId}`,
        });

        const publicKey = await this.keyProvider.getPublicKey(id.keyId);
        jsonResponse(res, 201, {
          did: id.did,
          keyId: id.keyId,
          publicKey: Buffer.from(publicKey).toString('base64url'),
          createdAt: id.createdAt,
        });
      });

      this.routes.set('GET /v1/identity/:did', async (req, res) => {
        const urlPath = new URL(req.url ?? '/', `http://${req.headers.host}`).pathname;
        const did = decodeURIComponent(urlPath.split('/').pop() ?? '');

        if (!did.startsWith('did:key:z6Mk')) {
          errorResponse(res, 400, 'INVALID_DID', `Cannot resolve DID: ${did}`);
          return;
        }

        try {
          didToPublicKey(did); // Validates the DID can be decoded
          const doc = resolveDid(did);
          jsonResponse(res, 200, doc);
        } catch {
          errorResponse(res, 400, 'INVALID_DID', `Cannot resolve DID: ${did}`);
        }
      });
    }

    // ─── Credentials ───────────────────────────────────────────

    if (capabilities.includes('credentials')) {
      this.routes.set('POST /v1/credentials', async (req, res, body) => {
        const auth = await this.authenticateRequest(req);
        if (!auth.authenticated) {
          errorResponse(res, 401, auth.code!, auth.error!);
          return;
        }

        const {
          type, subjectDid, scope, maxDelegationDepth,
          sensitivityLevel, expiresInMs,
        } = body as {
          type: CredentialType;
          subjectDid: string;
          scope?: string[];
          maxDelegationDepth?: number;
          sensitivityLevel?: SensitivityLevel;
          expiresInMs?: number;
        };

        // Find the issuer's identity
        const issuerIdentity = this.findIdentityByDid(auth.did!);
        if (!issuerIdentity) {
          errorResponse(res, 403, 'INVALID_DID', 'Issuer identity not managed by this server');
          return;
        }

        const vc = await issueVC(this.keyProvider, {
          type,
          issuerDid: issuerIdentity.did,
          issuerKeyId: issuerIdentity.keyId,
          subjectDid,
          scope,
          maxDelegationDepth,
          sensitivityLevel,
          expiresInMs,
        });

        await this.auditLog.log({
          eventType: 'vc_issued',
          actorDid: issuerIdentity.did,
          targetDid: subjectDid,
          result: 'success',
          reason: `Issued ${type}`,
        });

        jsonResponse(res, 201, vc);
      });

      this.routes.set('POST /v1/credentials/verify', async (_req, res, body) => {
        const { credential } = body as { credential: VerifiableCredential };
        if (!credential) {
          errorResponse(res, 400, 'INVALID_DID', 'Missing credential in request body');
          return;
        }

        const result = await verifyVC(credential);

        // Also check revocation
        const revoked = this.revocationManager.isVCRevoked(credential.id);

        jsonResponse(res, 200, {
          valid: result.valid && !revoked,
          checks: {
            ...result.checks,
            revocation: !revoked,
          },
          ...(result.error ? { error: result.error } : {}),
        });
      });

      this.routes.set('POST /v1/credentials/revoke', async (req, res, body) => {
        const auth = await this.authenticateRequest(req);
        if (!auth.authenticated) {
          errorResponse(res, 401, auth.code!, auth.error!);
          return;
        }

        const { credentialId, reason } = body as { credentialId: string; reason: RevocationReason };
        const identity = this.findIdentityByDid(auth.did!);
        if (!identity) {
          errorResponse(res, 403, 'INVALID_DID', 'Revoker identity not managed by this server');
          return;
        }

        await this.revocationManager.revokeVC(
          this.keyProvider, identity.keyId,
          identity.did, credentialId, reason
        );

        await this.auditLog.log({
          eventType: 'vc_revoked',
          actorDid: identity.did,
          result: 'success',
          reason: `Revoked ${credentialId}: ${reason}`,
        });

        jsonResponse(res, 200, { revoked: true, credentialId });
      });
    }

    // ─── Reputation ────────────────────────────────────────────

    if (capabilities.includes('reputation')) {
      this.routes.set('GET /v1/reputation/:did', async (req, res) => {
        const urlPath = new URL(req.url ?? '/', `http://${req.headers.host}`).pathname;
        const did = decodeURIComponent(urlPath.split('/').pop() ?? '');

        const score = this.reputationEngine.computeScore(did);
        jsonResponse(res, 200, score);
      });

      this.routes.set('POST /v1/reputation/vouch', async (req, res, body) => {
        const auth = await this.authenticateRequest(req);
        if (!auth.authenticated) {
          errorResponse(res, 401, auth.code!, auth.error!);
          return;
        }

        const { subjectDid, polarity, weight, reason } = body as {
          subjectDid: string;
          polarity: 'positive' | 'negative';
          weight: number;
          reason?: string;
        };

        if (auth.did === subjectDid) {
          errorResponse(res, 400, 'RATE_LIMITED', 'Self-vouching is not allowed');
          return;
        }

        const rateCheck = this.reputationEngine.checkVouchRateLimit(auth.did!, subjectDid);
        if (!rateCheck.allowed) {
          errorResponse(res, 429, 'RATE_LIMITED', rateCheck.reason ?? 'Rate limited');
          return;
        }

        this.reputationEngine.addVouch({
          voucherDid: auth.did!,
          subjectDid,
          polarity,
          weight: Math.min(1, Math.max(0, weight)),
          voucherVerified: true,
          reason: reason as import('@sentinel/core').NegativeReason | undefined,
          timestamp: new Date().toISOString(),
        });

        await this.auditLog.log({
          eventType: 'reputation_vouch',
          actorDid: auth.did!,
          targetDid: subjectDid,
          result: 'success',
          reason: `${polarity} vouch (weight: ${weight})`,
        });

        const newScore = this.reputationEngine.computeScore(subjectDid);
        jsonResponse(res, 201, { accepted: true, newScore: newScore.score });
      });
    }

    // ─── Intent ────────────────────────────────────────────────

    if (capabilities.includes('intent')) {
      this.routes.set('POST /v1/intents', async (req, res, body) => {
        const auth = await this.authenticateRequest(req);
        if (!auth.authenticated) {
          errorResponse(res, 401, auth.code!, auth.error!);
          return;
        }

        const { action, scope, principalDid, delegationChain, expiresInMs } = body as {
          action: string;
          scope: string[];
          principalDid: string;
          delegationChain?: string[];
          expiresInMs?: number;
        };

        const identity = this.findIdentityByDid(auth.did!);
        if (!identity) {
          errorResponse(res, 403, 'INVALID_DID', 'Agent identity not managed by this server');
          return;
        }

        const intent = await createIntent(this.keyProvider, {
          agentDid: identity.did,
          agentKeyId: identity.keyId,
          action,
          scope,
          principalDid,
          delegationChain: delegationChain ?? [],
          expiresInMs,
        });

        await this.auditLog.log({
          eventType: 'intent_created',
          actorDid: identity.did,
          result: 'success',
          reason: `Intent: ${action}`,
          metadata: { intentId: intent.intentId },
        });

        jsonResponse(res, 201, intent);
      });

      this.routes.set('POST /v1/intents/validate', async (_req, res, body) => {
        const { intent } = body as { intent: IntentEnvelope };
        if (!intent) {
          errorResponse(res, 400, 'INTENT_REQUIRED', 'Missing intent in request body');
          return;
        }

        const result = await validateIntent(intent, this.seenNonces);
        jsonResponse(res, 200, result);
      });
    }

    // ─── Revocation ────────────────────────────────────────────

    if (capabilities.includes('revocation')) {
      this.routes.set('GET /v1/revocation/status/:did', async (req, res) => {
        const urlPath = new URL(req.url ?? '/', `http://${req.headers.host}`).pathname;
        const did = decodeURIComponent(urlPath.split('/').pop() ?? '');

        const trustCheck = this.revocationManager.isTrusted(did);
        jsonResponse(res, 200, {
          did,
          trusted: trustCheck.trusted,
          didRevoked: !trustCheck.trusted,
          reason: trustCheck.reason,
        });
      });

      this.routes.set('GET /v1/revocation/list', async (_req, res) => {
        const list = await this.revocationManager.publishRevocationList(
          this.keyProvider, this.keyId, this.did
        );
        jsonResponse(res, 200, list);
      });

      this.routes.set('POST /v1/revocation/kill-switch', async (req, res, body) => {
        const auth = await this.authenticateRequest(req);
        if (!auth.authenticated) {
          errorResponse(res, 401, auth.code!, auth.error!);
          return;
        }

        const { targetDid, reason, cascade, downstreamDids } = body as {
          targetDid: string;
          reason: string;
          cascade?: boolean;
          downstreamDids?: string[];
        };

        const identity = this.findIdentityByDid(auth.did!);
        if (!identity) {
          errorResponse(res, 403, 'INVALID_DID', 'Activator identity not managed by this server');
          return;
        }

        const event = await this.revocationManager.killSwitch(
          this.keyProvider, identity.keyId,
          identity.did, targetDid, reason,
          { cascade: cascade ?? true, downstreamDids }
        );

        await this.auditLog.log({
          eventType: 'emergency_revoke',
          actorDid: identity.did,
          targetDid,
          result: 'success',
          reason,
        });

        jsonResponse(res, 200, event);
      });
    }

    // ─── Safety ────────────────────────────────────────────────

    if (capabilities.includes('safety') && this.safetyPipeline) {
      this.routes.set('POST /v1/safety/check', async (_req, res, body) => {
        const { text } = body as { text: string };
        if (!text) {
          errorResponse(res, 400, 'SAFETY_VIOLATION', 'Missing text in request body');
          return;
        }

        const result = await this.safetyPipeline!.check(text);
        jsonResponse(res, 200, result);
      });
    }

    // ─── Audit ─────────────────────────────────────────────────

    if (capabilities.includes('audit')) {
      this.routes.set('GET /v1/audit', async (_req, res) => {
        const entries = await this.auditLog.readAll();
        jsonResponse(res, 200, { entries, totalEntries: entries.length });
      });

      this.routes.set('POST /v1/audit/verify', async (_req, res) => {
        const result = await this.auditLog.verifyIntegrity();
        jsonResponse(res, 200, result);
      });
    }

    // ─── Token ─────────────────────────────────────────────────

    this.routes.set('POST /v1/token', async (_req, res, body) => {
      const { did, scope, audience, expiresInSec } = body as {
        did: string;
        scope?: string[];
        audience?: string;
        expiresInSec?: number;
      };

      const identity = this.findIdentityByDid(did);
      if (!identity) {
        errorResponse(res, 404, 'DID_NOT_FOUND', 'DID not managed by this server');
        return;
      }

      const token = await createSTPToken(this.keyProvider, {
        issuerDid: identity.did,
        keyId: identity.keyId,
        audience,
        scope,
        expiresInSec,
      });

      jsonResponse(res, 201, { token });
    });
  }

  // ─── Helpers ─────────────────────────────────────────────────

  private findIdentityByDid(did: string): AgentIdentity | undefined {
    return this.identities.get(did);
  }
}

// ─── Factory ─────────────────────────────────────────────────────────

/**
 * Create an STP-compliant HTTP server.
 *
 * @example
 * ```ts
 * const server = await createSTPServer({
 *   name: 'my-trust-server',
 *   port: 3100,
 *   enableSafety: true,
 * });
 * await server.start();
 * // Discovery at: GET http://localhost:3100/.well-known/sentinel-configuration
 * // Identity:     POST http://localhost:3100/v1/identity
 * // Credentials:  POST http://localhost:3100/v1/credentials
 * // Reputation:   GET  http://localhost:3100/v1/reputation/{did}
 * // ...
 * ```
 */
export async function createSTPServer(config: STPServerConfig): Promise<STPServer> {
  const keyProvider = config.keyProvider ?? new InMemoryKeyProvider();
  const identity = await createIdentity(keyProvider, `stp-server-${config.name}`);

  const auditLog = new AuditLog({ logPath: `stp-server-${config.name}-audit.jsonl` });
  await auditLog.init();

  const reputationEngine = new ReputationEngine();
  const revocationManager = new RevocationManager();

  let safetyPipeline: SafetyPipeline | undefined;
  if (config.enableSafety) {
    const classifiers = config.safetyClassifiers ?? [new RegexClassifier()];
    safetyPipeline = new SafetyPipeline({ classifiers });
  }

  await auditLog.log({
    eventType: 'identity_created',
    actorDid: identity.did,
    result: 'success',
    reason: `STP Server "${config.name}" initialized`,
  });

  return new STPServerImpl(
    identity,
    keyProvider,
    auditLog,
    reputationEngine,
    revocationManager,
    safetyPipeline,
    config
  );
}

// ─── Re-exports ──────────────────────────────────────────────────────

export type {
  VerifiableCredential,
  KeyProvider,
  IntentEnvelope,
  CredentialType,
  SensitivityLevel,
} from '@sentinel/core';
export type { ReputationScore } from '@sentinel/reputation';
export type { RevocationReason } from '@sentinel/revocation';

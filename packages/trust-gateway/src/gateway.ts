/**
 * Trust Gateway — runtime MCP request enforcement using YAML policies and STCs.
 *
 * For every incoming tool call, the gateway:
 * 1. Identifies which server policy applies
 * 2. Checks the server's STC trust score against the policy
 * 3. Enforces tool allow/block lists
 * 4. Applies rate limiting
 * 5. Logs the decision to the audit trail
 */

import { AuditLog } from '@sentinel-atl/audit';
import type { GatewayConfig, ServerPolicy, TrustRequirements } from './config.js';
import { TrustStore } from './trust-store.js';

// ─── Types ───────────────────────────────────────────────────────────

export interface GatewayRequest {
  /** Name of the server being called */
  serverName: string;
  /** Tool being invoked */
  toolName: string;
  /** Caller identifier */
  callerId: string;
  /** Tool call arguments (for logging) */
  arguments?: Record<string, unknown>;
}

export type TrustDecision =
  | 'allow'           // All checks passed
  | 'deny-no-cert'    // No certificate found
  | 'deny-invalid-cert' // Certificate signature invalid
  | 'deny-expired'    // Certificate expired
  | 'deny-score'      // Trust score too low
  | 'deny-grade'      // Grade too low
  | 'deny-findings'   // Too many critical/high findings
  | 'deny-permissions'// Forbidden permissions detected
  | 'deny-blocked-tool'  // Tool is on block list
  | 'deny-not-allowed'   // Tool not on allow list
  | 'deny-rate-limit'    // Rate limit exceeded
  | 'deny-unknown-server' // Server not in config
  | 'warn';           // Permissive mode — logged but allowed

export interface GatewayResponse {
  allowed: boolean;
  decision: TrustDecision;
  reason?: string;
  serverName: string;
  toolName: string;
  trustScore?: number;
  grade?: string;
  latencyMs: number;
}

// ─── Rate Limiter ────────────────────────────────────────────────────

class RateLimiter {
  private windows = new Map<string, { count: number; resetAt: number }>();

  constructor(
    private maxRequests: number,
    private windowMs: number
  ) {}

  check(key: string): boolean {
    const now = Date.now();
    const entry = this.windows.get(key);

    if (!entry || now >= entry.resetAt) {
      this.windows.set(key, { count: 1, resetAt: now + this.windowMs });
      return true;
    }

    if (entry.count >= this.maxRequests) return false;
    entry.count++;
    return true;
  }
}

function parseRateLimit(spec: string): { max: number; windowMs: number } {
  const match = spec.match(/^(\d+)\/(min|hour|day)$/);
  if (!match) return { max: 100, windowMs: 60_000 };

  const max = parseInt(match[1]);
  const windowMs = match[2] === 'min' ? 60_000
    : match[2] === 'hour' ? 3_600_000
    : 86_400_000;

  return { max, windowMs };
}

// ─── Grade Comparison ────────────────────────────────────────────────

const GRADE_ORDER: Record<string, number> = { A: 4, B: 3, C: 2, D: 1, F: 0 };

function gradeAtLeast(actual: string, required: string): boolean {
  return (GRADE_ORDER[actual] ?? 0) >= (GRADE_ORDER[required] ?? 0);
}

// ─── Gateway ─────────────────────────────────────────────────────────

export class TrustGateway {
  private config: GatewayConfig;
  private trustStore: TrustStore;
  private auditLog: AuditLog;
  private rateLimiters = new Map<string, RateLimiter>();
  private stats = {
    totalRequests: 0,
    allowed: 0,
    denied: 0,
    warned: 0,
  };

  constructor(config: GatewayConfig, trustStore?: TrustStore, auditLog?: AuditLog) {
    this.config = config;
    this.trustStore = trustStore ?? new TrustStore();
    this.auditLog = auditLog ?? new AuditLog({
      logPath: config.gateway.logPath ?? './sentinel-gateway-audit.jsonl',
    });

    // Initialize rate limiters for each server
    for (const server of config.servers) {
      if (server.rateLimit) {
        const { max, windowMs } = parseRateLimit(server.rateLimit);
        this.rateLimiters.set(server.name, new RateLimiter(max, windowMs));
      }
    }
  }

  /**
   * Get the trust store for loading certificates.
   */
  getTrustStore(): TrustStore {
    return this.trustStore;
  }

  /**
   * Process a tool call request through the trust pipeline.
   */
  async processRequest(request: GatewayRequest): Promise<GatewayResponse> {
    const start = performance.now();
    this.stats.totalRequests++;

    // Find the server policy
    const policy = this.config.servers.find(s => s.name === request.serverName);
    if (!policy) {
      this.stats.denied++;
      return this.makeResponse(request, 'deny-unknown-server',
        `Server "${request.serverName}" is not configured`, start);
    }

    // Rate limit check
    const limiter = this.rateLimiters.get(request.serverName);
    if (limiter && !limiter.check(`${request.callerId}:${request.serverName}`)) {
      this.stats.denied++;
      return this.makeResponse(request, 'deny-rate-limit', 'Rate limit exceeded', start);
    }

    // Tool allow/block list check
    if (policy.blockedTools?.includes(request.toolName)) {
      this.stats.denied++;
      return this.makeResponse(request, 'deny-blocked-tool',
        `Tool "${request.toolName}" is blocked for server "${request.serverName}"`, start);
    }

    if (policy.allowedTools && !policy.allowedTools.includes(request.toolName)) {
      this.stats.denied++;
      return this.makeResponse(request, 'deny-not-allowed',
        `Tool "${request.toolName}" is not in the allowed list for server "${request.serverName}"`, start);
    }

    // Trust verification
    const trustResult = this.checkTrust(request.serverName, policy);

    if (trustResult.decision !== 'allow') {
      if (this.config.gateway.mode === 'permissive') {
        // Permissive mode: warn but allow
        this.stats.warned++;
        await this.audit(request, 'warn', trustResult.reason);
        return {
          allowed: true,
          decision: 'warn',
          reason: `[WARN] ${trustResult.reason}`,
          serverName: request.serverName,
          toolName: request.toolName,
          trustScore: trustResult.trustScore,
          grade: trustResult.grade,
          latencyMs: performance.now() - start,
        };
      }

      this.stats.denied++;
      await this.audit(request, trustResult.decision, trustResult.reason);
      return {
        allowed: false,
        decision: trustResult.decision,
        reason: trustResult.reason,
        serverName: request.serverName,
        toolName: request.toolName,
        trustScore: trustResult.trustScore,
        grade: trustResult.grade,
        latencyMs: performance.now() - start,
      };
    }

    // All checks passed
    this.stats.allowed++;
    await this.audit(request, 'allow');

    return {
      allowed: true,
      decision: 'allow',
      serverName: request.serverName,
      toolName: request.toolName,
      trustScore: trustResult.trustScore,
      grade: trustResult.grade,
      latencyMs: performance.now() - start,
    };
  }

  /**
   * Get gateway stats.
   */
  getStats() {
    return { ...this.stats };
  }

  // ─── Trust Verification ─────────────────────────────────────────

  private checkTrust(
    serverName: string,
    policy: ServerPolicy
  ): { decision: TrustDecision; reason?: string; trustScore?: number; grade?: string } {
    const trust = policy.trust ?? {};
    const globalMinScore = this.config.gateway.minTrustScore;
    const globalMinGrade = this.config.gateway.minGrade;

    // Check if certificate is required
    const cert = this.trustStore.getCertificate(serverName);

    if (trust.requireCertificate && !cert) {
      return { decision: 'deny-no-cert', reason: `No trust certificate found for "${serverName}"` };
    }

    // If no cert and not required, skip cert-dependent checks
    if (!cert) {
      // Apply global minimums if set — without a cert we can't verify
      if (globalMinScore !== undefined || globalMinGrade !== undefined) {
        return { decision: 'deny-no-cert', reason: `Trust score/grade required but no certificate available for "${serverName}"` };
      }
      return { decision: 'allow' };
    }

    if (!cert.verified) {
      return { decision: 'deny-invalid-cert', reason: 'Certificate signature is invalid', trustScore: cert.certificate.trustScore.overall, grade: cert.certificate.trustScore.grade };
    }

    // Expiry check
    if (new Date(cert.certificate.expiresAt) < new Date()) {
      return { decision: 'deny-expired', reason: 'Certificate has expired', trustScore: cert.certificate.trustScore.overall, grade: cert.certificate.trustScore.grade };
    }

    const score = cert.certificate.trustScore.overall;
    const grade = cert.certificate.trustScore.grade;

    // Score checks (server-specific overrides global)
    const minScore = trust.minScore ?? globalMinScore;
    if (minScore !== undefined && score < minScore) {
      return { decision: 'deny-score', reason: `Trust score ${score} is below minimum ${minScore}`, trustScore: score, grade };
    }

    // Grade checks
    const minGrade = trust.minGrade ?? globalMinGrade;
    if (minGrade && !gradeAtLeast(grade, minGrade)) {
      return { decision: 'deny-grade', reason: `Grade ${grade} is below minimum ${minGrade}`, trustScore: score, grade };
    }

    // Finding limits
    const summary = cert.certificate.findingSummary;
    if (trust.maxFindingsCritical !== undefined && summary.critical > trust.maxFindingsCritical) {
      return { decision: 'deny-findings', reason: `${summary.critical} critical findings exceeds max ${trust.maxFindingsCritical}`, trustScore: score, grade };
    }
    if (trust.maxFindingsHigh !== undefined && summary.high > trust.maxFindingsHigh) {
      return { decision: 'deny-findings', reason: `${summary.high} high findings exceeds max ${trust.maxFindingsHigh}`, trustScore: score, grade };
    }

    // Permission checks
    if (trust.allowedPermissions) {
      const forbidden = cert.certificate.permissions.filter(p => !trust.allowedPermissions!.includes(p));
      if (forbidden.length > 0) {
        return { decision: 'deny-permissions', reason: `Forbidden permissions detected: ${forbidden.join(', ')}`, trustScore: score, grade };
      }
    }
    if (trust.blockedPermissions) {
      const blocked = cert.certificate.permissions.filter(p => trust.blockedPermissions!.includes(p));
      if (blocked.length > 0) {
        return { decision: 'deny-permissions', reason: `Blocked permissions detected: ${blocked.join(', ')}`, trustScore: score, grade };
      }
    }

    return { decision: 'allow', trustScore: score, grade };
  }

  // ─── Helpers ────────────────────────────────────────────────────

  private async audit(
    request: GatewayRequest,
    decision: TrustDecision,
    reason?: string
  ): Promise<void> {
    await this.auditLog.log({
      eventType: decision === 'allow' ? 'session_created' : 'handshake_failed',
      actorDid: request.callerId,
      result: decision === 'allow' || decision === 'warn' ? 'success' : 'failure',
      metadata: {
        server: request.serverName,
        tool: request.toolName,
        decision,
        reason,
      },
    });
  }

  private makeResponse(
    request: GatewayRequest,
    decision: TrustDecision,
    reason: string,
    startTime: number
  ): GatewayResponse {
    this.audit(request, decision, reason);
    return {
      allowed: false,
      decision,
      reason,
      serverName: request.serverName,
      toolName: request.toolName,
      latencyMs: performance.now() - startTime,
    };
  }
}

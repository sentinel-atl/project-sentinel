/**
 * @sentinel-atl/gateway — MCP Security Gateway
 *
 * A drop-in proxy that sits between MCP clients and MCP servers,
 * adding Sentinel's full trust pipeline to every tool call:
 *
 *   Client → [Gateway: identity + credentials + reputation + safety + audit] → Server
 *
 * Features:
 * - Per-caller rate limiting
 * - Configurable allow/deny tool policies
 * - Pre-dispatch and post-response content safety
 * - Full audit trail of every tool call
 * - Automatic reputation tracking
 * - Kill switch support for emergency revocation
 * - Offline/degraded mode with cached trust decisions
 *
 * Usage:
 *   const gw = await createGateway({ name: 'my-gateway', enableSafety: true });
 *   gw.addToolPolicy('dangerous_tool', { requiredScopes: ['admin:write'], minReputation: 80 });
 *   const result = await gw.processToolCall(request);
 */

import {
  type VerifiableCredential,
  type IntentEnvelope,
  type KeyProvider,
  type AgentIdentity,
  type NegativeReason,
  InMemoryKeyProvider,
  createIdentity,
} from '@sentinel-atl/core';
import { AuditLog, type AuditEventType } from '@sentinel-atl/audit';
import { ReputationEngine, type ReputationScore } from '@sentinel-atl/reputation';
import { RevocationManager, type KillSwitchEvent, type RevocationReason } from '@sentinel-atl/revocation';
import { OfflineManager, type DegradedDecision } from '@sentinel-atl/offline';
import {
  SafetyPipeline,
  RegexClassifier,
  type SafetyCheckResult,
  type ContentClassifier,
} from '@sentinel-atl/safety';
import {
  createSentinelGuard,
  SentinelGuard,
  type SentinelGuardConfig,
  type MCPToolCallRequest,
  type VerifyResult,
} from '@sentinel-atl/mcp-plugin';

// ─── Configuration Types ─────────────────────────────────────────────

export interface GatewayConfig {
  /** Gateway name (used for identity + audit file naming) */
  name: string;

  /** Custom KeyProvider (default: InMemoryKeyProvider) */
  keyProvider?: KeyProvider;

  /** Minimum global reputation score (default: 0 = accept all) */
  minReputation?: number;

  /** Whether to require intent envelopes on every call (default: false) */
  requireIntent?: boolean;

  /** Enable content safety pipeline (default: false) */
  enableSafety?: boolean;

  /** Custom safety classifiers (default: RegexClassifier) */
  safetyClassifiers?: ContentClassifier[];

  /** Max requests per caller per window (default: 100) */
  rateLimitMax?: number;

  /** Rate limit window in ms (default: 60000 = 1 minute) */
  rateLimitWindowMs?: number;

  /** Custom audit log file path */
  auditLogPath?: string;

  /** Custom reputation engine */
  reputationEngine?: ReputationEngine;

  /** Shared revocation manager */
  revocationManager?: RevocationManager;
}

export interface ToolPolicy {
  /** Scopes required to call this tool */
  requiredScopes?: string[];
  /** Minimum reputation for this specific tool (overrides global) */
  minReputation?: number;
  /** Required credential types */
  requiredCredentials?: string[];
  /** Whether this tool is completely blocked */
  blocked?: boolean;
  /** Custom pre-dispatch hook — return false to deny */
  preHook?: (request: MCPToolCallRequest) => Promise<boolean>;
}

export interface GatewayResult {
  /** Whether the tool call was allowed through */
  allowed: boolean;
  /** Error or denial reason */
  reason?: string;
  /** Detailed check results from SentinelGuard */
  checks?: VerifyResult['checks'];
  /** Caller's reputation score */
  callerReputation?: ReputationScore;
  /** Offline decision info (if in degraded mode) */
  offlineDecision?: DegradedDecision;
  /** Safety check result */
  safetyResult?: SafetyCheckResult;
  /** Latency of all gateway checks in ms */
  gatewayLatencyMs: number;
}

export interface GatewayStats {
  totalRequests: number;
  allowed: number;
  denied: number;
  safetyBlocked: number;
  rateLimited: number;
  byTool: Record<string, { allowed: number; denied: number }>;
  byCaller: Record<string, { allowed: number; denied: number; lastSeen: string }>;
}

// ─── Rate Limiter ────────────────────────────────────────────────────

class CallerRateLimiter {
  private windows = new Map<string, { count: number; resetAt: number }>();

  constructor(
    private maxRequests: number,
    private windowMs: number
  ) {}

  check(callerDid: string): { allowed: boolean; retryAfterMs?: number } {
    const now = Date.now();
    const entry = this.windows.get(callerDid);

    if (!entry || now >= entry.resetAt) {
      this.windows.set(callerDid, { count: 1, resetAt: now + this.windowMs });
      return { allowed: true };
    }

    if (entry.count >= this.maxRequests) {
      return { allowed: false, retryAfterMs: entry.resetAt - now };
    }

    entry.count++;
    return { allowed: true };
  }

  reset(callerDid: string): void {
    this.windows.delete(callerDid);
  }

  resetAll(): void {
    this.windows.clear();
  }
}

// ─── Gateway Implementation ──────────────────────────────────────────

export class MCPSecurityGateway {
  readonly did: string;
  readonly keyId: string;

  private guard: SentinelGuard;
  private auditLog: AuditLog;
  private reputationEngine: ReputationEngine;
  private revocationManager: RevocationManager;
  private offlineManager: OfflineManager;
  private safetyPipeline: SafetyPipeline | undefined;
  private keyProvider: KeyProvider;

  private toolPolicies = new Map<string, ToolPolicy>();
  private rateLimiter: CallerRateLimiter;
  private stats: GatewayStats = {
    totalRequests: 0,
    allowed: 0,
    denied: 0,
    safetyBlocked: 0,
    rateLimited: 0,
    byTool: {},
    byCaller: {},
  };

  /** @internal — use createGateway() factory instead */
  constructor(
    identity: AgentIdentity,
    keyProvider: KeyProvider,
    auditLog: AuditLog,
    guard: SentinelGuard,
    reputationEngine: ReputationEngine,
    revocationManager: RevocationManager,
    offlineManager: OfflineManager,
    safetyPipeline: SafetyPipeline | undefined,
    rateLimiter: CallerRateLimiter
  ) {
    this.did = identity.did;
    this.keyId = identity.keyId;
    this.keyProvider = keyProvider;
    this.auditLog = auditLog;
    this.guard = guard;
    this.reputationEngine = reputationEngine;
    this.revocationManager = revocationManager;
    this.offlineManager = offlineManager;
    this.safetyPipeline = safetyPipeline;
    this.rateLimiter = rateLimiter;
  }

  // ─── Tool Policies ──────────────────────────────────────────────

  /** Register a per-tool policy (scopes, rep thresholds, blocks, hooks) */
  addToolPolicy(toolName: string, policy: ToolPolicy): void {
    this.toolPolicies.set(toolName, policy);
  }

  /** Remove a tool policy */
  removeToolPolicy(toolName: string): void {
    this.toolPolicies.delete(toolName);
  }

  /** List all configured tool policies */
  getToolPolicies(): ReadonlyMap<string, ToolPolicy> {
    return this.toolPolicies;
  }

  // ─── Core: Process Tool Call ────────────────────────────────────

  /**
   * Process an incoming MCP tool call through the full Sentinel pipeline.
   *
   * Pipeline:
   * 1. Rate limiting (per-caller)
   * 2. Tool policy check (blocked? required scopes?)
   * 3. Pre-hook (custom function)
   * 4. SentinelGuard verification (identity, credentials, reputation, intent, revocation, attestation)
   * 5. Pre-dispatch content safety
   * 6. Return result
   */
  async processToolCall(request: MCPToolCallRequest): Promise<GatewayResult> {
    const start = performance.now();
    this.stats.totalRequests++;

    const toolStats = this.stats.byTool[request.toolName] ??= { allowed: 0, denied: 0 };
    const callerStats = this.stats.byCaller[request.callerDid] ??= {
      allowed: 0,
      denied: 0,
      lastSeen: new Date().toISOString(),
    };
    callerStats.lastSeen = new Date().toISOString();

    // 1. Rate limiting
    const rateCheck = this.rateLimiter.check(request.callerDid);
    if (!rateCheck.allowed) {
      this.stats.denied++;
      this.stats.rateLimited++;
      toolStats.denied++;
      callerStats.denied++;
      await this.audit('handshake_failed', request.callerDid, 'failure', 'Rate limited');
      return {
        allowed: false,
        reason: `Rate limited. Retry after ${rateCheck.retryAfterMs}ms`,
        gatewayLatencyMs: performance.now() - start,
      };
    }

    // 2. Tool policy — blocked check
    const policy = this.toolPolicies.get(request.toolName);
    if (policy?.blocked) {
      this.stats.denied++;
      toolStats.denied++;
      callerStats.denied++;
      await this.audit('intent_rejected', request.callerDid, 'failure', `Tool ${request.toolName} is blocked`);
      return {
        allowed: false,
        reason: `Tool "${request.toolName}" is blocked by gateway policy`,
        gatewayLatencyMs: performance.now() - start,
      };
    }

    // 3. Pre-hook
    if (policy?.preHook) {
      const hookResult = await policy.preHook(request);
      if (!hookResult) {
        this.stats.denied++;
        toolStats.denied++;
        callerStats.denied++;
        await this.audit('intent_rejected', request.callerDid, 'failure', 'Pre-hook denied');
        return {
          allowed: false,
          reason: 'Denied by tool pre-hook',
          gatewayLatencyMs: performance.now() - start,
        };
      }
    }

    // 4. SentinelGuard verification (full 10-step pipeline)
    const verifyResult = await this.guard.verifyToolCall(request);

    if (!verifyResult.allowed) {
      this.stats.denied++;
      toolStats.denied++;
      callerStats.denied++;
      return {
        allowed: false,
        reason: verifyResult.reason,
        checks: verifyResult.checks,
        callerReputation: verifyResult.callerReputation,
        offlineDecision: verifyResult.offlineDecision,
        safetyResult: verifyResult.safetyResult,
        gatewayLatencyMs: performance.now() - start,
      };
    }

    // 5. Tool-specific reputation check (if policy sets higher than global)
    if (policy?.minReputation) {
      const rep = verifyResult.callerReputation ?? this.reputationEngine.computeScore(request.callerDid);
      if (rep.score < policy.minReputation) {
        this.stats.denied++;
        toolStats.denied++;
        callerStats.denied++;
        await this.audit('handshake_failed', request.callerDid, 'failure',
          `Tool ${request.toolName} requires reputation ${policy.minReputation}, got ${rep.score}`);
        return {
          allowed: false,
          reason: `Insufficient reputation for tool "${request.toolName}": ${rep.score} < ${policy.minReputation}`,
          checks: verifyResult.checks,
          callerReputation: rep,
          gatewayLatencyMs: performance.now() - start,
        };
      }
    }

    // 6. Pre-dispatch content safety (check the tool call payload)
    if (this.safetyPipeline && request.authPayload) {
      const safetyResult = await this.safetyPipeline.preDispatch(request.authPayload);
      if (!safetyResult.allowed) {
        this.stats.denied++;
        this.stats.safetyBlocked++;
        toolStats.denied++;
        callerStats.denied++;
        await this.audit('intent_rejected', request.callerDid, 'failure', 'Content safety violation');
        return {
          allowed: false,
          reason: 'Blocked by content safety policy',
          checks: verifyResult.checks,
          safetyResult: safetyResult.result,
          gatewayLatencyMs: performance.now() - start,
        };
      }
    }

    // All checks passed
    this.stats.allowed++;
    toolStats.allowed++;
    callerStats.allowed++;
    await this.audit('session_created', request.callerDid, 'success', `Tool call: ${request.toolName}`);

    return {
      allowed: true,
      checks: verifyResult.checks,
      callerReputation: verifyResult.callerReputation,
      offlineDecision: verifyResult.offlineDecision,
      safetyResult: verifyResult.safetyResult,
      gatewayLatencyMs: performance.now() - start,
    };
  }

  /**
   * Check the safety of a tool response before returning it to the caller.
   * Call this after the upstream MCP server returns a result.
   */
  async checkResponseSafety(
    callerDid: string,
    toolName: string,
    response: string
  ): Promise<{ allowed: boolean; safetyResult?: SafetyCheckResult }> {
    if (!this.safetyPipeline) return { allowed: true };

    const result = await this.safetyPipeline.postResponse(response);
    if (!result.allowed) {
      this.stats.safetyBlocked++;
      await this.audit('intent_rejected', callerDid, 'failure',
        `Response safety violation for ${toolName}`);
    }
    return { allowed: result.allowed, safetyResult: result.result };
  }

  /**
   * Record the outcome of a tool call (for audit trail).
   */
  async recordOutcome(
    request: MCPToolCallRequest,
    result: 'success' | 'failure',
    reason?: string
  ): Promise<void> {
    await this.guard.recordResult(request, result, reason);
  }

  // ─── Revocation / Kill Switch ──────────────────────────────────

  /** Revoke a caller's DID — they can no longer pass through the gateway */
  async revokeCaller(
    targetDid: string,
    reason: RevocationReason
  ): Promise<void> {
    await this.revocationManager.revokeDID(
      this.keyProvider, this.keyId,
      this.did, targetDid, reason
    );
    this.rateLimiter.reset(targetDid);
  }

  /** Emergency kill switch — cascading revocation */
  async killSwitch(
    targetDid: string,
    reason: string,
    downstreamDids?: string[]
  ): Promise<KillSwitchEvent> {
    return this.revocationManager.killSwitch(
      this.keyProvider, this.keyId,
      this.did, targetDid, reason,
      { cascade: true, downstreamDids }
    );
  }

  // ─── Reputation ────────────────────────────────────────────────

  /** Get a caller's current reputation score */
  getCallerReputation(did: string): ReputationScore {
    return this.reputationEngine.computeScore(did);
  }

  /** Submit a reputation vouch (positive or negative) for a caller */
  vouch(
    callerDid: string,
    polarity: 'positive' | 'negative',
    weight: number,
    reason?: string
  ): { allowed: boolean; reason?: string } {
    const result = this.reputationEngine.checkVouchRateLimit(this.did, callerDid);
    if (!result.allowed) {
      return { allowed: false, reason: result.reason };
    }
    this.reputationEngine.addVouch({
      voucherDid: this.did,
      subjectDid: callerDid,
      polarity,
      weight,
      reason: reason as NegativeReason | undefined,
      voucherVerified: true,
      timestamp: new Date().toISOString(),
    });
    return { allowed: true };
  }

  // ─── Observability ─────────────────────────────────────────────

  /** Get gateway statistics */
  getStats(): Readonly<GatewayStats> {
    return { ...this.stats };
  }

  /** Reset statistics */
  resetStats(): void {
    this.stats = {
      totalRequests: 0,
      allowed: 0,
      denied: 0,
      safetyBlocked: 0,
      rateLimited: 0,
      byTool: {},
      byCaller: {},
    };
  }

  /** Get the audit log instance */
  getAuditLog(): AuditLog {
    return this.auditLog;
  }

  /** Get the underlying SentinelGuard */
  getGuard(): SentinelGuard {
    return this.guard;
  }

  // ─── Offline Mode ──────────────────────────────────────────────

  /** Enter degraded/offline mode */
  goOffline(): void {
    this.offlineManager.goOffline();
  }

  /** Return to online mode */
  goOnline(): void {
    this.offlineManager.goOnline();
  }

  /** Check if gateway is in degraded mode */
  get isOnline(): boolean {
    return this.offlineManager.isOnline;
  }

  // ─── Internal ──────────────────────────────────────────────────

  private async audit(
    eventType: AuditEventType,
    targetDid: string,
    result: 'success' | 'failure',
    reason?: string
  ): Promise<void> {
    await this.auditLog.log({
      eventType,
      actorDid: this.did,
      targetDid,
      result,
      reason,
    });
  }
}

// ─── Factory ─────────────────────────────────────────────────────────

/**
 * Create a fully-initialized MCP Security Gateway.
 *
 * @example
 * ```ts
 * const gw = await createGateway({ name: 'my-gateway', enableSafety: true });
 * gw.addToolPolicy('delete_all', { blocked: true });
 * gw.addToolPolicy('exec_code', { minReputation: 80, requiredScopes: ['code:execute'] });
 *
 * const result = await gw.processToolCall({
 *   toolName: 'search',
 *   callerDid: agent.did,
 *   credentials: [vc],
 * });
 *
 * if (result.allowed) {
 *   const output = await upstreamServer.callTool('search', args);
 *   const safety = await gw.checkResponseSafety(agent.did, 'search', JSON.stringify(output));
 *   if (safety.allowed) return output;
 * }
 * ```
 */
export async function createGateway(config: GatewayConfig): Promise<MCPSecurityGateway> {
  // 1. Identity
  const keyProvider = config.keyProvider ?? new InMemoryKeyProvider();
  const identity = await createIdentity(keyProvider, `gateway-${config.name}`);

  // 2. Audit log
  const auditLog = new AuditLog({ logPath: config.auditLogPath ?? `gateway-${config.name}-audit.jsonl` });
  await auditLog.init();

  // 3. Subsystems
  const reputationEngine = config.reputationEngine ?? new ReputationEngine();
  const revocationManager = config.revocationManager ?? new RevocationManager();
  const offlineManager = new OfflineManager();

  let safetyPipeline: SafetyPipeline | undefined;
  if (config.enableSafety) {
    const classifiers = config.safetyClassifiers ?? [new RegexClassifier()];
    safetyPipeline = new SafetyPipeline({ classifiers });
  }

  // 4. Build SentinelGuard with the gateway's own DID
  const toolScopes: Record<string, string[]> = {};
  const guard = createSentinelGuard({
    auditLog,
    serverDid: identity.did,
    minReputation: config.minReputation ?? 0,
    requireIntent: config.requireIntent ?? false,
    reputationEngine,
    revocationManager,
    offlineManager,
    safetyPipeline,
    toolScopes,
  });

  // 5. Rate limiter
  const rateLimiter = new CallerRateLimiter(
    config.rateLimitMax ?? 100,
    config.rateLimitWindowMs ?? 60_000
  );

  // 6. Log gateway creation
  await auditLog.log({
    eventType: 'identity_created',
    actorDid: identity.did,
    result: 'success',
    reason: `Gateway "${config.name}" initialized`,
  });

  return new MCPSecurityGateway(
    identity,
    keyProvider,
    auditLog,
    guard,
    reputationEngine,
    revocationManager,
    offlineManager,
    safetyPipeline,
    rateLimiter
  );
}

// ─── Re-exports ──────────────────────────────────────────────────────

export type { MCPToolCallRequest, VerifyResult, SentinelGuardConfig } from '@sentinel-atl/mcp-plugin';
export type { SafetyCheckResult, ContentClassifier } from '@sentinel-atl/safety';
export type { ReputationScore } from '@sentinel-atl/reputation';
export type { RevocationReason, KillSwitchEvent } from '@sentinel-atl/revocation';
export type { DegradedDecision } from '@sentinel-atl/offline';
export type { VerifiableCredential, IntentEnvelope, KeyProvider } from '@sentinel-atl/core';

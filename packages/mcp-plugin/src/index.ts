/**
 * @sentinel/mcp-plugin — MCP Identity Middleware
 *
 * Sentinel for MCP servers. Adds identity verification, credential checks,
 * intent validation, and audit logging at the tool-call boundary.
 *
 * MCP has no identity layer. This plugin fills that gap.
 *
 * Usage:
 *   const guard = createSentinelGuard({ ... });
 *
 *   // In your MCP server tool handler:
 *   async function handleToolCall(request) {
 *     const check = await guard.verifyToolCall(request);
 *     if (!check.allowed) return { error: check.reason };
 *     // ... proceed with tool logic
 *     await guard.recordResult(request, 'success');
 *   }
 */

import {
  verifyVC,
  validateIntent,
  didToPublicKey,
  verify,
  fromBase64Url,
  textToBytes,
  type VerifiableCredential,
  type IntentEnvelope,
  type KeyProvider,
} from '@sentinel/core';
import { AuditLog, type AuditEventType } from '@sentinel/audit';
import { ReputationEngine, type ReputationScore } from '@sentinel/reputation';
import { RevocationManager } from '@sentinel/revocation';
import { AttestationManager } from '@sentinel/attestation';
import { OfflineManager, type DegradedDecision } from '@sentinel/offline';
import { SafetyPipeline, type SafetyCheckResult } from '@sentinel/safety';

// ─── Types ───────────────────────────────────────────────────────────

export interface SentinelGuardConfig {
  /** Audit log instance */
  auditLog: AuditLog;
  /** This server's DID (for audit logging) */
  serverDid: string;
  /** Minimum reputation score required (0-100, default: 0 = accept all) */
  minReputation?: number;
  /** Required credential types from caller */
  requiredCredentials?: string[];
  /** Required scopes for specific tools */
  toolScopes?: Record<string, string[]>;
  /** Reputation engine (shared or per-instance) */
  reputationEngine?: ReputationEngine;
  /** Whether to require intent envelopes (default: false) */
  requireIntent?: boolean;
  /** Revocation manager for DID/VC revocation checks */
  revocationManager?: RevocationManager;
  /** Attestation manager for code attestation checks */
  attestationManager?: AttestationManager;
  /** Expected code hash — if set, callers must have matching attestation */
  requiredCodeHash?: string;
  /** Offline manager for degraded mode support */
  offlineManager?: OfflineManager;
  /** Safety pipeline for content filtering */
  safetyPipeline?: SafetyPipeline;
}

export interface MCPToolCallRequest {
  /** The tool being called */
  toolName: string;
  /** Caller's DID */
  callerDid: string;
  /** VCs presented by the caller */
  credentials?: VerifiableCredential[];
  /** Intent envelope (if the caller provides one) */
  intent?: IntentEnvelope;
  /** Signature over the tool call payload for authentication */
  authSignature?: string;
  /** The serialized payload that was signed */
  authPayload?: string;
}

export interface VerifyResult {
  allowed: boolean;
  reason?: string;
  checks: {
    identity: boolean;
    credentials: boolean;
    reputation: boolean;
    intent: boolean;
    scope: boolean;
    revocation: boolean;
    attestation: boolean;
    safety: boolean;
  };
  callerReputation?: ReputationScore;
  offlineDecision?: DegradedDecision;
  safetyResult?: SafetyCheckResult;
}

// ─── Guard Implementation ────────────────────────────────────────────

export class SentinelGuard {
  private config: Required<
    Pick<SentinelGuardConfig, 'auditLog' | 'serverDid' | 'minReputation' | 'requireIntent'>
  > & SentinelGuardConfig;
  private reputationEngine: ReputationEngine;
  private revocationManager: RevocationManager;
  private attestationManager: AttestationManager;
  private offlineManager: OfflineManager;
  private safetyPipeline: SafetyPipeline | undefined;
  private seenNonces = new Set<string>();

  constructor(config: SentinelGuardConfig) {
    this.config = {
      ...config,
      minReputation: config.minReputation ?? 0,
      requireIntent: config.requireIntent ?? false,
    };
    this.reputationEngine = config.reputationEngine ?? new ReputationEngine();
    this.revocationManager = config.revocationManager ?? new RevocationManager();
    this.attestationManager = config.attestationManager ?? new AttestationManager();
    this.offlineManager = config.offlineManager ?? new OfflineManager();
    this.safetyPipeline = config.safetyPipeline;
  }

  /**
   * Verify a tool call request against Sentinel policies.
   *
   * Checks (in order):
   * 1. Identity — caller DID resolves to a valid Ed25519 key
   * 2. Authentication — caller signed the request payload
   * 3. Credentials — all required VCs are presented and valid
   * 4. Scope — caller has the required scope for this tool
   * 5. Reputation — caller meets minimum reputation threshold
   * 6. Intent — if required, intent envelope is present and valid
   */
  async verifyToolCall(request: MCPToolCallRequest): Promise<VerifyResult> {
    const checks = {
      identity: false,
      credentials: false,
      reputation: false,
      intent: false,
      scope: false,
      revocation: false,
      attestation: false,
      safety: false,
    };

    // 1. Identity — verify caller DID is resolvable
    try {
      didToPublicKey(request.callerDid);
      checks.identity = true;
    } catch {
      await this.audit('handshake_failed', request.callerDid, 'failure', 'Invalid caller DID');
      return { allowed: false, reason: `Invalid caller DID: ${request.callerDid}`, checks };
    }

    // 1b. Revocation — check if caller DID or any credential is revoked
    const trustCheck = this.revocationManager.isTrusted(request.callerDid);
    if (!trustCheck.trusted) {
      await this.audit('emergency_revoke', request.callerDid, 'failure', trustCheck.reason);
      return { allowed: false, reason: `Caller revoked: ${trustCheck.reason}`, checks };
    }
    if (request.credentials) {
      for (const vc of request.credentials) {
        const vcTrust = this.revocationManager.isTrusted(vc.issuer, vc.id);
        if (!vcTrust.trusted) {
          await this.audit('vc_revoked', request.callerDid, 'failure', vcTrust.reason);
          return { allowed: false, reason: `Credential revoked: ${vcTrust.reason}`, checks };
        }
      }
    }
    checks.revocation = true;

    // 1c. Attestation — if required, verify caller's code hash
    if (this.config.requiredCodeHash) {
      const attestResult = await this.attestationManager.verifyCodeHash(
        request.callerDid,
        this.config.requiredCodeHash
      );
      if (!attestResult.match) {
        await this.audit('handshake_failed', request.callerDid, 'failure', attestResult.error);
        return { allowed: false, reason: `Attestation failed: ${attestResult.error}`, checks };
      }
    }
    checks.attestation = true;

    // 2. Authentication — verify caller signed the payload
    if (request.authSignature && request.authPayload) {
      try {
        const publicKey = didToPublicKey(request.callerDid);
        const sig = fromBase64Url(request.authSignature);
        const payload = textToBytes(request.authPayload);
        const valid = await verify(sig, payload, publicKey);
        if (!valid) {
          await this.audit('handshake_failed', request.callerDid, 'failure', 'Auth signature invalid');
          return { allowed: false, reason: 'Authentication signature invalid', checks };
        }
      } catch {
        await this.audit('handshake_failed', request.callerDid, 'failure', 'Auth verification error');
        return { allowed: false, reason: 'Authentication verification failed', checks };
      }
    }

    // 3. Credentials — verify all presented VCs
    const requiredTypes = this.config.requiredCredentials ?? [];
    const presentedTypes = new Set<string>();

    if (request.credentials && request.credentials.length > 0) {
      for (const vc of request.credentials) {
        const result = await verifyVC(vc);
        if (!result.valid) {
          await this.audit('vc_verified', request.callerDid, 'failure', `VC invalid: ${result.error}`);
          return {
            allowed: false,
            reason: `Credential verification failed: ${result.error}`,
            checks,
          };
        }
        // Ensure the VC is actually for this caller
        if (vc.credentialSubject.id !== request.callerDid) {
          await this.audit('vc_verified', request.callerDid, 'failure', 'VC subject mismatch');
          return {
            allowed: false,
            reason: 'Credential subject does not match caller DID',
            checks,
          };
        }
        presentedTypes.add(vc.type[1]);
      }
    }

    // Check all required types are covered
    for (const required of requiredTypes) {
      if (!presentedTypes.has(required)) {
        await this.audit('vc_verified', request.callerDid, 'failure', `Missing ${required}`);
        return {
          allowed: false,
          reason: `Missing required credential: ${required}`,
          checks,
        };
      }
    }
    checks.credentials = true;

    // 4. Scope — check caller has required scope for this tool
    const requiredScopes = this.config.toolScopes?.[request.toolName];
    if (requiredScopes && requiredScopes.length > 0 && request.credentials) {
      const callerScopes = new Set<string>();
      for (const vc of request.credentials) {
        if (vc.credentialSubject.scope) {
          for (const s of vc.credentialSubject.scope) callerScopes.add(s);
        }
      }

      for (const required of requiredScopes) {
        if (!callerScopes.has(required)) {
          await this.audit('intent_rejected', request.callerDid, 'failure', `Missing scope: ${required}`);
          return {
            allowed: false,
            reason: `Caller lacks required scope for tool "${request.toolName}": ${required}`,
            checks,
          };
        }
      }
    }
    checks.scope = true;

    // 5. Reputation
    const reputation = this.reputationEngine.computeScore(request.callerDid);
    if (reputation.isQuarantined) {
      await this.audit('handshake_failed', request.callerDid, 'failure', 'Caller quarantined');
      return {
        allowed: false,
        reason: 'Caller is quarantined due to negative reputation',
        checks,
        callerReputation: reputation,
      };
    }
    if (reputation.score < this.config.minReputation) {
      await this.audit('handshake_failed', request.callerDid, 'failure', `Reputation ${reputation.score} < ${this.config.minReputation}`);
      return {
        allowed: false,
        reason: `Reputation score ${reputation.score} below minimum ${this.config.minReputation}`,
        checks,
        callerReputation: reputation,
      };
    }
    checks.reputation = true;

    // 6. Intent
    if (this.config.requireIntent) {
      if (!request.intent) {
        await this.audit('intent_rejected', request.callerDid, 'failure', 'No intent provided');
        return { allowed: false, reason: 'Intent envelope required but not provided', checks };
      }

      const intentResult = await validateIntent(request.intent, this.seenNonces);
      if (!intentResult.valid) {
        await this.audit('intent_rejected', request.callerDid, 'failure', intentResult.error);
        return {
          allowed: false,
          reason: `Intent validation failed: ${intentResult.error}`,
          checks,
        };
      }
      checks.intent = true;
    } else {
      checks.intent = true; // Not required, auto-pass
    }

    // All checks passed
    // 7. Offline mode evaluation
    const offlineDecision = this.offlineManager.evaluateTrustDecision(
      request.callerDid,
      request.credentials?.[0]?.issuer
    );
    if (offlineDecision.action === 'deny') {
      await this.audit('handshake_failed', request.callerDid, 'failure', offlineDecision.reason);
      return { allowed: false, reason: `Offline policy denied: ${offlineDecision.reason}`, checks, offlineDecision };
    }

    // 8. Content safety (if pipeline configured)
    let safetyResult: SafetyCheckResult | undefined;
    if (this.safetyPipeline && request.authPayload) {
      const safetyCheck = await this.safetyPipeline.preDispatch(request.authPayload);
      safetyResult = safetyCheck.result;
      if (!safetyCheck.allowed) {
        await this.audit('intent_rejected', request.callerDid, 'failure', `Content safety: ${safetyResult.violations[0]?.description}`);
        return { allowed: false, reason: `Content safety blocked: ${safetyResult.violations[0]?.description}`, checks, safetyResult };
      }
    }
    checks.safety = true;

    await this.audit('vc_verified', request.callerDid, 'success', undefined, {
      tool: request.toolName,
      credentialCount: request.credentials?.length ?? 0,
    });

    return {
      allowed: true,
      checks,
      callerReputation: reputation,
      offlineDecision,
      safetyResult,
    };
  }

  /**
   * Record the outcome of a tool call for audit and reputation.
   */
  async recordResult(
    request: MCPToolCallRequest,
    result: 'success' | 'failure',
    reason?: string
  ): Promise<void> {
    await this.audit(
      result === 'success' ? 'session_created' : 'session_terminated',
      request.callerDid,
      result,
      reason,
      { tool: request.toolName }
    );
  }

  /**
   * Get the reputation engine for adding vouches or querying scores.
   */
  getReputationEngine(): ReputationEngine {
    return this.reputationEngine;
  }

  /**
   * Get the revocation manager for revoking DIDs/VCs.
   */
  getRevocationManager(): RevocationManager {
    return this.revocationManager;
  }

  /**
   * Get the attestation manager for verifying code attestations.
   */
  getAttestationManager(): AttestationManager {
    return this.attestationManager;
  }

  /**
   * Get the offline manager for cache/policy control.
   */
  getOfflineManager(): OfflineManager {
    return this.offlineManager;
  }

  /**
   * Get the safety pipeline (if configured).
   */
  getSafetyPipeline(): SafetyPipeline | undefined {
    return this.safetyPipeline;
  }

  private async audit(
    eventType: AuditEventType,
    actorDid: string,
    result: 'success' | 'failure',
    reason?: string,
    metadata?: Record<string, unknown>
  ): Promise<void> {
    await this.config.auditLog.log({
      eventType,
      actorDid,
      targetDid: this.config.serverDid,
      result,
      reason,
      metadata,
    });
  }
}

/**
 * Create a SentinelGuard instance — the main entry point.
 *
 * @example
 * ```ts
 * const guard = createSentinelGuard({
 *   auditLog: new AuditLog({ logPath: './sentinel-audit.jsonl' }),
 *   serverDid: myServer.did,
 *   requiredCredentials: ['AgentAuthorizationCredential'],
 *   toolScopes: {
 *     'send_email': ['email:send'],
 *     'read_files': ['fs:read'],
 *   },
 *   minReputation: 30,
 * });
 * ```
 */
export function createSentinelGuard(config: SentinelGuardConfig): SentinelGuard {
  return new SentinelGuard(config);
}

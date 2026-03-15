/**
 * @sentinel-atl/stepup — Step-Up Authentication for Sensitive Actions
 *
 * When an agent is about to do something high-sensitivity — authorize a
 * large payment, delete data, modify permissions — the trust pipeline
 * should PAUSE and ask the human principal to re-confirm.
 *
 * This is the "Are you sure?" for AI agents, but cryptographically backed.
 *
 * How it works:
 *
 * 1. Agent detects a sensitive action (via VC sensitivity level or policy rules)
 * 2. Agent creates a `StepUpChallenge` describing what it wants to do
 * 3. Challenge is sent to the human principal
 * 4. Human signs an `StepUpApproval` (proving they reviewed + approved)
 * 5. Agent proceeds only if the approval signature is valid and timely
 *
 * The challenge is time-bounded and single-use to prevent replay.
 */

import {
  toBase64Url,
  fromBase64Url,
  textToBytes,
  secureRandom,
  sign,
  verify,
  toHex,
  hash,
  didToPublicKey,
  type KeyProvider,
  type SensitivityLevel,
} from '@sentinel-atl/core';
import { AuditLog } from '@sentinel-atl/audit';

// ─── Types ───────────────────────────────────────────────────────────

export interface StepUpChallenge {
  /** Unique challenge ID */
  challengeId: string;
  /** The agent requesting approval */
  agentDid: string;
  /** The human principal being asked to approve */
  principalDid: string;
  /** Human-readable description of the action */
  actionDescription: string;
  /** Machine-readable action identifier */
  action: string;
  /** Scope being requested */
  scope: string[];
  /** Why step-up was triggered */
  triggerReason: StepUpTrigger;
  /** When the challenge expires (ISO 8601) */
  expiresAt: string;
  /** One-time nonce */
  nonce: string;
  /** Created timestamp */
  createdAt: string;
}

export interface StepUpApproval {
  /** The challenge being approved */
  challengeId: string;
  /** The principal who approved it */
  principalDid: string;
  /** Approval or denial */
  decision: 'approved' | 'denied';
  /** When the decision was made */
  decidedAt: string;
  /** Ed25519 signature over the approval data (base64url) */
  signature: string;
}

export type StepUpTrigger =
  | 'sensitivity_high'
  | 'sensitivity_critical'
  | 'amount_threshold'
  | 'scope_escalation'
  | 'first_use'
  | 'anomaly_detected'
  | 'policy_rule';

export interface StepUpPolicy {
  /** Actions that always require step-up */
  alwaysRequireActions?: string[];
  /** Sensitivity levels that trigger step-up (default: ['high', 'critical']) */
  sensitivityLevels?: SensitivityLevel[];
  /** Challenge timeout in ms (default: 5 minutes) */
  challengeTimeoutMs?: number;
  /** Maximum pending challenges per agent */
  maxPendingChallenges?: number;
}

export interface StepUpResult {
  approved: boolean;
  error?: string;
  challengeId?: string;
}

// ─── Canonicalization ────────────────────────────────────────────────

function canonicalizeChallenge(challenge: StepUpChallenge): Uint8Array {
  return textToBytes(
    `stepup:${challenge.challengeId}:${challenge.agentDid}:${challenge.principalDid}:${challenge.action}:${challenge.nonce}:${challenge.expiresAt}`
  );
}

// ─── Step-Up Manager ─────────────────────────────────────────────────

export class StepUpManager {
  private pendingChallenges = new Map<string, StepUpChallenge>();
  private usedNonces = new Set<string>();
  private policy: Required<StepUpPolicy>;
  private auditLog?: AuditLog;

  constructor(
    policy: StepUpPolicy = {},
    auditLog?: AuditLog
  ) {
    this.policy = {
      alwaysRequireActions: policy.alwaysRequireActions ?? [],
      sensitivityLevels: policy.sensitivityLevels ?? ['high', 'critical'],
      challengeTimeoutMs: policy.challengeTimeoutMs ?? 5 * 60_000,
      maxPendingChallenges: policy.maxPendingChallenges ?? 10,
    };
    this.auditLog = auditLog;
  }

  /**
   * Check if an action requires step-up authentication.
   */
  requiresStepUp(
    action: string,
    sensitivityLevel?: SensitivityLevel
  ): { required: boolean; trigger?: StepUpTrigger } {
    // Check explicit action list
    if (this.policy.alwaysRequireActions.includes(action)) {
      return { required: true, trigger: 'policy_rule' };
    }

    // Check sensitivity level
    if (
      sensitivityLevel &&
      this.policy.sensitivityLevels.includes(sensitivityLevel)
    ) {
      const trigger: StepUpTrigger =
        sensitivityLevel === 'critical' ? 'sensitivity_critical' : 'sensitivity_high';
      return { required: true, trigger };
    }

    return { required: false };
  }

  /**
   * Create a step-up challenge for the human principal to approve.
   */
  createChallenge(
    agentDid: string,
    principalDid: string,
    action: string,
    scope: string[],
    trigger: StepUpTrigger,
    actionDescription: string
  ): StepUpChallenge {
    // Enforce max pending limit
    const agentPending = Array.from(this.pendingChallenges.values())
      .filter(c => c.agentDid === agentDid).length;
    if (agentPending >= this.policy.maxPendingChallenges) {
      throw new Error(`Max pending challenges (${this.policy.maxPendingChallenges}) reached for agent`);
    }

    const nonce = toHex(secureRandom(16));
    const challengeId = `stepup-${toHex(secureRandom(8))}`;
    const now = new Date();

    const challenge: StepUpChallenge = {
      challengeId,
      agentDid,
      principalDid,
      actionDescription,
      action,
      scope,
      triggerReason: trigger,
      expiresAt: new Date(now.getTime() + this.policy.challengeTimeoutMs).toISOString(),
      nonce,
      createdAt: now.toISOString(),
    };

    this.pendingChallenges.set(challengeId, challenge);
    return challenge;
  }

  /**
   * Principal signs an approval for a challenge.
   */
  async signApproval(
    keyProvider: KeyProvider,
    principalKeyId: string,
    challenge: StepUpChallenge,
    decision: 'approved' | 'denied'
  ): Promise<StepUpApproval> {
    const approvalData = textToBytes(
      `stepup-approval:${challenge.challengeId}:${challenge.principalDid}:${decision}:${challenge.nonce}`
    );
    const sig = await keyProvider.sign(principalKeyId, approvalData);

    return {
      challengeId: challenge.challengeId,
      principalDid: challenge.principalDid,
      decision,
      decidedAt: new Date().toISOString(),
      signature: toBase64Url(sig),
    };
  }

  /**
   * Verify a step-up approval and consume the challenge.
   *
   * This is the critical gate: if the approval is invalid, expired,
   * or replayed, the action MUST NOT proceed.
   */
  async verifyApproval(approval: StepUpApproval): Promise<StepUpResult> {
    // Find the pending challenge
    const challenge = this.pendingChallenges.get(approval.challengeId);
    if (!challenge) {
      return { approved: false, error: 'Challenge not found or already consumed' };
    }

    // Check nonce replay
    if (this.usedNonces.has(challenge.nonce)) {
      return { approved: false, error: 'Challenge nonce already used (replay)' };
    }

    // Check expiry
    if (new Date(challenge.expiresAt) < new Date()) {
      this.pendingChallenges.delete(approval.challengeId);
      return { approved: false, error: 'Challenge expired' };
    }

    // Check principal matches
    if (approval.principalDid !== challenge.principalDid) {
      return { approved: false, error: 'Principal DID mismatch' };
    }

    // Verify signature
    try {
      const publicKey = didToPublicKey(approval.principalDid);
      const approvalData = textToBytes(
        `stepup-approval:${challenge.challengeId}:${challenge.principalDid}:${approval.decision}:${challenge.nonce}`
      );
      const sig = fromBase64Url(approval.signature);
      const valid = await verify(sig, approvalData, publicKey);

      if (!valid) {
        return { approved: false, error: 'Invalid approval signature' };
      }
    } catch (e) {
      return { approved: false, error: `Signature verification failed: ${(e as Error).message}` };
    }

    // Consume the challenge (single-use)
    this.pendingChallenges.delete(approval.challengeId);
    this.usedNonces.add(challenge.nonce);

    // Check the decision
    if (approval.decision === 'denied') {
      await this.auditLog?.log({
        eventType: 'intent_rejected',
        actorDid: approval.principalDid,
        targetDid: challenge.agentDid,
        result: 'failure',
        reason: 'Step-up denied by principal',
        metadata: {
          challengeId: approval.challengeId,
          action: challenge.action,
        },
      });
      return { approved: false, error: 'Denied by principal', challengeId: approval.challengeId };
    }

    await this.auditLog?.log({
      eventType: 'intent_validated',
      actorDid: approval.principalDid,
      targetDid: challenge.agentDid,
      result: 'success',
      metadata: {
        type: 'step_up_approval',
        challengeId: approval.challengeId,
        action: challenge.action,
      },
    });

    return { approved: true, challengeId: approval.challengeId };
  }

  /**
   * Get a pending challenge by ID.
   */
  getChallenge(challengeId: string): StepUpChallenge | undefined {
    return this.pendingChallenges.get(challengeId);
  }

  /**
   * Get count of pending challenges.
   */
  getPendingCount(): number {
    return this.pendingChallenges.size;
  }

  /**
   * Cancel a pending challenge.
   */
  cancelChallenge(challengeId: string): boolean {
    return this.pendingChallenges.delete(challengeId);
  }
}

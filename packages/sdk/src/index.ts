/**
 * @sentinel/sdk — The developer-facing SDK
 *
 * Add trust to your AI agent in ~5 lines of code:
 *
 *   const agent = await createTrustedAgent({ name: 'my-agent' });
 *   const vc = await agent.requestAuthorization(principalDid, scopes);
 *   const session = await agent.handshake(peerDid, peerPassport);
 *   const intent = await agent.createIntent('book_flight', scopes);
 *   await agent.vouch(peerDid, 'positive', 0.8);
 *
 * This wraps @sentinel/core, @sentinel/handshake, @sentinel/reputation,
 * and @sentinel/audit into a single cohesive API.
 */

import {
  InMemoryKeyProvider,
  createIdentity,
  issueVC,
  verifyVC,
  createIntent,
  validateIntent,
  createPassport,
  checkPassportCompatibility,
  type KeyProvider,
  type AgentIdentity,
  type AgentPassport,
  type VerifiableCredential,
  type IntentEnvelope,
  type CredentialType,
  type SensitivityLevel,
} from '@sentinel/core';
import {
  createHandshakeInit,
  processInitAndRespond,
  createVCExchange,
  verifyVCExchange,
  createSessionEstablished,
  HandshakeRateLimiter,
  HandshakeCircuitBreaker,
  type HandshakeConfig,
  type SessionEstablished,
} from '@sentinel/handshake';
import { ReputationEngine, type ReputationScore } from '@sentinel/reputation';
import { AuditLog } from '@sentinel/audit';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { mkdirSync, existsSync } from 'node:fs';

// ─── Types ───────────────────────────────────────────────────────────

export interface TrustedAgentConfig {
  /** Agent name */
  name: string;
  /** Agent capabilities */
  capabilities?: string[];
  /** Credential types this agent can present */
  offeredCredentials?: string[];
  /** Credential types this agent requires from peers */
  requiredCredentials?: string[];
  /** Trust roots (principal DIDs) */
  trustRoots?: string[];
  /** Custom KeyProvider (default: InMemoryKeyProvider) */
  keyProvider?: KeyProvider;
  /** Custom audit log path */
  auditLogPath?: string;
  /** Custom reputation engine */
  reputationEngine?: ReputationEngine;
}

export interface TrustedAgent {
  /** Agent's DID */
  readonly did: string;
  /** Agent's key ID */
  readonly keyId: string;
  /** Agent's passport */
  readonly passport: AgentPassport;

  /** Issue a credential */
  issueCredential(options: {
    type: CredentialType;
    subjectDid: string;
    scope?: string[];
    maxDelegationDepth?: number;
    sensitivityLevel?: SensitivityLevel;
    expiresInMs?: number;
  }): Promise<VerifiableCredential>;

  /** Verify a credential */
  verifyCredential(vc: VerifiableCredential): Promise<{ valid: boolean; error?: string }>;

  /** Perform a handshake with a peer (simplified one-shot) */
  handshake(
    peerDid: string,
    peerPassport: AgentPassport,
    myCredentials: VerifiableCredential[],
    peerCredentials: VerifiableCredential[]
  ): Promise<{ session: SessionEstablished } | { error: string }>;

  /** Create a signed intent envelope */
  createIntent(
    action: string,
    scope: string[],
    principalDid: string,
    delegationChain?: string[],
    expiresInMs?: number
  ): Promise<IntentEnvelope>;

  /** Validate an intent from another agent */
  validateIntent(intent: IntentEnvelope): Promise<{ valid: boolean; error?: string }>;

  /** Add a reputation vouch for a peer */
  vouch(
    peerDid: string,
    polarity: 'positive' | 'negative',
    weight: number,
    reason?: string
  ): { allowed: boolean; reason?: string };

  /** Get reputation score for any agent */
  getReputation(did: string): ReputationScore;

  /** Get the audit log instance */
  getAuditLog(): AuditLog;

  /** Get the key provider */
  getKeyProvider(): KeyProvider;
}

// ─── Implementation ──────────────────────────────────────────────────

class TrustedAgentImpl implements TrustedAgent {
  readonly did: string;
  readonly keyId: string;
  readonly passport: AgentPassport;

  private keyProvider: KeyProvider;
  private auditLog: AuditLog;
  private reputationEngine: ReputationEngine;
  private rateLimiter = new HandshakeRateLimiter();
  private circuitBreaker = new HandshakeCircuitBreaker();
  private seenNonces = new Set<string>();

  constructor(
    identity: AgentIdentity,
    keyProvider: KeyProvider,
    passport: AgentPassport,
    auditLog: AuditLog,
    reputationEngine: ReputationEngine
  ) {
    this.did = identity.did;
    this.keyId = identity.keyId;
    this.keyProvider = keyProvider;
    this.passport = passport;
    this.auditLog = auditLog;
    this.reputationEngine = reputationEngine;
  }

  async issueCredential(options: {
    type: CredentialType;
    subjectDid: string;
    scope?: string[];
    maxDelegationDepth?: number;
    sensitivityLevel?: SensitivityLevel;
    expiresInMs?: number;
  }): Promise<VerifiableCredential> {
    const vc = await issueVC(this.keyProvider, {
      ...options,
      issuerDid: this.did,
      issuerKeyId: this.keyId,
    });

    await this.auditLog.log({
      eventType: 'vc_issued',
      actorDid: this.did,
      targetDid: options.subjectDid,
      result: 'success',
      metadata: { type: options.type },
    });

    return vc;
  }

  async verifyCredential(vc: VerifiableCredential) {
    const result = await verifyVC(vc);
    await this.auditLog.log({
      eventType: 'vc_verified',
      actorDid: this.did,
      targetDid: vc.credentialSubject.id,
      result: result.valid ? 'success' : 'failure',
      reason: result.error,
    });
    return { valid: result.valid, error: result.error };
  }

  async handshake(
    peerDid: string,
    peerPassport: AgentPassport,
    myCredentials: VerifiableCredential[],
    peerCredentials: VerifiableCredential[]
  ): Promise<{ session: SessionEstablished } | { error: string }> {
    // Rate limit
    const rateCheck = this.rateLimiter.check(this.did);
    if (!rateCheck.allowed) return { error: 'Rate limited' };

    // Circuit breaker
    const cbCheck = this.circuitBreaker.check(peerDid);
    if (!cbCheck.allowed) return { error: 'Circuit breaker open' };

    // Compatibility
    const issues = checkPassportCompatibility(this.passport, peerPassport);
    if (issues.length > 0) {
      this.circuitBreaker.recordFailure(peerDid);
      return { error: `Incompatible: ${issues.join(', ')}` };
    }

    const config: HandshakeConfig = {
      selfDid: this.did,
      selfKeyId: this.keyId,
      passport: this.passport,
      keyProvider: this.keyProvider,
      auditLog: this.auditLog,
    };

    const peerConfig: HandshakeConfig = {
      selfDid: peerDid,
      selfKeyId: '', // Not used for response processing
      passport: peerPassport,
      keyProvider: this.keyProvider, // Not used
    };

    // Steps 1-2
    const init = createHandshakeInit(config);
    const response = processInitAndRespond(init, peerConfig);
    if (response.type === 'handshake_error') {
      this.circuitBreaker.recordFailure(peerDid);
      return { error: response.message };
    }

    // Steps 3-4: Exchange and verify
    const myExchange = await createVCExchange(config, response.nonce, myCredentials);
    const myVerify = await verifyVCExchange(myExchange, response.nonce);
    if (!myVerify.valid) {
      this.circuitBreaker.recordFailure(peerDid);
      return { error: `My VC exchange failed: ${myVerify.error}` };
    }

    // Verify peer's credentials
    for (const vc of peerCredentials) {
      const result = await verifyVC(vc);
      if (!result.valid) {
        this.circuitBreaker.recordFailure(peerDid);
        return { error: `Peer VC invalid: ${result.error}` };
      }
    }

    // Step 5
    const session = createSessionEstablished(this.did, peerDid);

    this.circuitBreaker.recordSuccess(peerDid);
    await this.auditLog.log({
      eventType: 'handshake_complete',
      actorDid: this.did,
      targetDid: peerDid,
      result: 'success',
      metadata: { sessionId: session.sessionId },
    });

    return { session };
  }

  async createIntent(
    action: string,
    scope: string[],
    principalDid: string,
    delegationChain: string[] = [],
    expiresInMs?: number
  ): Promise<IntentEnvelope> {
    const intent = await createIntent(this.keyProvider, {
      action,
      scope,
      principalDid,
      agentDid: this.did,
      agentKeyId: this.keyId,
      delegationChain,
      expiresInMs,
    });

    await this.auditLog.log({
      eventType: 'intent_created',
      actorDid: this.did,
      intentId: intent.intentId,
      result: 'success',
      metadata: { action, scope },
    });

    return intent;
  }

  async validateIntent(intent: IntentEnvelope) {
    const result = await validateIntent(intent, this.seenNonces);
    await this.auditLog.log({
      eventType: result.valid ? 'intent_validated' : 'intent_rejected',
      actorDid: this.did,
      intentId: intent.intentId,
      result: result.valid ? 'success' : 'failure',
      reason: result.error,
    });
    return { valid: result.valid, error: result.error };
  }

  vouch(
    peerDid: string,
    polarity: 'positive' | 'negative',
    weight: number,
    reason?: string
  ) {
    return this.reputationEngine.addVouch({
      voucherDid: this.did,
      subjectDid: peerDid,
      polarity,
      weight,
      voucherVerified: true,
      reason: reason as any,
      timestamp: new Date().toISOString(),
    });
  }

  getReputation(did: string): ReputationScore {
    return this.reputationEngine.computeScore(did);
  }

  getAuditLog(): AuditLog {
    return this.auditLog;
  }

  getKeyProvider(): KeyProvider {
    return this.keyProvider;
  }
}

// ─── Factory ─────────────────────────────────────────────────────────

/**
 * Create a trusted agent — the main SDK entry point.
 *
 * @example
 * ```ts
 * import { createTrustedAgent } from '@sentinel/sdk';
 *
 * const agent = await createTrustedAgent({
 *   name: 'my-travel-bot',
 *   capabilities: ['flight_search', 'hotel_booking'],
 * });
 *
 * console.log(agent.did); // did:key:z6Mk...
 * ```
 */
export async function createTrustedAgent(config: TrustedAgentConfig): Promise<TrustedAgent> {
  const keyProvider = config.keyProvider ?? new InMemoryKeyProvider();
  const identity = await createIdentity(keyProvider, config.name);

  const passport = createPassport({
    did: identity.did,
    name: config.name,
    capabilities: config.capabilities,
    offeredCredentials: config.offeredCredentials,
    requiredCredentials: config.requiredCredentials,
    trustRoots: config.trustRoots,
  });

  // Set up audit log
  const auditDir = join(homedir(), '.sentinel');
  if (!existsSync(auditDir)) mkdirSync(auditDir, { recursive: true });
  const auditLogPath = config.auditLogPath ?? join(auditDir, `${config.name}-audit.jsonl`);
  const auditLog = new AuditLog({ logPath: auditLogPath });

  const reputationEngine = config.reputationEngine ?? new ReputationEngine();

  await auditLog.log({
    eventType: 'identity_created',
    actorDid: identity.did,
    result: 'success',
    metadata: { name: config.name },
  });

  return new TrustedAgentImpl(identity, keyProvider, passport, auditLog, reputationEngine);
}

// Re-export commonly needed types
export type {
  VerifiableCredential,
  IntentEnvelope,
  AgentPassport,
  SessionEstablished,
  ReputationScore,
  CredentialType,
  SensitivityLevel,
  KeyProvider,
};

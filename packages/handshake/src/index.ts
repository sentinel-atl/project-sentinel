/**
 * @sentinel-atl/handshake — Zero-Trust Agent Handshake Protocol
 *
 * Before two agents share ANY data, they must complete this 5-step mutual
 * verification. Both sides prove identity and exchange credentials.
 *
 * This is NOT like TLS (which verifies servers). This verifies AGENTS —
 * their identity, their authorization chain, and their reputation.
 *
 * Features no other agent protocol has:
 * - Protocol version negotiation (no silent downgrades)
 * - Per-DID rate limiting (prevents handshake DDoS)
 * - Configurable timeout + circuit breaker
 * - ±30s clock tolerance
 */

import {
  secureRandom,
  toHex,
  toBase64Url,
  fromBase64Url,
  textToBytes,
  verify,
  didToPublicKey,
  type VerifiableCredential,
  type AgentPassport,
  type KeyProvider,
  verifyVC,
} from '@sentinel-atl/core';
import type { AuditLog } from '@sentinel-atl/audit';

// ─── Protocol Messages ───────────────────────────────────────────────

export interface HandshakeInit {
  type: 'handshake_init';
  protocolVersion: string;
  initiatorDid: string;
  supportedVCTypes: string[];
  nonce: string;
  timestamp: string;
  passport: AgentPassport;
}

export interface HandshakeResponse {
  type: 'handshake_response';
  protocolVersion: string;
  responderDid: string;
  requestedVCTypes: string[];
  nonce: string;
  timestamp: string;
  passport: AgentPassport;
}

export interface VCExchangeMessage {
  type: 'vc_exchange';
  senderDid: string;
  credentials: VerifiableCredential[];
  /** Signature over (peer_nonce + own credentials), proving liveness */
  proofOfLiveness: string;
}

export interface SessionEstablished {
  type: 'session_established';
  sessionId: string;
  negotiatedVersion: string;
  initiatorDid: string;
  responderDid: string;
  createdAt: string;
  expiresAt: string;
}

export interface HandshakeError {
  type: 'handshake_error';
  code: 'VERSION_MISMATCH' | 'VC_VERIFICATION_FAILED' | 'RATE_LIMITED' | 'TIMEOUT' | 'CLOCK_SKEW' | 'TRUST_REQUIREMENTS_NOT_MET' | 'CIRCUIT_OPEN';
  message: string;
  retryAfterMs?: number;
}

export type HandshakeMessage =
  | HandshakeInit
  | HandshakeResponse
  | VCExchangeMessage
  | SessionEstablished
  | HandshakeError;

// ─── Rate Limiter ────────────────────────────────────────────────────

interface RateLimitEntry {
  count: number;
  windowStart: number;
}

export class HandshakeRateLimiter {
  private entries = new Map<string, RateLimitEntry>();
  private maxPerWindow: number;
  private windowMs: number;

  constructor(maxPerMinute = 10) {
    this.maxPerWindow = maxPerMinute;
    this.windowMs = 60_000;
  }

  check(did: string): { allowed: boolean; retryAfterMs?: number } {
    const now = Date.now();
    const entry = this.entries.get(did);

    if (!entry || now - entry.windowStart > this.windowMs) {
      this.entries.set(did, { count: 1, windowStart: now });
      return { allowed: true };
    }

    if (entry.count >= this.maxPerWindow) {
      const retryAfter = this.windowMs - (now - entry.windowStart);
      return { allowed: false, retryAfterMs: retryAfter };
    }

    entry.count++;
    return { allowed: true };
  }
}

// ─── Circuit Breaker ─────────────────────────────────────────────────

interface CircuitState {
  failures: number;
  lastFailure: number;
  open: boolean;
}

export class HandshakeCircuitBreaker {
  private circuits = new Map<string, CircuitState>();
  private threshold: number;
  private coolOffMs: number;

  constructor(failureThreshold = 5, coolOffMs = 60_000) {
    this.threshold = failureThreshold;
    this.coolOffMs = coolOffMs;
  }

  check(did: string): { allowed: boolean; retryAfterMs?: number } {
    const state = this.circuits.get(did);
    if (!state) return { allowed: true };

    if (state.open) {
      const elapsed = Date.now() - state.lastFailure;
      if (elapsed < this.coolOffMs) {
        return { allowed: false, retryAfterMs: this.coolOffMs - elapsed };
      }
      // Half-open: allow one attempt
      state.open = false;
      state.failures = 0;
      return { allowed: true };
    }

    return { allowed: true };
  }

  recordFailure(did: string): void {
    const state = this.circuits.get(did) ?? { failures: 0, lastFailure: 0, open: false };
    state.failures++;
    state.lastFailure = Date.now();
    if (state.failures >= this.threshold) {
      state.open = true;
    }
    this.circuits.set(did, state);
  }

  recordSuccess(did: string): void {
    this.circuits.delete(did);
  }
}

// ─── Handshake Session ───────────────────────────────────────────────

export interface HandshakeConfig {
  /** Our agent's DID */
  selfDid: string;
  /** Our agent's key ID for signing */
  selfKeyId: string;
  /** Our agent's passport */
  passport: AgentPassport;
  /** KeyProvider for signing operations */
  keyProvider: KeyProvider;
  /** Optional audit log */
  auditLog?: AuditLog;
  /** Handshake timeout in ms (default: 5000) */
  timeoutMs?: number;
  /** Clock skew tolerance in ms (default: 30000) */
  clockToleranceMs?: number;
}

const CLOCK_TOLERANCE_MS = 30_000;

/**
 * Create step 1: HandshakeInit message.
 */
export function createHandshakeInit(config: HandshakeConfig): HandshakeInit {
  return {
    type: 'handshake_init',
    protocolVersion: '1.0',
    initiatorDid: config.selfDid,
    supportedVCTypes: config.passport.offeredCredentials,
    nonce: toHex(secureRandom(32)),
    timestamp: new Date().toISOString(),
    passport: config.passport,
  };
}

/**
 * Process step 1 and create step 2: HandshakeResponse.
 */
export function processInitAndRespond(
  init: HandshakeInit,
  config: HandshakeConfig
): HandshakeResponse | HandshakeError {
  // Validate clock
  const initTime = new Date(init.timestamp).getTime();
  const now = Date.now();
  const tolerance = config.clockToleranceMs ?? CLOCK_TOLERANCE_MS;

  if (Math.abs(now - initTime) > tolerance) {
    return {
      type: 'handshake_error',
      code: 'CLOCK_SKEW',
      message: `Clock difference exceeds ${tolerance}ms tolerance`,
    };
  }

  // Check protocol version
  if (init.protocolVersion !== '1.0') {
    return {
      type: 'handshake_error',
      code: 'VERSION_MISMATCH',
      message: `Unsupported protocol version: ${init.protocolVersion}. Supported: 1.0`,
    };
  }

  return {
    type: 'handshake_response',
    protocolVersion: '1.0',
    responderDid: config.selfDid,
    requestedVCTypes: config.passport.requiredCredentials,
    nonce: toHex(secureRandom(32)),
    timestamp: new Date().toISOString(),
    passport: config.passport,
  };
}

/**
 * Create step 3/4: VC Exchange message with proof of liveness.
 */
export async function createVCExchange(
  config: HandshakeConfig,
  peerNonce: string,
  credentials: VerifiableCredential[]
): Promise<VCExchangeMessage> {
  // Proof of liveness: sign the peer's nonce + our credentials
  const livenessData = textToBytes(
    peerNonce + JSON.stringify(credentials.map((c) => c.id))
  );
  const sig = await config.keyProvider.sign(config.selfKeyId, livenessData);

  return {
    type: 'vc_exchange',
    senderDid: config.selfDid,
    credentials,
    proofOfLiveness: toBase64Url(sig),
  };
}

/**
 * Verify a VC Exchange message.
 */
export async function verifyVCExchange(
  exchange: VCExchangeMessage,
  ourNonce: string
): Promise<{ valid: boolean; error?: string }> {
  // 1. Verify proof of liveness
  const livenessData = textToBytes(
    ourNonce + JSON.stringify(exchange.credentials.map((c) => c.id))
  );
  const sig = fromBase64Url(exchange.proofOfLiveness);
  const senderPubKey = didToPublicKey(exchange.senderDid);

  const livenessValid = await verify(sig, livenessData, senderPubKey);
  if (!livenessValid) {
    return { valid: false, error: 'Proof of liveness failed' };
  }

  // 2. Verify each credential
  for (const vc of exchange.credentials) {
    const result = await verifyVC(vc);
    if (!result.valid) {
      return { valid: false, error: `VC verification failed: ${result.error}` };
    }
  }

  return { valid: true };
}

/**
 * Create the session established message after successful mutual verification.
 */
export function createSessionEstablished(
  initiatorDid: string,
  responderDid: string,
  sessionDurationMs = 3600_000 // Default: 1 hour
): SessionEstablished {
  const now = new Date();
  return {
    type: 'session_established',
    sessionId: toHex(secureRandom(16)),
    negotiatedVersion: '1.0',
    initiatorDid,
    responderDid,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + sessionDurationMs).toISOString(),
  };
}

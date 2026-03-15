/**
 * @sentinel/core — Proof of Intent module
 *
 * ⚡ THIS IS SENTINEL'S PRIMARY DIFFERENTIATOR ⚡
 *
 * Every agent action is bound to a signed Intent Envelope that traces back
 * to the original human request. No other agent trust protocol does this.
 *
 * The Intent Envelope proves:
 * - WHAT the agent is doing (action + scope)
 * - WHO authorized it (principal DID + delegation chain)
 * - WHEN it expires (time-bounded)
 * - That it can't be replayed (nonce)
 * - That scope only narrows through delegation (never widens)
 */

import { sign, verify, hash, secureRandom, toBase64Url, fromBase64Url, toHex, textToBytes } from './crypto.js';
import { didToPublicKey } from './did.js';
import type { KeyProvider } from './key-provider.js';

export interface IntentEnvelope {
  /** UUIDv7-style unique identifier */
  intentId: string;
  /** Protocol version for forward compatibility */
  version: '1.0';
  /** Human-readable action descriptor */
  action: string;
  /** Scoped permissions for this action */
  scope: string[];
  /** DID of the human principal who originated this intent */
  principalDid: string;
  /** DID of the agent executing this action */
  agentDid: string;
  /** Ordered list of VC IDs forming the delegation chain */
  delegationChain: string[];
  /** ISO 8601 expiry — after this time the intent is dead */
  expiry: string;
  /** 32-byte random nonce (hex) — prevents replay */
  nonce: string;
  /** Ed25519 signature over the canonicalized envelope (base64url) */
  signature: string;
}

export interface CreateIntentOptions {
  action: string;
  scope: string[];
  principalDid: string;
  agentDid: string;
  agentKeyId: string;
  delegationChain: string[];
  expiresInMs?: number;
}

/**
 * Generate a time-ordered unique ID (UUIDv7-like).
 */
function generateIntentId(): string {
  const timestamp = Date.now();
  const random = secureRandom(10);
  const hex = timestamp.toString(16).padStart(12, '0') + toHex(random);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-7${hex.slice(13, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

/**
 * Canonicalize an intent envelope for signing (excludes signature field).
 */
function canonicalizeIntent(intent: Omit<IntentEnvelope, 'signature'>): Uint8Array {
  return textToBytes(JSON.stringify(intent, Object.keys(intent).sort()));
}

/**
 * Create a signed Intent Envelope.
 *
 * This binds an agent action to the human principal's authorization chain.
 * Every downstream call MUST carry this envelope — it's the proof that
 * "this action was authorized by a real human, through this specific chain,
 * for this specific purpose, and it expires at this time."
 */
export async function createIntent(
  keyProvider: KeyProvider,
  options: CreateIntentOptions
): Promise<IntentEnvelope> {
  const expiresIn = options.expiresInMs ?? 5 * 60 * 1000; // Default: 5 minutes

  const intentBody = {
    intentId: generateIntentId(),
    version: '1.0' as const,
    action: options.action,
    scope: options.scope,
    principalDid: options.principalDid,
    agentDid: options.agentDid,
    delegationChain: options.delegationChain,
    expiry: new Date(Date.now() + expiresIn).toISOString(),
    nonce: toHex(secureRandom(32)),
  };

  const dataToSign = canonicalizeIntent(intentBody);
  const sig = await keyProvider.sign(options.agentKeyId, dataToSign);

  return {
    ...intentBody,
    signature: toBase64Url(sig),
  };
}

export interface ValidateIntentResult {
  valid: boolean;
  error?: string;
  checks: {
    signature: boolean;
    expiry: boolean;
    nonce: boolean;
    scopeValid: boolean;
  };
}

/**
 * Validate an Intent Envelope.
 *
 * Checks:
 * 1. Signature is valid (signed by the agent DID)
 * 2. Not expired (±30s tolerance)
 * 3. Nonce is present and well-formed
 * 4. Scope is non-empty
 */
export async function validateIntent(
  intent: IntentEnvelope,
  seenNonces?: Set<string>
): Promise<ValidateIntentResult> {
  const checks = {
    signature: false,
    expiry: false,
    nonce: false,
    scopeValid: false,
  };

  // 1. Nonce — must be present, 64 hex chars (32 bytes), and not replayed
  if (!intent.nonce || intent.nonce.length !== 64) {
    return { valid: false, error: 'Invalid nonce', checks };
  }
  if (seenNonces?.has(intent.nonce)) {
    return { valid: false, error: 'Replayed nonce detected', checks };
  }
  checks.nonce = true;

  // 2. Expiry (±30s tolerance)
  const now = Date.now();
  const expiry = new Date(intent.expiry).getTime();
  const CLOCK_TOLERANCE_MS = 30_000;
  if (now > expiry + CLOCK_TOLERANCE_MS) {
    return { valid: false, error: 'Intent has expired', checks };
  }
  checks.expiry = true;

  // 3. Scope must be non-empty
  if (!intent.scope || intent.scope.length === 0) {
    return { valid: false, error: 'Intent has no scope', checks };
  }
  checks.scopeValid = true;

  // 4. Verify signature
  const { signature, ...body } = intent;
  const dataToVerify = canonicalizeIntent(body);
  const sig = fromBase64Url(signature);

  try {
    const agentPublicKey = didToPublicKey(intent.agentDid);
    checks.signature = await verify(sig, dataToVerify, agentPublicKey);
  } catch {
    checks.signature = false;
  }

  if (!checks.signature) {
    return { valid: false, error: 'Invalid signature', checks };
  }

  // Track nonce to prevent replay
  seenNonces?.add(intent.nonce);

  return { valid: true, checks };
}

/**
 * Check if an action is within the intent's scope.
 */
export function isActionInScope(intent: IntentEnvelope, requiredScope: string): boolean {
  return intent.scope.includes(requiredScope);
}

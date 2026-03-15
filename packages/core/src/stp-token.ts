/**
 * @sentinel-atl/core — STP Token (Sentinel Trust Protocol Token)
 *
 * A compact, URL-safe token format for authenticating agent HTTP requests.
 * Structure: STP.<header-b64url>.<payload-b64url>.<signature-b64url>
 *
 * Similar to JWT but:
 * - Uses Ed25519 (not RS256/HS256)
 * - Carries agent-specific claims (scope, vcIds, intentId, reputation)
 * - Includes nonce for replay protection
 * - DID-based key resolution (no JWKS endpoints needed)
 */

import { sign, verify, toBase64Url, fromBase64Url, textToBytes, bytesToText, secureRandom, toHex } from './crypto.js';
import { didToPublicKey } from './did.js';
import type { KeyProvider } from './key-provider.js';

// ─── Types ───────────────────────────────────────────────────────────

export interface STPTokenHeader {
  alg: 'EdDSA';
  typ: 'STP+jwt';
  /** DID + key fragment, e.g. "did:key:z6Mk...#key-1" */
  kid: string;
}

export interface STPTokenPayload {
  /** Issuer: agent's DID */
  iss: string;
  /** Subject: target server DID or resource identifier */
  sub?: string;
  /** Audience: server URL this token is intended for */
  aud?: string;
  /** Issued-at: Unix timestamp in seconds */
  iat: number;
  /** Expiration: Unix timestamp in seconds */
  exp: number;
  /** Nonce: 32-byte random hex for replay protection */
  nonce: string;
  /** Requested scopes */
  scope?: string[];
  /** VC IDs backing the claimed scopes */
  vcIds?: string[];
  /** Associated intent envelope ID */
  intentId?: string;
  /** Self-reported reputation (server MUST re-verify) */
  reputation?: number;
}

export interface CreateSTPTokenOptions {
  /** Agent's DID */
  issuerDid: string;
  /** Key ID in the KeyProvider */
  keyId: string;
  /** Target server DID or resource */
  subject?: string;
  /** Server URL */
  audience?: string;
  /** Token lifetime in seconds (default: 300 = 5 minutes) */
  expiresInSec?: number;
  /** Scopes to claim */
  scope?: string[];
  /** VC IDs supporting the scopes */
  vcIds?: string[];
  /** Intent envelope ID */
  intentId?: string;
  /** Self-reported reputation */
  reputation?: number;
}

export interface VerifySTPTokenResult {
  valid: boolean;
  error?: string;
  header?: STPTokenHeader;
  payload?: STPTokenPayload;
  checks: {
    format: boolean;
    signature: boolean;
    expiry: boolean;
    nonce: boolean;
    audience: boolean;
  };
}

// ─── Constants ───────────────────────────────────────────────────────

const STP_PREFIX = 'STP';
const CLOCK_TOLERANCE_SEC = 30;

// ─── Create Token ────────────────────────────────────────────────────

/**
 * Create a signed STP Token.
 *
 * @example
 * ```ts
 * const token = await createSTPToken(keyProvider, {
 *   issuerDid: agent.did,
 *   keyId: agent.keyId,
 *   audience: 'https://trust.example.com',
 *   scope: ['flights:book'],
 * });
 * // Use: Authorization: STP <token>
 * ```
 */
export async function createSTPToken(
  keyProvider: KeyProvider,
  options: CreateSTPTokenOptions
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  const header: STPTokenHeader = {
    alg: 'EdDSA',
    typ: 'STP+jwt',
    kid: `${options.issuerDid}#key-1`,
  };

  const payload: STPTokenPayload = {
    iss: options.issuerDid,
    iat: now,
    exp: now + (options.expiresInSec ?? 300),
    nonce: toHex(secureRandom(32)),
  };

  if (options.subject) payload.sub = options.subject;
  if (options.audience) payload.aud = options.audience;
  if (options.scope) payload.scope = options.scope;
  if (options.vcIds) payload.vcIds = options.vcIds;
  if (options.intentId) payload.intentId = options.intentId;
  if (options.reputation !== undefined) payload.reputation = options.reputation;

  const headerB64 = toBase64Url(textToBytes(JSON.stringify(header)));
  const payloadB64 = toBase64Url(textToBytes(JSON.stringify(payload)));
  const signingInput = textToBytes(`${headerB64}.${payloadB64}`);

  const signature = await keyProvider.sign(options.keyId, signingInput);
  const signatureB64 = toBase64Url(signature);

  return `${STP_PREFIX}.${headerB64}.${payloadB64}.${signatureB64}`;
}

// ─── Verify Token ────────────────────────────────────────────────────

/**
 * Verify an STP Token. Checks format, signature, expiry, and nonce.
 *
 * @param token - The full STP token string
 * @param seenNonces - Set of previously seen nonces (for replay protection)
 * @param expectedAudience - If set, verify the `aud` claim matches
 */
export async function verifySTPToken(
  token: string,
  seenNonces?: Set<string>,
  expectedAudience?: string
): Promise<VerifySTPTokenResult> {
  const checks = {
    format: false,
    signature: false,
    expiry: false,
    nonce: false,
    audience: false,
  };

  // 1. Format check
  const parts = token.split('.');
  if (parts.length !== 4 || parts[0] !== STP_PREFIX) {
    return { valid: false, error: 'Invalid STP token format: expected STP.<header>.<payload>.<signature>', checks };
  }

  let header: STPTokenHeader;
  let payload: STPTokenPayload;

  try {
    header = JSON.parse(bytesToText(fromBase64Url(parts[1])));
    payload = JSON.parse(bytesToText(fromBase64Url(parts[2])));
  } catch {
    return { valid: false, error: 'Failed to decode token header/payload', checks };
  }

  if (header.alg !== 'EdDSA' || header.typ !== 'STP+jwt') {
    return { valid: false, error: `Unsupported algorithm or type: ${header.alg}/${header.typ}`, checks };
  }

  if (!header.kid || !payload.iss || !payload.iat || !payload.exp || !payload.nonce) {
    return { valid: false, error: 'Missing required token fields', checks };
  }

  checks.format = true;

  // 2. Signature verification
  try {
    // Extract DID from kid (format: "did:key:z6Mk...#key-1")
    const did = header.kid.split('#')[0];
    if (did !== payload.iss) {
      return { valid: false, error: 'Token kid DID does not match iss claim', checks, header, payload };
    }

    const publicKey = didToPublicKey(did);
    const signingInput = textToBytes(`${parts[1]}.${parts[2]}`);
    const signature = fromBase64Url(parts[3]);

    const sigValid = await verify(signature, signingInput, publicKey);
    if (!sigValid) {
      return { valid: false, error: 'Invalid signature', checks, header, payload };
    }
    checks.signature = true;
  } catch (e) {
    return { valid: false, error: `Signature verification failed: ${(e as Error).message}`, checks, header, payload };
  }

  // 3. Expiry check (with ±30s tolerance)
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now - CLOCK_TOLERANCE_SEC) {
    return { valid: false, error: 'Token has expired', checks, header, payload };
  }
  if (payload.iat > now + CLOCK_TOLERANCE_SEC) {
    return { valid: false, error: 'Token issued in the future', checks, header, payload };
  }
  checks.expiry = true;

  // 4. Nonce replay check
  if (seenNonces) {
    if (seenNonces.has(payload.nonce)) {
      return { valid: false, error: 'Nonce has already been used (replay detected)', checks, header, payload };
    }
    seenNonces.add(payload.nonce);
  }
  checks.nonce = true;

  // 5. Audience check
  if (expectedAudience && payload.aud && payload.aud !== expectedAudience) {
    return { valid: false, error: `Audience mismatch: expected ${expectedAudience}, got ${payload.aud}`, checks, header, payload };
  }
  checks.audience = true;

  return { valid: true, header, payload, checks };
}

/**
 * Decode an STP Token without verifying it.
 * Useful for inspecting claims before full verification.
 */
export function decodeSTPToken(token: string): { header: STPTokenHeader; payload: STPTokenPayload } | null {
  const parts = token.split('.');
  if (parts.length !== 4 || parts[0] !== STP_PREFIX) return null;

  try {
    const header = JSON.parse(bytesToText(fromBase64Url(parts[1]))) as STPTokenHeader;
    const payload = JSON.parse(bytesToText(fromBase64Url(parts[2]))) as STPTokenPayload;
    return { header, payload };
  } catch {
    return null;
  }
}

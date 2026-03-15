/**
 * @sentinel-atl/core — Verifiable Credentials (VC) module
 *
 * W3C Verifiable Credentials Data Model v2.0 implementation.
 * Supports: AgentAuthorizationCredential, DelegationCredential,
 *           ReputationCredential, NegativeReputationCredential.
 *
 * Every credential is Ed25519-signed and bound to a DID.
 * This is what makes Sentinel different from API keys — credentials are
 * scoped, time-bounded, non-forgeable, and carry the full delegation chain.
 */

import { sign, verify, hash, toBase64Url, fromBase64Url, textToBytes, toHex, secureRandom } from './crypto.js';
import { didToPublicKey } from './did.js';
import type { KeyProvider } from './key-provider.js';

export type CredentialType =
  | 'AgentAuthorizationCredential'
  | 'DelegationCredential'
  | 'ComplianceCredential'
  | 'ReputationCredential'
  | 'NegativeReputationCredential'
  | 'CodeAttestationCredential';

export type SensitivityLevel = 'low' | 'medium' | 'high' | 'critical';

export type NegativeReason =
  | 'timeout'
  | 'incorrect_output'
  | 'scope_violation'
  | 'content_safety'
  | 'unresponsive'
  | 'data_leak';

export interface CredentialSubject {
  id: string; // Subject DID
  scope?: string[];
  maxDelegationDepth?: number;
  sensitivityLevel?: SensitivityLevel;
  parentIntent?: string;
  // Negative reputation
  reason?: NegativeReason;
  details?: string;
  // Code attestation
  codeHash?: string;
  buildSignature?: string;
}

export interface CredentialProof {
  type: 'Ed25519Signature2020';
  created: string;
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
  proofValue: string; // base64url-encoded signature
}

export interface VerifiableCredential {
  '@context': string[];
  id: string;
  type: ['VerifiableCredential', CredentialType];
  issuer: string; // Issuer DID
  issuanceDate: string;
  expirationDate: string;
  credentialSubject: CredentialSubject;
  proof: CredentialProof;
}

export interface IssueVCOptions {
  type: CredentialType;
  issuerDid: string;
  issuerKeyId: string;
  subjectDid: string;
  scope?: string[];
  maxDelegationDepth?: number;
  sensitivityLevel?: SensitivityLevel;
  parentIntent?: string;
  expiresInMs?: number;
  // For negative reputation
  reason?: NegativeReason;
  details?: string;
  // For code attestation
  codeHash?: string;
  buildSignature?: string;
}

/**
 * Generate a unique credential ID using crypto-random bytes.
 */
function generateCredentialId(): string {
  const bytes = secureRandom(16);
  return `urn:uuid:${toHex(bytes.slice(0, 4))}-${toHex(bytes.slice(4, 6))}-${toHex(bytes.slice(6, 8))}-${toHex(bytes.slice(8, 10))}-${toHex(bytes.slice(10, 16))}`;
}

/**
 * Canonicalize a credential for signing.
 * Deterministic JSON serialization with recursively sorted keys.
 */
function canonicalize(vc: Omit<VerifiableCredential, 'proof'>): Uint8Array {
  return textToBytes(JSON.stringify(sortDeep(vc)));
}

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value !== null && typeof value === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

/**
 * Issue a new Verifiable Credential.
 *
 * This is the core VC creation function. It:
 * 1. Builds the credential body
 * 2. Canonicalizes it for signing
 * 3. Signs with the issuer's Ed25519 key
 * 4. Attaches the proof
 */
export async function issueVC(
  keyProvider: KeyProvider,
  options: IssueVCOptions
): Promise<VerifiableCredential> {
  const now = new Date();
  const expiresIn = options.expiresInMs ?? 24 * 60 * 60 * 1000; // Default: 24h
  const expiry = new Date(now.getTime() + expiresIn);

  const subject: CredentialSubject = {
    id: options.subjectDid,
  };

  if (options.scope) subject.scope = options.scope;
  if (options.maxDelegationDepth !== undefined) subject.maxDelegationDepth = options.maxDelegationDepth;
  if (options.sensitivityLevel) subject.sensitivityLevel = options.sensitivityLevel;
  if (options.parentIntent) subject.parentIntent = options.parentIntent;
  if (options.reason) subject.reason = options.reason;
  if (options.details) subject.details = options.details;
  if (options.codeHash) subject.codeHash = options.codeHash;
  if (options.buildSignature) subject.buildSignature = options.buildSignature;

  const vcBody = {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://sentinel-protocol.org/ns/v1',
    ],
    id: generateCredentialId(),
    type: ['VerifiableCredential', options.type] as ['VerifiableCredential', CredentialType],
    issuer: options.issuerDid,
    issuanceDate: now.toISOString(),
    expirationDate: expiry.toISOString(),
    credentialSubject: subject,
  };

  // Sign the canonicalized credential body
  const dataToSign = canonicalize(vcBody);
  const signature = await keyProvider.sign(options.issuerKeyId, dataToSign);

  const proof: CredentialProof = {
    type: 'Ed25519Signature2020',
    created: now.toISOString(),
    verificationMethod: `${options.issuerDid}#key-1`,
    proofPurpose: 'assertionMethod',
    proofValue: toBase64Url(signature),
  };

  return { ...vcBody, proof };
}

export interface VerifyVCResult {
  valid: boolean;
  error?: string;
  checks: {
    signature: boolean;
    expiry: boolean;
    issuerResolvable: boolean;
  };
}

/**
 * Verify a Verifiable Credential.
 *
 * Checks:
 * 1. Signature validity (Ed25519)
 * 2. Expiration (with ±30s clock tolerance)
 * 3. Issuer DID is resolvable
 */
export async function verifyVC(vc: VerifiableCredential): Promise<VerifyVCResult> {
  const checks = {
    signature: false,
    expiry: false,
    issuerResolvable: false,
  };

  // 1. Resolve issuer's public key from DID
  let issuerPublicKey: Uint8Array;
  try {
    issuerPublicKey = didToPublicKey(vc.issuer);
    checks.issuerResolvable = true;
  } catch {
    return { valid: false, error: `Cannot resolve issuer DID: ${vc.issuer}`, checks };
  }

  // 2. Check expiration (±30s tolerance)
  const now = Date.now();
  const expiry = new Date(vc.expirationDate).getTime();
  const CLOCK_TOLERANCE_MS = 30_000;
  if (now > expiry + CLOCK_TOLERANCE_MS) {
    checks.expiry = false;
    return { valid: false, error: 'Credential has expired', checks };
  }
  checks.expiry = true;

  // 3. Verify signature
  const { proof, ...vcBody } = vc;
  const dataToVerify = canonicalize(vcBody);
  const signature = fromBase64Url(proof.proofValue);

  try {
    checks.signature = await verify(signature, dataToVerify, issuerPublicKey);
  } catch {
    checks.signature = false;
  }

  if (!checks.signature) {
    return { valid: false, error: 'Invalid signature', checks };
  }

  return { valid: true, checks };
}

/**
 * Validate scope narrowing in a delegation chain.
 *
 * Rule: each delegation can only NARROW scope, never widen.
 * This is what prevents privilege escalation through sub-agents.
 */
export function validateScopeNarrowing(
  parentScope: string[],
  childScope: string[]
): { valid: boolean; error?: string } {
  for (const scope of childScope) {
    if (!parentScope.includes(scope)) {
      return {
        valid: false,
        error: `Scope "${scope}" not present in parent scope. Delegation can only narrow, not widen.`,
      };
    }
  }
  return { valid: true };
}

/**
 * Validate a full delegation chain.
 *
 * Walks the chain from root (human principal) to leaf (current agent) and verifies:
 * 1. Each VC in the chain is valid
 * 2. Scope only narrows at each hop
 * 3. Delegation depth doesn't exceed maxDelegationDepth
 */
export async function validateDelegationChain(
  chain: VerifiableCredential[]
): Promise<{ valid: boolean; error?: string; depth: number }> {
  if (chain.length === 0) {
    return { valid: false, error: 'Empty delegation chain', depth: 0 };
  }

  let currentScope: string[] | undefined;
  let maxDepth = Infinity;

  for (let i = 0; i < chain.length; i++) {
    const vc = chain[i];

    // Verify each VC
    const result = await verifyVC(vc);
    if (!result.valid) {
      return { valid: false, error: `VC at depth ${i} invalid: ${result.error}`, depth: i };
    }

    // Check delegation depth
    if (i >= maxDepth) {
      return {
        valid: false,
        error: `Delegation depth ${i} exceeds maxDelegationDepth ${maxDepth}`,
        depth: i,
      };
    }

    // Check scope narrowing
    const vcScope = vc.credentialSubject.scope;
    if (vcScope && currentScope) {
      const scopeResult = validateScopeNarrowing(currentScope, vcScope);
      if (!scopeResult.valid) {
        return { valid: false, error: `At depth ${i}: ${scopeResult.error}`, depth: i };
      }
    }

    currentScope = vcScope ?? currentScope;
    if (vc.credentialSubject.maxDelegationDepth !== undefined) {
      maxDepth = vc.credentialSubject.maxDelegationDepth;
    }
  }

  return { valid: true, depth: chain.length };
}

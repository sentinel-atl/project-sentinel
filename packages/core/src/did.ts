/**
 * @sentinel/core — DID (Decentralized Identifier) module
 *
 * Implements did:key method using Ed25519 public keys.
 * Format: did:key:z6Mk<base58btc-encoded-multicodec-key>
 *
 * This is the identity foundation of the Agent Trust Layer.
 * Every agent gets a DID. No central registry. No gatekeeper.
 */

import { toBase64Url, fromBase64Url } from './crypto.js';
import type { KeyProvider } from './key-provider.js';

// Multicodec prefix for Ed25519 public key: 0xed01
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

// Base58btc alphabet (Bitcoin flavor)
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58btcEncode(bytes: Uint8Array): string {
  // Convert bytes to a big integer
  let num = 0n;
  for (const byte of bytes) {
    num = num * 256n + BigInt(byte);
  }

  // Encode to base58
  let encoded = '';
  while (num > 0n) {
    const remainder = Number(num % 58n);
    num = num / 58n;
    encoded = BASE58_ALPHABET[remainder] + encoded;
  }

  // Preserve leading zeros
  for (const byte of bytes) {
    if (byte === 0) {
      encoded = '1' + encoded;
    } else {
      break;
    }
  }

  return encoded;
}

function base58btcDecode(str: string): Uint8Array {
  let num = 0n;
  for (const char of str) {
    const index = BASE58_ALPHABET.indexOf(char);
    if (index === -1) throw new Error(`Invalid base58 character: ${char}`);
    num = num * 58n + BigInt(index);
  }

  // Convert big integer to bytes
  const hex = num.toString(16).padStart(2, '0');
  const paddedHex = hex.length % 2 ? '0' + hex : hex;
  const bytes: number[] = [];
  for (let i = 0; i < paddedHex.length; i += 2) {
    bytes.push(parseInt(paddedHex.substring(i, i + 2), 16));
  }

  // Restore leading zeros
  let leadingZeros = 0;
  for (const char of str) {
    if (char === '1') leadingZeros++;
    else break;
  }

  return new Uint8Array([...new Array(leadingZeros).fill(0), ...bytes]);
}

export interface DIDDocument {
  '@context': string[];
  id: string;
  verificationMethod: Array<{
    id: string;
    type: string;
    controller: string;
    publicKeyMultibase: string;
  }>;
  authentication: string[];
  assertionMethod: string[];
  keyAgreement?: Array<{
    id: string;
    type: string;
    controller: string;
    publicKeyMultibase: string;
  }>;
}

export interface AgentIdentity {
  did: string;
  keyId: string;
  publicKey: Uint8Array;
  createdAt: string;
}

/**
 * Create a did:key from an Ed25519 public key.
 * Format: did:key:z<base58btc(multicodec_prefix + public_key)>
 */
export function publicKeyToDid(publicKey: Uint8Array): string {
  const multicodecKey = new Uint8Array(ED25519_MULTICODEC_PREFIX.length + publicKey.length);
  multicodecKey.set(ED25519_MULTICODEC_PREFIX);
  multicodecKey.set(publicKey, ED25519_MULTICODEC_PREFIX.length);
  return `did:key:z${base58btcEncode(multicodecKey)}`;
}

/**
 * Extract the Ed25519 public key from a did:key string.
 */
export function didToPublicKey(did: string): Uint8Array {
  if (!did.startsWith('did:key:z')) {
    throw new Error(`Unsupported DID method: ${did}`);
  }
  const multibase = did.slice('did:key:z'.length);
  const decoded = base58btcDecode(multibase);

  // Verify multicodec prefix
  if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error('Invalid multicodec prefix: expected Ed25519 (0xed01)');
  }

  return decoded.slice(2);
}

/**
 * Generate a minimal DID Document from a did:key.
 */
export function resolveDid(did: string): DIDDocument {
  const multibase = did.slice('did:key:'.length);
  const verificationMethodId = `${did}#${multibase}`;

  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
    ],
    id: did,
    verificationMethod: [
      {
        id: verificationMethodId,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase: multibase,
      },
    ],
    authentication: [verificationMethodId],
    assertionMethod: [verificationMethodId],
  };
}

/**
 * Create a new agent identity: generate a keypair, store it, return the DID.
 */
export async function createIdentity(
  keyProvider: KeyProvider,
  keyId?: string
): Promise<AgentIdentity> {
  const id = keyId ?? `agent-${Date.now()}`;
  const keyPair = await keyProvider.generate(id);
  const did = publicKeyToDid(keyPair.publicKey);

  return {
    did,
    keyId: id,
    publicKey: keyPair.publicKey,
    createdAt: new Date().toISOString(),
  };
}

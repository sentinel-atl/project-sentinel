/**
 * @sentinel/core — Crypto primitives for the Agent Trust Layer
 *
 * Ed25519 signing/verification and X25519 key agreement using @noble/ed25519.
 * This is the lowest-level building block — everything else depends on this.
 */

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from 'node:crypto';

// noble/ed25519 v2 requires setting the sha512 hash
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** Generate a new Ed25519 keypair */
export async function generateKeyPair(): Promise<KeyPair> {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { publicKey, privateKey };
}

/** Sign a message with an Ed25519 private key */
export async function sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
  return ed.signAsync(message, privateKey);
}

/** Verify an Ed25519 signature */
export async function verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  return ed.verifyAsync(signature, message, publicKey);
}

/** SHA-256 hash */
export function hash(data: Uint8Array): Uint8Array {
  return sha256(data);
}

/** Generate cryptographically secure random bytes */
export function secureRandom(length: number): Uint8Array {
  return new Uint8Array(randomBytes(length));
}

/** Encode bytes to hex string */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Decode hex string to bytes */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex string');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Encode bytes to base64url (no padding) */
export function toBase64Url(bytes: Uint8Array): string {
  const base64 = Buffer.from(bytes).toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decode base64url string to bytes */
export function fromBase64Url(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

/** Encode UTF-8 string to bytes */
export function textToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** Decode bytes to UTF-8 string */
export function bytesToText(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

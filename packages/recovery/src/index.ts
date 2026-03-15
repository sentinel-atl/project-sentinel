/**
 * @sentinel-atl/recovery — Key Backup & Recovery via Shamir's Secret Sharing
 *
 * When an agent's key is lost, the identity is gone — all VCs become
 * unverifiable. This module implements Shamir's Secret Sharing to split
 * a private key into N shares requiring K to reconstruct (default: 3-of-5).
 *
 * Recovery is OFFLINE-FIRST — no network call required.
 * Shares are meant to be distributed to trusted parties.
 */

import { secureRandom, toHex, fromHex, toBase64Url, fromBase64Url } from '@sentinel-atl/core';
import { randomBytes } from 'node:crypto';

/**
 * GF(256) arithmetic for Shamir's Secret Sharing.
 * Operations in the Galois Field GF(2^8) using the irreducible polynomial x^8 + x^4 + x^3 + x + 1.
 */

// Precompute log and exp tables for GF(256)
const EXP_TABLE = new Uint8Array(512);
const LOG_TABLE = new Uint8Array(256);

(function initGF256Tables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP_TABLE[i] = x;
    LOG_TABLE[x] = i;
    x = x ^ (x << 1);
    if (x & 0x100) x ^= 0x11b; // Reduce by x^8 + x^4 + x^3 + x + 1
  }
  // Fill the second half for wraparound
  for (let i = 255; i < 512; i++) {
    EXP_TABLE[i] = EXP_TABLE[i - 255];
  }
})();

function gf256Add(a: number, b: number): number {
  return a ^ b;
}

function gf256Mul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP_TABLE[LOG_TABLE[a] + LOG_TABLE[b]];
}

function gf256Div(a: number, b: number): number {
  if (b === 0) throw new Error('Division by zero in GF(256)');
  if (a === 0) return 0;
  return EXP_TABLE[(LOG_TABLE[a] - LOG_TABLE[b] + 255) % 255];
}

/**
 * Evaluate a polynomial at point x in GF(256).
 * coefficients[0] is the constant term (the secret).
 */
function evaluatePolynomial(coefficients: Uint8Array, x: number): number {
  let result = 0;
  for (let i = coefficients.length - 1; i >= 0; i--) {
    result = gf256Add(gf256Mul(result, x), coefficients[i]);
  }
  return result;
}

/**
 * Lagrange interpolation at x=0 in GF(256) to recover the secret.
 */
function lagrangeInterpolate(points: Array<{ x: number; y: number }>): number {
  let secret = 0;
  for (let i = 0; i < points.length; i++) {
    let numerator = 1;
    let denominator = 1;
    for (let j = 0; j < points.length; j++) {
      if (i === j) continue;
      numerator = gf256Mul(numerator, points[j].x);
      denominator = gf256Mul(denominator, gf256Add(points[i].x, points[j].x));
    }
    const lagrangeBasis = gf256Div(numerator, denominator);
    secret = gf256Add(secret, gf256Mul(points[i].y, lagrangeBasis));
  }
  return secret;
}

export interface Share {
  /** Share index (1-based, used as the x-coordinate) */
  index: number;
  /** Base64url-encoded share data */
  data: string;
  /** Total number of shares created */
  totalShares: number;
  /** Minimum shares needed to reconstruct */
  threshold: number;
}

/**
 * Split a secret into N shares requiring K to reconstruct.
 *
 * Default: 5 shares, 3 required (3-of-5).
 * Each byte of the secret gets its own random polynomial.
 */
export function splitSecret(
  secret: Uint8Array,
  totalShares = 5,
  threshold = 3
): Share[] {
  if (threshold > totalShares) {
    throw new Error('Threshold cannot exceed total shares');
  }
  if (threshold < 2) {
    throw new Error('Threshold must be at least 2');
  }
  if (totalShares > 255) {
    throw new Error('Maximum 255 shares (GF(256) constraint)');
  }

  const shares: Share[] = [];

  // Initialize share data arrays
  const shareData: Uint8Array[] = [];
  for (let s = 0; s < totalShares; s++) {
    shareData.push(new Uint8Array(secret.length));
  }

  // For each byte of the secret, create a random polynomial and evaluate
  for (let byteIndex = 0; byteIndex < secret.length; byteIndex++) {
    // Random polynomial coefficients: [secret_byte, random, random, ...]
    const coefficients = new Uint8Array(threshold);
    coefficients[0] = secret[byteIndex];
    const randomCoeffs = new Uint8Array(randomBytes(threshold - 1));
    coefficients.set(randomCoeffs, 1);

    // Evaluate polynomial at x = 1, 2, ..., totalShares
    for (let s = 0; s < totalShares; s++) {
      shareData[s][byteIndex] = evaluatePolynomial(coefficients, s + 1);
    }
  }

  // Package shares
  for (let s = 0; s < totalShares; s++) {
    shares.push({
      index: s + 1,
      data: toBase64Url(shareData[s]),
      totalShares,
      threshold,
    });
  }

  return shares;
}

/**
 * Reconstruct a secret from K shares.
 *
 * The order of shares doesn't matter. Duplicate indices will throw.
 */
export function reconstructSecret(shares: Share[]): Uint8Array {
  if (shares.length === 0) {
    throw new Error('No shares provided');
  }

  const threshold = shares[0].threshold;
  if (shares.length < threshold) {
    throw new Error(`Need at least ${threshold} shares, got ${shares.length}`);
  }

  // Check for duplicate indices
  const indices = new Set(shares.map((s) => s.index));
  if (indices.size !== shares.length) {
    throw new Error('Duplicate share indices');
  }

  // Decode share data
  const shareArrays = shares.map((s) => ({
    x: s.index,
    data: fromBase64Url(s.data),
  }));

  const secretLength = shareArrays[0].data.length;
  const secret = new Uint8Array(secretLength);

  // Reconstruct each byte using Lagrange interpolation at x=0
  for (let byteIndex = 0; byteIndex < secretLength; byteIndex++) {
    const points = shareArrays.map((s) => ({
      x: s.x,
      y: s.data[byteIndex],
    }));
    secret[byteIndex] = lagrangeInterpolate(points);
  }

  return secret;
}

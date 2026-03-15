/**
 * STP Token tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  createSTPToken,
  verifySTPToken,
  decodeSTPToken,
  createIdentity,
  InMemoryKeyProvider,
  type KeyProvider,
  type AgentIdentity,
} from '../index.js';

describe('STP Token', () => {
  let kp: KeyProvider;
  let identity: AgentIdentity;

  beforeEach(async () => {
    kp = new InMemoryKeyProvider();
    identity = await createIdentity(kp, 'test-agent');
  });

  describe('createSTPToken', () => {
    it('should create a well-formed STP token', async () => {
      const token = await createSTPToken(kp, {
        issuerDid: identity.did,
        keyId: identity.keyId,
      });

      expect(token).toMatch(/^STP\..+\..+\..+$/);
      const parts = token.split('.');
      expect(parts).toHaveLength(4);
      expect(parts[0]).toBe('STP');
    });

    it('should include all optional claims', async () => {
      const token = await createSTPToken(kp, {
        issuerDid: identity.did,
        keyId: identity.keyId,
        subject: 'did:key:z6MkServer',
        audience: 'https://trust.example.com',
        scope: ['flights:book', 'flights:search'],
        vcIds: ['urn:uuid:vc-1'],
        intentId: 'intent-123',
        reputation: 75,
        expiresInSec: 600,
      });

      const decoded = decodeSTPToken(token);
      expect(decoded).not.toBeNull();
      expect(decoded!.payload.sub).toBe('did:key:z6MkServer');
      expect(decoded!.payload.aud).toBe('https://trust.example.com');
      expect(decoded!.payload.scope).toEqual(['flights:book', 'flights:search']);
      expect(decoded!.payload.vcIds).toEqual(['urn:uuid:vc-1']);
      expect(decoded!.payload.intentId).toBe('intent-123');
      expect(decoded!.payload.reputation).toBe(75);
    });

    it('should set correct header fields', async () => {
      const token = await createSTPToken(kp, {
        issuerDid: identity.did,
        keyId: identity.keyId,
      });

      const decoded = decodeSTPToken(token);
      expect(decoded!.header.alg).toBe('EdDSA');
      expect(decoded!.header.typ).toBe('STP+jwt');
      expect(decoded!.header.kid).toBe(`${identity.did}#key-1`);
    });

    it('should use default 5-minute expiry', async () => {
      const token = await createSTPToken(kp, {
        issuerDid: identity.did,
        keyId: identity.keyId,
      });

      const decoded = decodeSTPToken(token);
      expect(decoded!.payload.exp - decoded!.payload.iat).toBe(300);
    });
  });

  describe('verifySTPToken', () => {
    it('should verify a valid token', async () => {
      const token = await createSTPToken(kp, {
        issuerDid: identity.did,
        keyId: identity.keyId,
      });

      const result = await verifySTPToken(token);
      expect(result.valid).toBe(true);
      expect(result.checks.format).toBe(true);
      expect(result.checks.signature).toBe(true);
      expect(result.checks.expiry).toBe(true);
      expect(result.checks.nonce).toBe(true);
      expect(result.checks.audience).toBe(true);
    });

    it('should reject a tampered token', async () => {
      const token = await createSTPToken(kp, {
        issuerDid: identity.did,
        keyId: identity.keyId,
      });

      // Tamper with payload by replacing a character
      const parts = token.split('.');
      parts[2] = parts[2].slice(0, -1) + 'X';
      const tampered = parts.join('.');

      const result = await verifySTPToken(tampered);
      expect(result.valid).toBe(false);
    });

    it('should reject an expired token', async () => {
      const token = await createSTPToken(kp, {
        issuerDid: identity.did,
        keyId: identity.keyId,
        expiresInSec: -60, // Already expired
      });

      const result = await verifySTPToken(token);
      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/expired/i);
    });

    it('should detect nonce replay', async () => {
      const token = await createSTPToken(kp, {
        issuerDid: identity.did,
        keyId: identity.keyId,
      });

      const seenNonces = new Set<string>();

      const r1 = await verifySTPToken(token, seenNonces);
      expect(r1.valid).toBe(true);

      const r2 = await verifySTPToken(token, seenNonces);
      expect(r2.valid).toBe(false);
      expect(r2.error).toMatch(/replay/i);
    });

    it('should verify audience when expected', async () => {
      const token = await createSTPToken(kp, {
        issuerDid: identity.did,
        keyId: identity.keyId,
        audience: 'https://trust.example.com',
      });

      const good = await verifySTPToken(token, undefined, 'https://trust.example.com');
      expect(good.valid).toBe(true);

      const token2 = await createSTPToken(kp, {
        issuerDid: identity.did,
        keyId: identity.keyId,
        audience: 'https://other.example.com',
      });

      const bad = await verifySTPToken(token2, undefined, 'https://trust.example.com');
      expect(bad.valid).toBe(false);
      expect(bad.error).toMatch(/audience/i);
    });

    it('should reject invalid format', async () => {
      const r1 = await verifySTPToken('not-a-token');
      expect(r1.valid).toBe(false);
      expect(r1.checks.format).toBe(false);

      const r2 = await verifySTPToken('JWT.a.b.c');
      expect(r2.valid).toBe(false);
    });

    it('should reject token with wrong kid/iss mismatch', async () => {
      const token = await createSTPToken(kp, {
        issuerDid: identity.did,
        keyId: identity.keyId,
      });

      // Manually replace the iss claim to create a mismatch
      const parts = token.split('.');
      const payload = JSON.parse(Buffer.from(parts[2].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
      payload.iss = 'did:key:z6MkWrongDid';
      const newPayload = Buffer.from(JSON.stringify(payload)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const faked = `${parts[0]}.${parts[1]}.${newPayload}.${parts[3]}`;

      const result = await verifySTPToken(faked);
      expect(result.valid).toBe(false);
    });
  });

  describe('decodeSTPToken', () => {
    it('should decode without verification', async () => {
      const token = await createSTPToken(kp, {
        issuerDid: identity.did,
        keyId: identity.keyId,
        scope: ['test:read'],
      });

      const decoded = decodeSTPToken(token);
      expect(decoded).not.toBeNull();
      expect(decoded!.payload.iss).toBe(identity.did);
      expect(decoded!.payload.scope).toEqual(['test:read']);
    });

    it('should return null for invalid tokens', () => {
      expect(decodeSTPToken('garbage')).toBeNull();
      expect(decodeSTPToken('JWT.a.b.c')).toBeNull();
      expect(decodeSTPToken('STP.not-valid-base64.x.y')).toBeNull();
    });
  });
});

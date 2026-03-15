import { describe, it, expect, beforeEach } from 'vitest';
import { RevocationManager, type RevocationReason } from '../index.js';
import {
  generateKeyPair,
  InMemoryKeyProvider,
  publicKeyToDid,
} from '@sentinel/core';

async function makeIdentity(keyProvider: InMemoryKeyProvider, name: string) {
  await keyProvider.generate(name);
  const pubKey = await keyProvider.getPublicKey(name);
  const did = publicKeyToDid(pubKey);
  return { keyId: name, did };
}

describe('@sentinel/revocation', () => {
  let keyProvider: InMemoryKeyProvider;
  let manager: RevocationManager;
  let admin: { keyId: string; did: string };
  let agentA: { keyId: string; did: string };
  let agentB: { keyId: string; did: string };

  beforeEach(async () => {
    keyProvider = new InMemoryKeyProvider();
    manager = new RevocationManager();
    admin = await makeIdentity(keyProvider, 'admin');
    agentA = await makeIdentity(keyProvider, 'agentA');
    agentB = await makeIdentity(keyProvider, 'agentB');
  });

  // ─── VC Revocation ────────────────────────────────────────────────

  describe('VC revocation', () => {
    it('revokes a VC and detects it', async () => {
      const credId = 'urn:uuid:test-vc-1';
      expect(manager.isVCRevoked(credId)).toBe(false);

      const entry = await manager.revokeVC(
        keyProvider, admin.keyId, admin.did,
        credId, 'policy_violation', 'Used outside scope'
      );

      expect(entry.credentialId).toBe(credId);
      expect(entry.reason).toBe('policy_violation');
      expect(entry.details).toBe('Used outside scope');
      expect(manager.isVCRevoked(credId)).toBe(true);
    });

    it('returns revocation details', async () => {
      const credId = 'urn:uuid:test-vc-2';
      await manager.revokeVC(
        keyProvider, admin.keyId, admin.did,
        credId, 'key_compromise'
      );

      const rev = manager.getVCRevocation(credId);
      expect(rev).toBeDefined();
      expect(rev!.reason).toBe('key_compromise');
      expect(rev!.revokedAt).toBeDefined();
    });

    it('returns undefined for non-revoked VC', () => {
      expect(manager.getVCRevocation('urn:uuid:not-revoked')).toBeUndefined();
    });
  });

  // ─── Signed Revocation List ───────────────────────────────────────

  describe('signed revocation list', () => {
    it('publishes and verifies a signed revocation list', async () => {
      await manager.revokeVC(
        keyProvider, admin.keyId, admin.did,
        'urn:uuid:vc-1', 'manual'
      );
      await manager.revokeVC(
        keyProvider, admin.keyId, admin.did,
        'urn:uuid:vc-2', 'scope_violation'
      );

      const list = await manager.publishRevocationList(
        keyProvider, admin.keyId, admin.did
      );

      expect(list.version).toBe(1);
      expect(list.issuerDid).toBe(admin.did);
      expect(list.entries).toHaveLength(2);
      expect(list.signature).toBeDefined();

      const result = await manager.verifyRevocationList(list);
      expect(result.valid).toBe(true);
    });

    it('detects tampered revocation list', async () => {
      await manager.revokeVC(
        keyProvider, admin.keyId, admin.did,
        'urn:uuid:vc-tamper', 'manual'
      );

      const list = await manager.publishRevocationList(
        keyProvider, admin.keyId, admin.did
      );

      // Tamper: add a fake entry
      list.entries.push({
        credentialId: 'urn:uuid:injected',
        revokedAt: new Date().toISOString(),
        reason: 'manual',
      });

      const result = await manager.verifyRevocationList(list);
      expect(result.valid).toBe(false);
    });

    it('increments version on each publish', async () => {
      const list1 = await manager.publishRevocationList(
        keyProvider, admin.keyId, admin.did
      );
      const list2 = await manager.publishRevocationList(
        keyProvider, admin.keyId, admin.did
      );

      expect(list1.version).toBe(1);
      expect(list2.version).toBe(2);
    });

    it('imports revocation list entries', async () => {
      // Manager 1 publishes a list
      const manager1 = new RevocationManager();
      await manager1.revokeVC(
        keyProvider, admin.keyId, admin.did,
        'urn:uuid:import-vc-1', 'manual'
      );
      const list = await manager1.publishRevocationList(
        keyProvider, admin.keyId, admin.did
      );

      // Manager 2 imports it
      const manager2 = new RevocationManager();
      expect(manager2.isVCRevoked('urn:uuid:import-vc-1')).toBe(false);
      const imported = manager2.importRevocationList(list);
      expect(imported).toBe(1);
      expect(manager2.isVCRevoked('urn:uuid:import-vc-1')).toBe(true);

      // Importing again doesn't duplicate
      const imported2 = manager2.importRevocationList(list);
      expect(imported2).toBe(0);
    });
  });

  // ─── DID Revocation ───────────────────────────────────────────────

  describe('DID revocation', () => {
    it('revokes a DID and detects it', async () => {
      expect(manager.isDIDRevoked(agentA.did)).toBe(false);

      const revocation = await manager.revokeDID(
        keyProvider, admin.keyId, admin.did,
        agentA.did, 'agent_decommissioned', 'Agent replaced'
      );

      expect(revocation.did).toBe(agentA.did);
      expect(revocation.revokedBy).toBe(admin.did);
      expect(revocation.reason).toBe('agent_decommissioned');
      expect(manager.isDIDRevoked(agentA.did)).toBe(true);
    });

    it('verifies a DID revocation signature', async () => {
      const revocation = await manager.revokeDID(
        keyProvider, admin.keyId, admin.did,
        agentA.did, 'policy_violation'
      );

      const result = await manager.verifyDIDRevocation(revocation);
      expect(result.valid).toBe(true);
    });

    it('detects tampered DID revocation', async () => {
      const revocation = await manager.revokeDID(
        keyProvider, admin.keyId, admin.did,
        agentA.did, 'policy_violation'
      );

      // Tamper: change the reason
      revocation.reason = 'emergency';

      const result = await manager.verifyDIDRevocation(revocation);
      expect(result.valid).toBe(false);
    });
  });

  // ─── Key Rotation ─────────────────────────────────────────────────

  describe('key rotation', () => {
    it('rotates keys with dual-signature notice', async () => {
      const newKeyProvider = new InMemoryKeyProvider();
      const newAgent = await makeIdentity(newKeyProvider, 'agentA-v2');

      const notice = await manager.rotateKey(
        keyProvider, agentA.keyId, agentA.did,
        newKeyProvider, newAgent.keyId, newAgent.did
      );

      expect(notice.oldDid).toBe(agentA.did);
      expect(notice.newDid).toBe(newAgent.did);
      expect(notice.oldKeySignature).toBeDefined();
      expect(notice.newKeySignature).toBeDefined();
    });

    it('verifies a valid key rotation', async () => {
      const newKeyProvider = new InMemoryKeyProvider();
      const newAgent = await makeIdentity(newKeyProvider, 'agentA-v2');

      const notice = await manager.rotateKey(
        keyProvider, agentA.keyId, agentA.did,
        newKeyProvider, newAgent.keyId, newAgent.did
      );

      const result = await manager.verifyKeyRotation(notice);
      expect(result.valid).toBe(true);
    });

    it('marks old DID as revoked after rotation', async () => {
      const newKeyProvider = new InMemoryKeyProvider();
      const newAgent = await makeIdentity(newKeyProvider, 'agentA-v2');

      await manager.rotateKey(
        keyProvider, agentA.keyId, agentA.did,
        newKeyProvider, newAgent.keyId, newAgent.did
      );

      expect(manager.isDIDRevoked(agentA.did)).toBe(true);
      expect(manager.isDIDRevoked(newAgent.did)).toBe(false);
    });

    it('resolves current DID through rotation chain', async () => {
      const kp2 = new InMemoryKeyProvider();
      const agent2 = await makeIdentity(kp2, 'v2');
      const kp3 = new InMemoryKeyProvider();
      const agent3 = await makeIdentity(kp3, 'v3');

      // Rotate A → 2, then 2 → 3
      await manager.rotateKey(
        keyProvider, agentA.keyId, agentA.did,
        kp2, agent2.keyId, agent2.did
      );
      await manager.rotateKey(
        kp2, agent2.keyId, agent2.did,
        kp3, agent3.keyId, agent3.did
      );

      // Resolve from original DID should land on v3
      expect(manager.resolveCurrentDid(agentA.did)).toBe(agent3.did);
      expect(manager.resolveCurrentDid(agent2.did)).toBe(agent3.did);
      expect(manager.resolveCurrentDid(agent3.did)).toBe(agent3.did);
    });
  });

  // ─── Kill Switch ──────────────────────────────────────────────────

  describe('kill switch', () => {
    it('revokes target DID immediately', async () => {
      const event = await manager.killSwitch(
        keyProvider, admin.keyId, admin.did,
        agentA.did,
        'Agent producing harmful output'
      );

      expect(event.targetDid).toBe(agentA.did);
      expect(event.activatedBy).toBe(admin.did);
      expect(manager.isDIDRevoked(agentA.did)).toBe(true);
    });

    it('cascades to downstream agents', async () => {
      const event = await manager.killSwitch(
        keyProvider, admin.keyId, admin.did,
        agentA.did,
        'Compromised key — cascade to dependents',
        { cascade: true, downstreamDids: [agentB.did] }
      );

      expect(event.cascade).toBe(true);
      expect(event.cascadedDids).toContain(agentB.did);
      expect(manager.isDIDRevoked(agentA.did)).toBe(true);
      expect(manager.isDIDRevoked(agentB.did)).toBe(true);
    });

    it('verifies kill switch event signature', async () => {
      const event = await manager.killSwitch(
        keyProvider, admin.keyId, admin.did,
        agentA.did, 'Test kill'
      );

      const result = await manager.verifyKillSwitch(event);
      expect(result.valid).toBe(true);
    });

    it('detects tampered kill switch event', async () => {
      const event = await manager.killSwitch(
        keyProvider, admin.keyId, admin.did,
        agentA.did, 'Test kill'
      );

      // Tamper: change the target
      event.targetDid = agentB.did;

      const result = await manager.verifyKillSwitch(event);
      expect(result.valid).toBe(false);
    });

    it('records kill events in history', async () => {
      await manager.killSwitch(
        keyProvider, admin.keyId, admin.did,
        agentA.did, 'Kill 1'
      );
      await manager.killSwitch(
        keyProvider, admin.keyId, admin.did,
        agentB.did, 'Kill 2'
      );

      const events = manager.getKillEvents();
      expect(events).toHaveLength(2);
      expect(events[0].reason).toBe('Kill 1');
      expect(events[1].reason).toBe('Kill 2');
    });
  });

  // ─── Comprehensive Trust Check ────────────────────────────────────

  describe('isTrusted', () => {
    it('trusts unrevoked DID + VC', () => {
      const result = manager.isTrusted(agentA.did, 'urn:uuid:valid-vc');
      expect(result.trusted).toBe(true);
    });

    it('rejects revoked DID', async () => {
      await manager.revokeDID(
        keyProvider, admin.keyId, admin.did,
        agentA.did, 'emergency'
      );
      const result = manager.isTrusted(agentA.did);
      expect(result.trusted).toBe(false);
      expect(result.reason).toContain('DID revoked');
    });

    it('rejects revoked VC even if DID is fine', async () => {
      const credId = 'urn:uuid:revoked-vc';
      await manager.revokeVC(
        keyProvider, admin.keyId, admin.did,
        credId, 'scope_violation'
      );

      const result = manager.isTrusted(agentA.did, credId);
      expect(result.trusted).toBe(false);
      expect(result.reason).toContain('VC revoked');
    });
  });

  // ─── Stats ─────────────────────────────────────────────────────────

  describe('stats', () => {
    it('reports correct stats', async () => {
      expect(manager.getStats()).toEqual({
        revokedVCs: 0,
        revokedDIDs: 0,
        rotations: 0,
        killEvents: 0,
      });

      await manager.revokeVC(keyProvider, admin.keyId, admin.did, 'urn:uuid:s1', 'manual');
      await manager.revokeDID(keyProvider, admin.keyId, admin.did, agentA.did, 'emergency');
      await manager.killSwitch(keyProvider, admin.keyId, admin.did, agentB.did, 'Test');

      const stats = manager.getStats();
      expect(stats.revokedVCs).toBe(1);
      expect(stats.revokedDIDs).toBeGreaterThanOrEqual(2); // agentA + agentB (from kill)
      expect(stats.killEvents).toBe(1);
    });
  });
});

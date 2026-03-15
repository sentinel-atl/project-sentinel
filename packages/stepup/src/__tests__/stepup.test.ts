import { describe, it, expect, beforeEach } from 'vitest';
import { StepUpManager, type StepUpChallenge } from '../index.js';
import { InMemoryKeyProvider, publicKeyToDid } from '@sentinel/core';

async function makeIdentity(kp: InMemoryKeyProvider, name: string) {
  await kp.generate(name);
  const pubKey = await kp.getPublicKey(name);
  return { keyId: name, did: publicKeyToDid(pubKey) };
}

describe('@sentinel/stepup', () => {
  let manager: StepUpManager;
  let principalKP: InMemoryKeyProvider;
  let principal: { keyId: string; did: string };
  let agentKP: InMemoryKeyProvider;
  let agent: { keyId: string; did: string };

  beforeEach(async () => {
    principalKP = new InMemoryKeyProvider();
    principal = await makeIdentity(principalKP, 'human');
    agentKP = new InMemoryKeyProvider();
    agent = await makeIdentity(agentKP, 'agent');
    manager = new StepUpManager({
      alwaysRequireActions: ['delete_account', 'transfer_funds'],
      sensitivityLevels: ['high', 'critical'],
      challengeTimeoutMs: 5 * 60_000,
      maxPendingChallenges: 3,
    });
  });

  // ─── requiresStepUp ────────────────────────────────────────────

  describe('requiresStepUp', () => {
    it('requires step-up for explicit actions', () => {
      const result = manager.requiresStepUp('delete_account');
      expect(result.required).toBe(true);
      expect(result.trigger).toBe('policy_rule');
    });

    it('requires step-up for high sensitivity', () => {
      const result = manager.requiresStepUp('some_action', 'high');
      expect(result.required).toBe(true);
      expect(result.trigger).toBe('sensitivity_high');
    });

    it('requires step-up for critical sensitivity', () => {
      const result = manager.requiresStepUp('some_action', 'critical');
      expect(result.required).toBe(true);
      expect(result.trigger).toBe('sensitivity_critical');
    });

    it('does not require step-up for low sensitivity', () => {
      const result = manager.requiresStepUp('read_email', 'low');
      expect(result.required).toBe(false);
    });

    it('does not require step-up for unknown actions', () => {
      const result = manager.requiresStepUp('read_email');
      expect(result.required).toBe(false);
    });
  });

  // ─── Challenge creation ────────────────────────────────────────

  describe('challenges', () => {
    it('creates a challenge', () => {
      const challenge = manager.createChallenge(
        agent.did, principal.did,
        'delete_account', ['admin:delete'],
        'policy_rule', 'Delete user account #12345'
      );

      expect(challenge.challengeId).toMatch(/^stepup-/);
      expect(challenge.agentDid).toBe(agent.did);
      expect(challenge.principalDid).toBe(principal.did);
      expect(challenge.action).toBe('delete_account');
      expect(challenge.nonce).toBeDefined();
      expect(challenge.expiresAt).toBeDefined();
      expect(manager.getPendingCount()).toBe(1);
    });

    it('enforces max pending challenges', () => {
      for (let i = 0; i < 3; i++) {
        manager.createChallenge(
          agent.did, principal.did,
          `action_${i}`, [], 'policy_rule', `Action ${i}`
        );
      }

      expect(() => {
        manager.createChallenge(
          agent.did, principal.did,
          'action_4', [], 'policy_rule', 'Action 4'
        );
      }).toThrow('Max pending challenges');
    });

    it('cancels a challenge', () => {
      const challenge = manager.createChallenge(
        agent.did, principal.did,
        'test', [], 'policy_rule', 'Test'
      );
      expect(manager.getPendingCount()).toBe(1);
      manager.cancelChallenge(challenge.challengeId);
      expect(manager.getPendingCount()).toBe(0);
    });
  });

  // ─── Approval flow ─────────────────────────────────────────────

  describe('approval flow', () => {
    let challenge: StepUpChallenge;

    beforeEach(() => {
      challenge = manager.createChallenge(
        agent.did, principal.did,
        'transfer_funds', ['payment:transfer'],
        'sensitivity_high', 'Transfer $5,000 to vendor'
      );
    });

    it('approves with valid principal signature', async () => {
      const approval = await manager.signApproval(
        principalKP, principal.keyId, challenge, 'approved'
      );
      const result = await manager.verifyApproval(approval);
      expect(result.approved).toBe(true);
      expect(result.challengeId).toBe(challenge.challengeId);
    });

    it('handles denial', async () => {
      const approval = await manager.signApproval(
        principalKP, principal.keyId, challenge, 'denied'
      );
      const result = await manager.verifyApproval(approval);
      expect(result.approved).toBe(false);
      expect(result.error).toContain('Denied by principal');
    });

    it('rejects wrong signer', async () => {
      // Agent tries to approve instead of principal
      const fakeApproval = await manager.signApproval(
        agentKP, agent.keyId, challenge, 'approved'
      );
      // Override the principalDid to match challenge (spoofing attempt)
      // The signature won't match principal's key
      const result = await manager.verifyApproval(fakeApproval);
      expect(result.approved).toBe(false);
    });

    it('prevents replay (second use of same challenge)', async () => {
      const approval = await manager.signApproval(
        principalKP, principal.keyId, challenge, 'approved'
      );

      // First use succeeds
      const r1 = await manager.verifyApproval(approval);
      expect(r1.approved).toBe(true);

      // Replay fails (challenge consumed)
      const r2 = await manager.verifyApproval(approval);
      expect(r2.approved).toBe(false);
      expect(r2.error).toContain('not found or already consumed');
    });

    it('rejects expired challenge', async () => {
      // Create manager with 0ms timeout
      const fastManager = new StepUpManager({ challengeTimeoutMs: 0 });
      const expiredChallenge = fastManager.createChallenge(
        agent.did, principal.did,
        'test', [], 'policy_rule', 'Expired test'
      );

      // Wait a tick for expiry
      await new Promise(r => setTimeout(r, 5));

      const approval = await fastManager.signApproval(
        principalKP, principal.keyId, expiredChallenge, 'approved'
      );
      const result = await fastManager.verifyApproval(approval);
      expect(result.approved).toBe(false);
      expect(result.error).toContain('expired');
    });

    it('rejects principal DID mismatch', async () => {
      const approval = await manager.signApproval(
        principalKP, principal.keyId, challenge, 'approved'
      );
      // Tamper with the principal DID
      approval.principalDid = agent.did;

      const result = await manager.verifyApproval(approval);
      expect(result.approved).toBe(false);
      expect(result.error).toContain('mismatch');
    });
  });
});

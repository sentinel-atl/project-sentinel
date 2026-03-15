import { describe, it, expect, beforeEach } from 'vitest';
import {
  OfflineManager,
  type VouchCRDT,
  type DegradedAction,
} from '../index.js';

describe('@sentinel/offline', () => {
  let manager: OfflineManager;

  beforeEach(() => {
    manager = new OfflineManager({
      cache: {
        vcTtlMs: 1000,           // 1 second for fast test
        reputationTtlMs: 500,    // 500ms
        revocationRefreshMs: 500, // 500ms
        revocationMaxStalenessMs: 2000,
      },
    });
  });

  // ─── Online/Offline State ──────────────────────────────────────

  describe('online/offline state', () => {
    it('starts online by default', () => {
      expect(manager.isOnline).toBe(true);
    });

    it('can go offline and back online', () => {
      manager.goOffline();
      expect(manager.isOnline).toBe(false);
      manager.goOnline();
      expect(manager.isOnline).toBe(true);
    });
  });

  // ─── VC Cache ──────────────────────────────────────────────────

  describe('VC cache', () => {
    const mockVC = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      id: 'urn:uuid:test-vc-1',
      type: ['VerifiableCredential', 'AgentAuthorizationCredential'],
      issuer: 'did:key:z6MkIssuer',
      issuanceDate: new Date().toISOString(),
      expirationDate: new Date(Date.now() + 3600000).toISOString(),
      credentialSubject: { id: 'did:key:z6MkSubject', scope: ['read:email'] },
      proof: { type: 'Ed25519Signature2020', verificationMethod: '', proofPurpose: 'assertionMethod', created: '', proofValue: '' },
    } as any;

    it('caches and retrieves a VC', () => {
      manager.cacheVC(mockVC);
      const result = manager.getCachedVC('urn:uuid:test-vc-1');
      expect(result).toBeDefined();
      expect(result!.vc.id).toBe('urn:uuid:test-vc-1');
      expect(result!.fresh).toBe(true);
    });

    it('returns undefined for uncached VCs', () => {
      expect(manager.getCachedVC('urn:uuid:nonexistent')).toBeUndefined();
    });

    it('marks stale VCs as not fresh', async () => {
      manager = new OfflineManager({ cache: { vcTtlMs: 50 } as any });
      manager.cacheVC(mockVC);
      await new Promise(r => setTimeout(r, 80));
      const result = manager.getCachedVC('urn:uuid:test-vc-1');
      expect(result).toBeDefined();
      expect(result!.fresh).toBe(false);
    });
  });

  // ─── Reputation Cache ──────────────────────────────────────────

  describe('reputation cache', () => {
    const mockScore = {
      did: 'did:key:z6MkAgent',
      score: 75,
      totalVouches: 10,
      positiveVouches: 8,
      negativeVouches: 2,
      isQuarantined: false,
      lastUpdated: new Date().toISOString(),
      source: 'live' as const,
    };

    it('caches and retrieves reputation scores', () => {
      manager.cacheReputation(mockScore);
      const result = manager.getCachedReputation('did:key:z6MkAgent');
      expect(result).toBeDefined();
      expect(result!.score).toBe(75);
      expect(result!.source).toBe('cached');
    });

    it('returns undefined for uncached DIDs', () => {
      expect(manager.getCachedReputation('did:key:z6MkNobody')).toBeUndefined();
    });
  });

  // ─── Offline Policy ────────────────────────────────────────────

  describe('offline policy evaluation', () => {
    it('allows everything when online', () => {
      const decision = manager.evaluateReputationAccess('did:key:z6MkAgent');
      expect(decision.action).toBe('allow');
      expect(decision.scenario).toBe('online');
    });

    it('warns for missing reputation when offline (default policy)', () => {
      manager.goOffline();
      const decision = manager.evaluateReputationAccess('did:key:z6MkAgent');
      expect(decision.action).toBe('warn');
      expect(decision.scenario).toBe('reputation_unavailable');
    });

    it('allows cached reputation when offline', () => {
      manager.cacheReputation({
        did: 'did:key:z6MkAgent',
        score: 80, totalVouches: 5, positiveVouches: 5, negativeVouches: 0,
        isQuarantined: false, lastUpdated: new Date().toISOString(), source: 'live',
      });
      manager.goOffline();
      const decision = manager.evaluateReputationAccess('did:key:z6MkAgent');
      expect(decision.action).toBe('allow');
      expect(decision.scenario).toBe('reputation_cached_fresh');
    });

    it('warns on stale reputation cache', async () => {
      manager.cacheReputation({
        did: 'did:key:z6MkAgent',
        score: 80, totalVouches: 5, positiveVouches: 5, negativeVouches: 0,
        isQuarantined: false, lastUpdated: new Date().toISOString(), source: 'live',
      });
      await new Promise(r => setTimeout(r, 600)); // Wait past 500ms TTL
      manager.goOffline();
      const decision = manager.evaluateReputationAccess('did:key:z6MkAgent');
      expect(decision.action).toBe('warn');
      expect(decision.scenario).toBe('reputation_cached_stale');
    });

    it('applies custom deny policy', () => {
      const strict = new OfflineManager({
        policy: { reputationUnavailable: 'deny', revocationStale: 'deny', networkPartitioned: 'deny', fullOffline: 'deny' },
      });
      strict.goOffline();
      const decision = strict.evaluateReputationAccess('did:key:z6MkAgent');
      expect(decision.action).toBe('deny');
    });

    it('evaluates full offline scenario correctly', () => {
      manager.goOffline();
      const decision = manager.evaluateTrustDecision('did:key:z6MkCaller', 'did:key:z6MkIssuer');
      expect(decision.scenario).toBe('full_offline');
      expect(decision.action).toBe('deny'); // default fullOffline = deny
    });

    it('returns most restrictive policy when partially cached', () => {
      manager.cacheReputation({
        did: 'did:key:z6MkCaller',
        score: 80, totalVouches: 5, positiveVouches: 5, negativeVouches: 0,
        isQuarantined: false, lastUpdated: new Date().toISOString(), source: 'live',
      });
      manager.goOffline();
      // Reputation is cached (allow), but revocation is missing (warn)
      const decision = manager.evaluateTrustDecision('did:key:z6MkCaller', 'did:key:z6MkIssuer');
      expect(decision.action).toBe('warn');
    });
  });

  // ─── Revocation Cache ──────────────────────────────────────────

  describe('revocation cache', () => {
    const mockList = {
      version: 1,
      issuerDid: 'did:key:z6MkIssuer',
      publishedAt: new Date().toISOString(),
      entries: [],
      signature: 'mock-sig',
    } as any;

    it('caches and retrieves revocation lists', () => {
      manager.cacheRevocationList('did:key:z6MkIssuer', mockList);
      const result = manager.getCachedRevocationList('did:key:z6MkIssuer');
      expect(result).toBeDefined();
      expect(result!.list.version).toBe(1);
      expect(result!.fresh).toBe(true);
    });

    it('evaluates revocation access when offline with cache', () => {
      manager.cacheRevocationList('did:key:z6MkIssuer', mockList);
      manager.goOffline();
      const decision = manager.evaluateRevocationAccess('did:key:z6MkIssuer');
      expect(decision.action).toBe('allow');
      expect(decision.scenario).toBe('revocation_cached_acceptable');
    });

    it('warns on stale revocation cache beyond max staleness', async () => {
      manager = new OfflineManager({
        cache: {
          revocationRefreshMs: 50,
          revocationMaxStalenessMs: 100,
        } as any,
      });
      manager.cacheRevocationList('did:key:z6MkIssuer', mockList);
      await new Promise(r => setTimeout(r, 150));
      manager.goOffline();
      const decision = manager.evaluateRevocationAccess('did:key:z6MkIssuer');
      expect(decision.action).toBe('warn');
      expect(decision.scenario).toBe('revocation_stale');
    });
  });

  // ─── Pending Transactions ──────────────────────────────────────

  describe('pending transactions', () => {
    it('queues and retrieves pending transactions', () => {
      const tx = manager.queueTransaction({
        type: 'vouch',
        voucherDid: 'did:key:z6MkA',
        subjectDid: 'did:key:z6MkB',
        polarity: 'positive',
        weight: 0.8,
        timestamp: new Date().toISOString(),
      });
      expect(tx.id).toBeTruthy();
      expect(tx.synced).toBe(false);
      expect(manager.getPendingTransactions()).toHaveLength(1);
    });

    it('marks transactions as synced', () => {
      const tx = manager.queueTransaction({
        type: 'revocation',
        credentialId: 'urn:uuid:test',
        revokerDid: 'did:key:z6MkA',
        reason: 'policy_violation',
        timestamp: new Date().toISOString(),
      });
      expect(manager.markSynced(tx.id)).toBe(true);
      expect(manager.getPendingTransactions()).toHaveLength(0);
    });

    it('drains synced transactions', () => {
      const tx1 = manager.queueTransaction({
        type: 'vouch', voucherDid: 'a', subjectDid: 'b', polarity: 'positive', weight: 1, timestamp: '',
      });
      manager.queueTransaction({
        type: 'vouch', voucherDid: 'c', subjectDid: 'd', polarity: 'negative', weight: 0.5, timestamp: '',
      });
      manager.markSynced(tx1.id);
      const drained = manager.drainSynced();
      expect(drained).toBe(1);
      expect(manager.getPendingTransactions()).toHaveLength(1);
    });

    it('tracks retry counts', () => {
      const tx = manager.queueTransaction({
        type: 'vouch', voucherDid: 'a', subjectDid: 'b', polarity: 'positive', weight: 1, timestamp: '',
      });
      manager.markRetried(tx.id);
      manager.markRetried(tx.id);
      const pending = manager.getPendingTransactions();
      expect(pending[0].retries).toBe(2);
    });
  });

  // ─── CRDT Reputation Merge ────────────────────────────────────

  describe('CRDT reputation merge', () => {
    it('records local vouches', () => {
      const entry = manager.recordVouch('did:key:z6MkA', 'did:key:z6MkB', 'positive', 0.8);
      expect(entry.key).toBe('did:key:z6MkA:did:key:z6MkB');
      expect(entry.polarity).toBe('positive');
    });

    it('exports local state', () => {
      manager.recordVouch('did:key:z6MkA', 'did:key:z6MkB', 'positive', 0.8);
      manager.recordVouch('did:key:z6MkC', 'did:key:z6MkB', 'negative', 0.5);
      const state = manager.exportVouchState();
      expect(state).toHaveLength(2);
    });

    it('merges new remote entries', () => {
      const remote: VouchCRDT[] = [{
        key: 'did:key:z6MkX:did:key:z6MkY',
        voucherDid: 'did:key:z6MkX',
        subjectDid: 'did:key:z6MkY',
        polarity: 'positive',
        weight: 0.9,
        wallClock: Date.now(),
        nodeId: 'remote-node',
      }];
      const result = manager.mergeRemoteState(remote);
      expect(result.added).toBe(1);
      expect(result.merged).toBe(1);
      expect(result.conflicts).toBe(0);
    });

    it('resolves conflicts with LWW (newer wins)', () => {
      // Local entry
      manager.recordVouch('did:key:z6MkA', 'did:key:z6MkB', 'positive', 0.5);

      // Remote entry is newer
      const remote: VouchCRDT[] = [{
        key: 'did:key:z6MkA:did:key:z6MkB',
        voucherDid: 'did:key:z6MkA',
        subjectDid: 'did:key:z6MkB',
        polarity: 'negative',
        weight: 0.9,
        wallClock: Date.now() + 1000,
        nodeId: 'remote-node',
      }];
      const result = manager.mergeRemoteState(remote);
      expect(result.updated).toBe(1);
      expect(result.conflicts).toBe(1);

      // Verify new value took effect
      const vouches = manager.getVouchesFor('did:key:z6MkB');
      expect(vouches[0].polarity).toBe('negative');
    });

    it('resolves tiebreaks by nodeId (lexicographic)', () => {
      const manager2 = new OfflineManager({ nodeId: 'aaa-node' });
      manager2.recordVouch('did:key:z6MkA', 'did:key:z6MkB', 'positive', 0.5);
      const localState = manager2.exportVouchState();

      // Remote entry with same wallClock but higher nodeId
      const remote: VouchCRDT[] = [{
        ...localState[0],
        polarity: 'negative' as const,
        nodeId: 'zzz-node', // Higher than 'aaa-node'
      }];
      const result = manager2.mergeRemoteState(remote);
      expect(result.conflicts).toBe(1);
      const vouches = manager2.getVouchesFor('did:key:z6MkB');
      expect(vouches[0].nodeId).toBe('zzz-node');
    });

    it('keeps local when local is newer', () => {
      manager.recordVouch('did:key:z6MkA', 'did:key:z6MkB', 'positive', 0.8);

      const remote: VouchCRDT[] = [{
        key: 'did:key:z6MkA:did:key:z6MkB',
        voucherDid: 'did:key:z6MkA',
        subjectDid: 'did:key:z6MkB',
        polarity: 'negative',
        weight: 0.3,
        wallClock: 1, // Very old
        nodeId: 'remote-node',
      }];
      const result = manager.mergeRemoteState(remote);
      expect(result.updated).toBe(0);
      const vouches = manager.getVouchesFor('did:key:z6MkB');
      expect(vouches[0].polarity).toBe('positive');
    });
  });

  // ─── Stats & Policy ────────────────────────────────────────────

  describe('stats and policy', () => {
    it('reports accurate stats', () => {
      manager.recordVouch('did:key:z6MkA', 'did:key:z6MkB', 'positive', 0.8);
      manager.queueTransaction({
        type: 'vouch', voucherDid: 'a', subjectDid: 'b', polarity: 'positive', weight: 1, timestamp: '',
      });
      const stats = manager.getStats();
      expect(stats.crdtEntries).toBe(1);
      expect(stats.pendingTransactions).toBe(1);
      expect(stats.isOnline).toBe(true);
    });

    it('allows runtime policy updates', () => {
      expect(manager.getPolicy().fullOffline).toBe('deny');
      manager.setPolicy({ fullOffline: 'warn' });
      expect(manager.getPolicy().fullOffline).toBe('warn');
    });
  });
});

/**
 * @sentinel-atl/offline — Offline & Degraded Mode
 *
 * The trust layer MUST NOT become a single point of failure. When external
 * services (reputation registry, revocation lists, gossip network) are
 * unreachable, agents need to keep operating with degraded-but-safe trust.
 *
 * This module provides:
 *
 * 1. **Trust Cache** — LRU cache for VCs, reputation scores, and revocation
 *    lists with configurable TTLs and max staleness windows.
 *
 * 2. **Offline Policy Engine** — Configurable policies (allow | warn | deny)
 *    for each degraded scenario.
 *
 * 3. **CRDT-Style Reputation Merge** — When agents reconnect after a partition,
 *    local reputation changes are merged using last-writer-wins (LWW) semantics
 *    per vouch entry, with vector clocks for causal ordering.
 *
 * 4. **Pending Transaction Log** — Operations performed offline are queued and
 *    synced on reconnect.
 *
 * Blueprint ref: Section 7.2 (Offline & Degraded Mode), Section 7.3 (Caching Strategy)
 */

import type { VerifiableCredential } from '@sentinel-atl/core';
import type { ReputationScore } from '@sentinel-atl/reputation';
import type { SignedRevocationList } from '@sentinel-atl/revocation';

// ─── Cache Types ─────────────────────────────────────────────────────

export interface CacheEntry<T> {
  value: T;
  cachedAt: number; // ms since epoch
  ttlMs: number;
  source: 'live' | 'cached';
}

export interface CacheConfig {
  /** Max entries per cache type (default: 10_000) */
  maxEntries: number;
  /** VC cache TTL in ms — capped to credential expiry (default: 1 hour) */
  vcTtlMs: number;
  /** Reputation score cache TTL in ms (default: 5 minutes) */
  reputationTtlMs: number;
  /** Revocation list refresh interval in ms (default: 10 minutes) */
  revocationRefreshMs: number;
  /** Max staleness for revocation lists before rejecting (default: 1 hour) */
  revocationMaxStalenessMs: number;
  /** Max age for CRDT vouch entries before pruning (default: 365 days) */
  vouchMaxAgeMs: number;
  /** Max pending transactions before oldest are dropped (default: 10_000) */
  maxPendingTransactions: number;
}

// ─── Offline Policy ──────────────────────────────────────────────────

export type DegradedAction = 'allow' | 'warn' | 'deny';

export interface OfflinePolicy {
  /** What to do when reputation registry is unreachable */
  reputationUnavailable: DegradedAction;
  /** What to do when revocation list is stale beyond maxStaleness */
  revocationStale: DegradedAction;
  /** What to do when gossip network is partitioned */
  networkPartitioned: DegradedAction;
  /** What to do in full offline mode (no network at all) */
  fullOffline: DegradedAction;
}

export interface DegradedDecision {
  action: DegradedAction;
  scenario: string;
  reason: string;
  cachedData?: unknown;
  staleness?: number; // ms since last refresh
}

// ─── Pending Transaction ─────────────────────────────────────────────

export type PendingOperation =
  | { type: 'vouch'; voucherDid: string; subjectDid: string; polarity: 'positive' | 'negative'; weight: number; timestamp: string }
  | { type: 'revocation'; credentialId: string; revokerDid: string; reason: string; timestamp: string }
  | { type: 'reputation_update'; did: string; score: number; timestamp: string };

export interface PendingTransaction {
  id: string;
  operation: PendingOperation;
  createdAt: string;
  synced: boolean;
  syncedAt?: string;
  retries: number;
}

// ─── CRDT Merge Types ────────────────────────────────────────────────

export interface VouchCRDT {
  /** Unique key: `${voucherDid}:${subjectDid}` */
  key: string;
  /** The vouch data */
  voucherDid: string;
  subjectDid: string;
  polarity: 'positive' | 'negative';
  weight: number;
  /** Logical timestamp for LWW resolution */
  wallClock: number;
  /** Node ID that authored this entry */
  nodeId: string;
}

export interface MergeResult {
  /** Number of entries merged */
  merged: number;
  /** Number of conflicts resolved (LWW) */
  conflicts: number;
  /** Entries that were new (not present locally) */
  added: number;
  /** Entries updated with newer remote data */
  updated: number;
}

// ─── LRU Cache ───────────────────────────────────────────────────────

class LRUCache<T> {
  private cache = new Map<string, CacheEntry<T>>();
  private maxSize: number;

  constructor(maxSize: number) {
    this.maxSize = maxSize;
  }

  get(key: string): CacheEntry<T> | undefined {
    const entry = this.cache.get(key);
    if (!entry) return undefined;

    // Move to end (most recently used)
    this.cache.delete(key);
    this.cache.set(key, entry);
    return entry;
  }

  set(key: string, value: T, ttlMs: number): void {
    // Evict if full
    if (this.cache.size >= this.maxSize && !this.cache.has(key)) {
      const oldest = this.cache.keys().next().value;
      if (oldest !== undefined) this.cache.delete(oldest);
    }
    this.cache.set(key, {
      value,
      cachedAt: Date.now(),
      ttlMs,
      source: 'cached',
    });
  }

  isValid(key: string): boolean {
    const entry = this.cache.get(key);
    if (!entry) return false;
    return (Date.now() - entry.cachedAt) < entry.ttlMs;
  }

  staleness(key: string): number {
    const entry = this.cache.get(key);
    if (!entry) return Infinity;
    return Date.now() - entry.cachedAt;
  }

  delete(key: string): boolean {
    return this.cache.delete(key);
  }

  clear(): void {
    this.cache.clear();
  }

  get size(): number {
    return this.cache.size;
  }

  entries(): IterableIterator<[string, CacheEntry<T>]> {
    return this.cache.entries();
  }
}

// ─── Offline Manager ─────────────────────────────────────────────────

const DEFAULT_CACHE_CONFIG: CacheConfig = {
  maxEntries: 10_000,
  vcTtlMs: 60 * 60 * 1000,           // 1 hour
  reputationTtlMs: 5 * 60 * 1000,    // 5 minutes
  revocationRefreshMs: 10 * 60 * 1000, // 10 minutes
  revocationMaxStalenessMs: 60 * 60 * 1000, // 1 hour
  vouchMaxAgeMs: 365 * 24 * 60 * 60 * 1000, // 1 year
  maxPendingTransactions: 10_000,
};

const DEFAULT_POLICY: OfflinePolicy = {
  reputationUnavailable: 'warn',
  revocationStale: 'warn',
  networkPartitioned: 'warn',
  fullOffline: 'deny',
};

export class OfflineManager {
  private vcCache: LRUCache<VerifiableCredential>;
  private reputationCache: LRUCache<ReputationScore>;
  private revocationCache: LRUCache<SignedRevocationList>;
  private pendingTx: PendingTransaction[] = [];
  private vouchCRDT = new Map<string, VouchCRDT>();
  private config: CacheConfig;
  private policy: OfflinePolicy;
  private nodeId: string;
  private _isOnline: boolean = true;
  private txCounter = 0;

  constructor(
    options?: {
      cache?: Partial<CacheConfig>;
      policy?: Partial<OfflinePolicy>;
      nodeId?: string;
    }
  ) {
    this.config = { ...DEFAULT_CACHE_CONFIG, ...options?.cache };
    this.policy = { ...DEFAULT_POLICY, ...options?.policy };
    this.nodeId = options?.nodeId ?? `node-${Date.now().toString(36)}`;

    this.vcCache = new LRUCache(this.config.maxEntries);
    this.reputationCache = new LRUCache(this.config.maxEntries);
    this.revocationCache = new LRUCache(this.config.maxEntries);
  }

  // ─── Online/Offline State ────────────────────────────────────────

  get isOnline(): boolean {
    return this._isOnline;
  }

  goOffline(): void {
    this._isOnline = false;
  }

  goOnline(): void {
    this._isOnline = true;
  }

  // ─── VC Cache ────────────────────────────────────────────────────

  cacheVC(vc: VerifiableCredential): void {
    const expiry = vc.expirationDate
      ? new Date(vc.expirationDate).getTime() - Date.now()
      : this.config.vcTtlMs;
    const ttl = Math.min(expiry, this.config.vcTtlMs);
    this.vcCache.set(vc.id, vc, Math.max(ttl, 0));
  }

  getCachedVC(id: string): { vc: VerifiableCredential; fresh: boolean } | undefined {
    const entry = this.vcCache.get(id);
    if (!entry) return undefined;
    return {
      vc: entry.value,
      fresh: this.vcCache.isValid(id),
    };
  }

  // ─── Reputation Cache ────────────────────────────────────────────

  cacheReputation(score: ReputationScore): void {
    this.reputationCache.set(score.did, score, this.config.reputationTtlMs);
  }

  getCachedReputation(did: string): ReputationScore | undefined {
    const entry = this.reputationCache.get(did);
    if (!entry) return undefined;

    const fresh = this.reputationCache.isValid(did);
    return {
      ...entry.value,
      source: fresh ? 'cached' : 'cached',
      lastUpdated: entry.value.lastUpdated,
    };
  }

  /**
   * Check if reputation is available and apply the offline policy.
   */
  evaluateReputationAccess(did: string): DegradedDecision {
    if (this._isOnline) {
      return { action: 'allow', scenario: 'online', reason: 'Network available' };
    }

    const cached = this.reputationCache.get(did);
    if (!cached) {
      return {
        action: this.policy.reputationUnavailable,
        scenario: 'reputation_unavailable',
        reason: `No cached reputation for ${did}`,
      };
    }

    const staleness = this.reputationCache.staleness(did);
    return {
      action: this.reputationCache.isValid(did) ? 'allow' : this.policy.reputationUnavailable,
      scenario: this.reputationCache.isValid(did) ? 'reputation_cached_fresh' : 'reputation_cached_stale',
      reason: this.reputationCache.isValid(did)
        ? 'Using fresh cached reputation'
        : `Reputation cache stale by ${Math.round(staleness / 1000)}s`,
      cachedData: cached.value,
      staleness,
    };
  }

  // ─── Revocation Cache ────────────────────────────────────────────

  cacheRevocationList(issuerDid: string, list: SignedRevocationList): void {
    this.revocationCache.set(issuerDid, list, this.config.revocationRefreshMs);
  }

  getCachedRevocationList(issuerDid: string): { list: SignedRevocationList; fresh: boolean } | undefined {
    const entry = this.revocationCache.get(issuerDid);
    if (!entry) return undefined;
    return {
      list: entry.value,
      fresh: this.revocationCache.isValid(issuerDid),
    };
  }

  /**
   * Check if a revocation list is usable under current conditions.
   */
  evaluateRevocationAccess(issuerDid: string): DegradedDecision {
    if (this._isOnline) {
      return { action: 'allow', scenario: 'online', reason: 'Can fetch fresh revocation list' };
    }

    const cached = this.revocationCache.get(issuerDid);
    if (!cached) {
      return {
        action: this.policy.revocationStale,
        scenario: 'revocation_unavailable',
        reason: `No cached revocation list for ${issuerDid}`,
      };
    }

    const staleness = this.revocationCache.staleness(issuerDid);
    if (staleness > this.config.revocationMaxStalenessMs) {
      return {
        action: this.policy.revocationStale,
        scenario: 'revocation_stale',
        reason: `Revocation list stale by ${Math.round(staleness / 1000)}s (max: ${this.config.revocationMaxStalenessMs / 1000}s)`,
        cachedData: cached.value,
        staleness,
      };
    }

    return {
      action: 'allow',
      scenario: 'revocation_cached_acceptable',
      reason: `Using cached revocation list (age: ${Math.round(staleness / 1000)}s)`,
      cachedData: cached.value,
      staleness,
    };
  }

  // ─── Full Offline Evaluation ─────────────────────────────────────

  /**
   * Evaluate whether a trust decision can proceed given current conditions.
   * Returns the most restrictive policy action applicable.
   */
  evaluateTrustDecision(callerDid: string, issuerDid?: string): DegradedDecision {
    if (this._isOnline) {
      return { action: 'allow', scenario: 'online', reason: 'All services available' };
    }

    // Check each subsystem and return the most restrictive result
    const repDecision = this.evaluateReputationAccess(callerDid);
    const revDecision = issuerDid
      ? this.evaluateRevocationAccess(issuerDid)
      : { action: 'allow' as DegradedAction, scenario: 'no_revocation_check', reason: 'No issuer to check' };

    // Full offline = no reputation AND no revocation
    if (repDecision.scenario === 'reputation_unavailable' &&
        revDecision.scenario === 'revocation_unavailable') {
      return {
        action: this.policy.fullOffline,
        scenario: 'full_offline',
        reason: 'No cached data available — fully offline',
      };
    }

    // Return the most restrictive
    const priority: Record<DegradedAction, number> = { deny: 2, warn: 1, allow: 0 };
    if (priority[repDecision.action] >= priority[revDecision.action]) {
      return repDecision;
    }
    return revDecision;
  }

  // ─── Pending Transactions ────────────────────────────────────────

  /**
   * Queue an operation performed offline for later sync.
   */
  queueTransaction(operation: PendingOperation): PendingTransaction {
    const tx: PendingTransaction = {
      id: `tx-${++this.txCounter}-${Date.now().toString(36)}`,
      operation,
      createdAt: new Date().toISOString(),
      synced: false,
      retries: 0,
    };
    this.pendingTx.push(tx);
    return tx;
  }

  /**
   * Get all pending (unsynced) transactions.
   */
  getPendingTransactions(): PendingTransaction[] {
    return this.pendingTx.filter(tx => !tx.synced);
  }

  /**
   * Mark a transaction as synced.
   */
  markSynced(txId: string): boolean {
    const tx = this.pendingTx.find(t => t.id === txId);
    if (!tx) return false;
    tx.synced = true;
    tx.syncedAt = new Date().toISOString();
    return true;
  }

  /**
   * Mark a transaction as failed (increment retry count).
   */
  markRetried(txId: string): boolean {
    const tx = this.pendingTx.find(t => t.id === txId);
    if (!tx) return false;
    tx.retries++;
    return true;
  }

  /**
   * Drain synced transactions (cleanup).
   */
  drainSynced(): number {
    const before = this.pendingTx.length;
    this.pendingTx = this.pendingTx.filter(tx => !tx.synced);
    return before - this.pendingTx.length;
  }

  // ─── CRDT Reputation Merge ──────────────────────────────────────

  /**
   * Record a vouch locally with CRDT metadata.
   */
  recordVouch(voucherDid: string, subjectDid: string, polarity: 'positive' | 'negative', weight: number): VouchCRDT {
    const key = `${voucherDid}:${subjectDid}`;
    const entry: VouchCRDT = {
      key,
      voucherDid,
      subjectDid,
      polarity,
      weight,
      wallClock: Date.now(),
      nodeId: this.nodeId,
    };
    this.vouchCRDT.set(key, entry);
    return entry;
  }

  /**
   * Merge remote CRDT state into local state.
   * Uses Last-Writer-Wins (LWW) with wall-clock timestamps.
   * Ties are broken by nodeId comparison (lexicographic).
   */
  mergeRemoteState(remote: VouchCRDT[]): MergeResult {
    let merged = 0;
    let conflicts = 0;
    let added = 0;
    let updated = 0;

    for (const remoteEntry of remote) {
      const local = this.vouchCRDT.get(remoteEntry.key);
      merged++;

      if (!local) {
        // New entry from remote
        this.vouchCRDT.set(remoteEntry.key, remoteEntry);
        added++;
      } else if (remoteEntry.wallClock > local.wallClock) {
        // Remote is newer — use it
        this.vouchCRDT.set(remoteEntry.key, remoteEntry);
        updated++;
        conflicts++;
      } else if (remoteEntry.wallClock === local.wallClock && remoteEntry.nodeId > local.nodeId) {
        // Tiebreak: higher nodeId wins
        this.vouchCRDT.set(remoteEntry.key, remoteEntry);
        updated++;
        conflicts++;
      }
      // else: local is newer or wins tiebreak — keep local
    }

    return { merged, conflicts, added, updated };
  }

  /**
   * Export local CRDT state for syncing to a peer.
   */
  exportVouchState(): VouchCRDT[] {
    return Array.from(this.vouchCRDT.values());
  }

  /**
   * Get CRDT vouch entries for a specific subject.
   */
  getVouchesFor(subjectDid: string): VouchCRDT[] {
    return Array.from(this.vouchCRDT.values())
      .filter(v => v.subjectDid === subjectDid);
  }

  // ─── Stats ───────────────────────────────────────────────────────

  /**
   * Prune expired CRDT vouch entries older than vouchMaxAgeMs.
   * Returns number of entries pruned.
   */
  pruneVouchHistory(): number {
    const now = Date.now();
    let pruned = 0;
    for (const [key, entry] of this.vouchCRDT) {
      if ((now - entry.wallClock) > this.config.vouchMaxAgeMs) {
        this.vouchCRDT.delete(key);
        pruned++;
      }
    }
    return pruned;
  }

  /**
   * Evict stale entries from all caches (entries past their TTL).
   * Returns total entries evicted.
   */
  pruneStaleCaches(): number {
    let evicted = 0;
    for (const [key] of this.vcCache.entries()) {
      if (!this.vcCache.isValid(key)) { this.vcCache.delete(key); evicted++; }
    }
    for (const [key] of this.reputationCache.entries()) {
      if (!this.reputationCache.isValid(key)) { this.reputationCache.delete(key); evicted++; }
    }
    for (const [key] of this.revocationCache.entries()) {
      if (!this.revocationCache.isValid(key)) { this.revocationCache.delete(key); evicted++; }
    }
    return evicted;
  }

  /**
   * Cap pending transactions to maxPendingTransactions, dropping oldest unsynced first.
   */
  capPendingTransactions(): number {
    if (this.pendingTx.length <= this.config.maxPendingTransactions) return 0;
    const excess = this.pendingTx.length - this.config.maxPendingTransactions;
    this.pendingTx.splice(0, excess);
    return excess;
  }

  getStats(): {
    vcCacheSize: number;
    reputationCacheSize: number;
    revocationCacheSize: number;
    pendingTransactions: number;
    crdtEntries: number;
    isOnline: boolean;
  } {
    return {
      vcCacheSize: this.vcCache.size,
      reputationCacheSize: this.reputationCache.size,
      revocationCacheSize: this.revocationCache.size,
      pendingTransactions: this.getPendingTransactions().length,
      crdtEntries: this.vouchCRDT.size,
      isOnline: this._isOnline,
    };
  }

  /** Get the current policy */
  getPolicy(): OfflinePolicy {
    return { ...this.policy };
  }

  /** Update policy at runtime */
  setPolicy(policy: Partial<OfflinePolicy>): void {
    this.policy = { ...this.policy, ...policy };
  }

  /** Get cache config */
  getCacheConfig(): CacheConfig {
    return { ...this.config };
  }
}

/**
 * Persistent nonce store — survives server restarts.
 *
 * Wraps the SentinelStore interface to provide a Set-like API for nonce tracking.
 * Nonces auto-expire based on intent expiry to prevent unbounded growth.
 */

import type { SentinelStore } from '@sentinel-atl/store';

// ─── Types ───────────────────────────────────────────────────────────

export interface NonceStoreConfig {
  /** Underlying persistent store */
  store: SentinelStore;
  /** Key prefix (default: 'nonce:') */
  prefix?: string;
  /** Default TTL in seconds (default: 300 = 5 minutes) */
  defaultTtl?: number;
}

// ─── Persistent Nonce Set ────────────────────────────────────────────

/**
 * A Set<string>-compatible nonce tracker backed by persistent storage.
 *
 * Drop-in replacement for the in-memory Set<string> used in validateIntent().
 * Nonces are stored with a TTL so they auto-expire and don't grow forever.
 */
export class NonceStore {
  private store: SentinelStore;
  private prefix: string;
  private defaultTtl: number;

  constructor(config: NonceStoreConfig) {
    this.store = config.store;
    this.prefix = config.prefix ?? 'nonce:';
    this.defaultTtl = config.defaultTtl ?? 300;
  }

  /** Check if a nonce has been seen. */
  async has(nonce: string): Promise<boolean> {
    return this.store.has(this.prefix + nonce);
  }

  /** Mark a nonce as seen with optional TTL in seconds. */
  async add(nonce: string, ttlSeconds?: number): Promise<void> {
    await this.store.set(this.prefix + nonce, '1', ttlSeconds ?? this.defaultTtl);
  }

  /**
   * Create a Set<string>-compatible adapter for use with validateIntent().
   *
   * Returns an object that looks like Set<string> with .has() and .add()
   * but uses async persistent storage under the hood.
   *
   * The adapter maintains a local cache and auto-flushes writes to the
   * persistent store in the background. For strict distributed replay
   * protection, use the async methods directly.
   */
  toSyncAdapter(): Set<string> & { flush(): Promise<void> } {
    const self = this;
    const pendingAdds: Array<{ nonce: string; ttl?: number }> = [];
    const localCache = new Set<string>();
    let flushInProgress = false;

    const doFlush = async () => {
      if (flushInProgress || pendingAdds.length === 0) return;
      flushInProgress = true;
      try {
        const batch = pendingAdds.splice(0, pendingAdds.length);
        for (const { nonce } of batch) {
          await self.add(nonce);
        }
      } finally {
        flushInProgress = false;
        // Flush again if new items arrived during flush
        if (pendingAdds.length > 0) doFlush();
      }
    };

    type AdapterType = Set<string> & { flush(): Promise<void> };

    const adapter: AdapterType = {
      has(nonce: string): boolean {
        return localCache.has(nonce);
      },
      add(nonce: string): AdapterType {
        localCache.add(nonce);
        pendingAdds.push({ nonce });
        // Auto-flush in the background
        doFlush();
        return adapter;
      },
      get size() {
        return localCache.size;
      },
      async flush(): Promise<void> {
        for (const { nonce } of pendingAdds) {
          await self.add(nonce);
        }
        pendingAdds.length = 0;
      },
      // Satisfy Set interface minimally
      delete: (nonce: string) => localCache.delete(nonce),
      clear: () => localCache.clear(),
      forEach: (cb: (v: string, v2: string, s: Set<string>) => void) => localCache.forEach(cb),
      entries: () => localCache.entries(),
      keys: () => localCache.keys(),
      values: () => localCache.values(),
      [Symbol.iterator]: () => localCache[Symbol.iterator](),
      [Symbol.toStringTag]: 'NonceStore',
    };

    return adapter as Set<string> & { flush(): Promise<void> };
  }

  /**
   * Pre-load nonces from the store into a local Set for synchronous checking.
   * Useful at startup to restore state from a previous session.
   */
  async preload(): Promise<Set<string>> {
    const keys = await this.store.keys(this.prefix);
    const set = new Set<string>();
    for (const key of keys) {
      set.add(key.slice(this.prefix.length));
    }
    return set;
  }
}

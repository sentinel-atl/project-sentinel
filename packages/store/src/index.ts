/**
 * @sentinel-atl/store — Persistent Storage Adapters
 *
 * Every Sentinel component (reputation, revocation, audit, offline) keeps state
 * in-memory by default. This package provides a storage interface + real backends
 * so state SURVIVES process restarts.
 *
 * Supported backends:
 * - **MemoryStore** — In-process Map (default, zero deps, same as before)
 * - **RedisStore**  — Redis/Valkey via ioredis (requires `ioredis` peer dep)
 * - **PostgresStore** — PostgreSQL via pg (requires `pg` peer dep)
 * - **SQLiteStore** — Local SQLite via better-sqlite3 (requires `better-sqlite3`)
 *
 * Usage:
 *   import { RedisStore } from '@sentinel-atl/store';
 *   const store = new RedisStore({ url: 'redis://localhost:6379', prefix: 'sentinel:' });
 *   await store.set('reputation:did:key:z6Mk...', JSON.stringify(score));
 *   const score = await store.get('reputation:did:key:z6Mk...');
 */

// ─── Store Interface ─────────────────────────────────────────────────

export interface SentinelStore {
  /** Get a value by key. Returns undefined if not found. */
  get(key: string): Promise<string | undefined>;

  /** Set a key-value pair with optional TTL in seconds. */
  set(key: string, value: string, ttlSeconds?: number): Promise<void>;

  /** Delete a key. Returns true if the key existed. */
  delete(key: string): Promise<boolean>;

  /** Check if a key exists. */
  has(key: string): Promise<boolean>;

  /** List keys matching a prefix. */
  keys(prefix: string): Promise<string[]>;

  /** Get multiple keys at once. */
  getMany(keys: string[]): Promise<Map<string, string>>;

  /** Set multiple key-value pairs at once. */
  setMany(entries: Array<{ key: string; value: string; ttlSeconds?: number }>): Promise<void>;

  /** Atomic increment (for counters). Returns new value. */
  increment(key: string, by?: number): Promise<number>;

  /** Append to a list (for audit logs). */
  listAppend(key: string, value: string): Promise<number>;

  /** Read a list (with optional start/end range). */
  listRange(key: string, start?: number, end?: number): Promise<string[]>;

  /** List length */
  listLength(key: string): Promise<number>;

  /** Close the store connection. */
  close(): Promise<void>;
}

// ─── Memory Store ────────────────────────────────────────────────────

interface MemoryEntry {
  value: string;
  expiresAt?: number;
}

export class MemoryStore implements SentinelStore {
  private data = new Map<string, MemoryEntry>();
  private lists = new Map<string, string[]>();

  private isExpired(entry: MemoryEntry): boolean {
    return entry.expiresAt !== undefined && Date.now() > entry.expiresAt;
  }

  async get(key: string): Promise<string | undefined> {
    const entry = this.data.get(key);
    if (!entry || this.isExpired(entry)) {
      if (entry) this.data.delete(key);
      return undefined;
    }
    return entry.value;
  }

  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    this.data.set(key, {
      value,
      expiresAt: ttlSeconds ? Date.now() + ttlSeconds * 1000 : undefined,
    });
  }

  async delete(key: string): Promise<boolean> {
    const existed = this.data.has(key) || this.lists.has(key);
    this.data.delete(key);
    this.lists.delete(key);
    return existed;
  }

  async has(key: string): Promise<boolean> {
    const entry = this.data.get(key);
    if (!entry) return false;
    if (this.isExpired(entry)) {
      this.data.delete(key);
      return false;
    }
    return true;
  }

  async keys(prefix: string): Promise<string[]> {
    const result: string[] = [];
    for (const key of this.data.keys()) {
      if (key.startsWith(prefix)) {
        const entry = this.data.get(key)!;
        if (!this.isExpired(entry)) result.push(key);
      }
    }
    for (const key of this.lists.keys()) {
      if (key.startsWith(prefix)) result.push(key);
    }
    return result;
  }

  async getMany(keys: string[]): Promise<Map<string, string>> {
    const result = new Map<string, string>();
    for (const key of keys) {
      const val = await this.get(key);
      if (val !== undefined) result.set(key, val);
    }
    return result;
  }

  async setMany(entries: Array<{ key: string; value: string; ttlSeconds?: number }>): Promise<void> {
    for (const e of entries) {
      await this.set(e.key, e.value, e.ttlSeconds);
    }
  }

  async increment(key: string, by = 1): Promise<number> {
    const current = await this.get(key);
    const newVal = (current ? parseInt(current, 10) : 0) + by;
    await this.set(key, String(newVal));
    return newVal;
  }

  async listAppend(key: string, value: string): Promise<number> {
    const list = this.lists.get(key) ?? [];
    list.push(value);
    this.lists.set(key, list);
    return list.length;
  }

  async listRange(key: string, start = 0, end = -1): Promise<string[]> {
    const list = this.lists.get(key) ?? [];
    const s = start < 0 ? Math.max(0, list.length + start) : start;
    const e = end < 0 ? list.length + end + 1 : end + 1;
    return list.slice(s, e);
  }

  async listLength(key: string): Promise<number> {
    return (this.lists.get(key) ?? []).length;
  }

  async close(): Promise<void> {
    this.data.clear();
    this.lists.clear();
  }
}

// ─── Redis Store ─────────────────────────────────────────────────────

export interface RedisStoreConfig {
  /** Redis connection URL (e.g. redis://localhost:6379) */
  url?: string;
  /** Redis host (default: localhost) */
  host?: string;
  /** Redis port (default: 6379) */
  port?: number;
  /** Redis password */
  password?: string;
  /** Key prefix (default: 'sentinel:') */
  prefix?: string;
  /** Database number (default: 0) */
  db?: number;
  /** Pre-configured ioredis instance */
  client?: unknown;
}

export class RedisStore implements SentinelStore {
  private client: any;
  private prefix: string;
  private ownsClient: boolean;

  constructor(config: RedisStoreConfig = {}) {
    this.prefix = config.prefix ?? 'sentinel:';
    if (config.client) {
      this.client = config.client;
      this.ownsClient = false;
    } else {
      // Dynamic import of ioredis
      try {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const Redis = require('ioredis');
        this.client = new Redis({
          host: config.host ?? 'localhost',
          port: config.port ?? 6379,
          password: config.password,
          db: config.db ?? 0,
          ...(config.url ? { url: config.url } : {}),
        });
        this.ownsClient = true;
      } catch {
        throw new Error(
          'ioredis is required for RedisStore. Install it: npm install ioredis'
        );
      }
    }
  }

  private k(key: string): string {
    return `${this.prefix}${key}`;
  }

  async get(key: string): Promise<string | undefined> {
    const val = await this.client.get(this.k(key));
    return val ?? undefined;
  }

  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    if (ttlSeconds) {
      await this.client.set(this.k(key), value, 'EX', ttlSeconds);
    } else {
      await this.client.set(this.k(key), value);
    }
  }

  async delete(key: string): Promise<boolean> {
    const count = await this.client.del(this.k(key));
    return count > 0;
  }

  async has(key: string): Promise<boolean> {
    return (await this.client.exists(this.k(key))) > 0;
  }

  async keys(prefix: string): Promise<string[]> {
    const pattern = `${this.prefix}${prefix}*`;
    const keys: string[] = [];
    let cursor = '0';
    do {
      const [next, batch] = await this.client.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
      cursor = next;
      for (const k of batch) {
        keys.push(k.slice(this.prefix.length));
      }
    } while (cursor !== '0');
    return keys;
  }

  async getMany(keys: string[]): Promise<Map<string, string>> {
    if (keys.length === 0) return new Map();
    const prefixed = keys.map(k => this.k(k));
    const values = await this.client.mget(...prefixed);
    const result = new Map<string, string>();
    for (let i = 0; i < keys.length; i++) {
      if (values[i] !== null) result.set(keys[i], values[i]);
    }
    return result;
  }

  async setMany(entries: Array<{ key: string; value: string; ttlSeconds?: number }>): Promise<void> {
    const pipeline = this.client.pipeline();
    for (const e of entries) {
      if (e.ttlSeconds) {
        pipeline.set(this.k(e.key), e.value, 'EX', e.ttlSeconds);
      } else {
        pipeline.set(this.k(e.key), e.value);
      }
    }
    await pipeline.exec();
  }

  async increment(key: string, by = 1): Promise<number> {
    return this.client.incrby(this.k(key), by);
  }

  async listAppend(key: string, value: string): Promise<number> {
    return this.client.rpush(this.k(key), value);
  }

  async listRange(key: string, start = 0, end = -1): Promise<string[]> {
    return this.client.lrange(this.k(key), start, end);
  }

  async listLength(key: string): Promise<number> {
    return this.client.llen(this.k(key));
  }

  async close(): Promise<void> {
    if (this.ownsClient) {
      await this.client.quit();
    }
  }
}

// ─── PostgreSQL Store ────────────────────────────────────────────────

export interface PostgresStoreConfig {
  /** PostgreSQL connection string */
  connectionString?: string;
  /** Connection pool (pre-configured pg.Pool) */
  pool?: unknown;
  /** Table name (default: 'sentinel_kv') */
  tableName?: string;
  /** Schema name (default: 'public') */
  schema?: string;
}

export class PostgresStore implements SentinelStore {
  private pool: any;
  private tableName: string;
  private schema: string;
  private ownsPool: boolean;
  private initialized = false;

  constructor(config: PostgresStoreConfig = {}) {
    this.tableName = config.tableName ?? 'sentinel_kv';
    this.schema = config.schema ?? 'public';
    if (config.pool) {
      this.pool = config.pool;
      this.ownsPool = false;
    } else {
      try {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const { Pool } = require('pg');
        this.pool = new Pool({
          connectionString: config.connectionString ?? 'postgresql://localhost:5432/sentinel',
        });
        this.ownsPool = true;
      } catch {
        throw new Error('pg is required for PostgresStore. Install it: npm install pg');
      }
    }
  }

  private get table() {
    return `"${this.schema}"."${this.tableName}"`;
  }

  private async ensureTable(): Promise<void> {
    if (this.initialized) return;
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS ${this.table} (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        expires_at TIMESTAMPTZ,
        is_list BOOLEAN DEFAULT FALSE
      )
    `);
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS ${this.table}_lists (
        key TEXT NOT NULL,
        idx SERIAL,
        value TEXT NOT NULL,
        PRIMARY KEY (key, idx)
      )
    `);
    this.initialized = true;
  }

  async get(key: string): Promise<string | undefined> {
    await this.ensureTable();
    const { rows } = await this.pool.query(
      `SELECT value FROM ${this.table} WHERE key = $1 AND (expires_at IS NULL OR expires_at > NOW())`,
      [key]
    );
    return rows[0]?.value ?? undefined;
  }

  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    await this.ensureTable();
    const expires = ttlSeconds
      ? new Date(Date.now() + ttlSeconds * 1000).toISOString()
      : null;
    await this.pool.query(
      `INSERT INTO ${this.table} (key, value, expires_at) VALUES ($1, $2, $3)
       ON CONFLICT (key) DO UPDATE SET value = $2, expires_at = $3`,
      [key, value, expires]
    );
  }

  async delete(key: string): Promise<boolean> {
    await this.ensureTable();
    const kv = await this.pool.query(`DELETE FROM ${this.table} WHERE key = $1`, [key]);
    const list = await this.pool.query(
      `DELETE FROM ${this.table}_lists WHERE key = $1`, [key]
    );
    return kv.rowCount > 0 || list.rowCount > 0;
  }

  async has(key: string): Promise<boolean> {
    await this.ensureTable();
    const { rows } = await this.pool.query(
      `SELECT 1 FROM ${this.table} WHERE key = $1 AND (expires_at IS NULL OR expires_at > NOW()) LIMIT 1`,
      [key]
    );
    return rows.length > 0;
  }

  async keys(prefix: string): Promise<string[]> {
    await this.ensureTable();
    const { rows } = await this.pool.query(
      `SELECT key FROM ${this.table} WHERE key LIKE $1 AND (expires_at IS NULL OR expires_at > NOW())`,
      [`${prefix}%`]
    );
    const { rows: listRows } = await this.pool.query(
      `SELECT DISTINCT key FROM ${this.table}_lists WHERE key LIKE $1`,
      [`${prefix}%`]
    );
    const allKeys = new Set([...rows.map((r: any) => r.key), ...listRows.map((r: any) => r.key)]);
    return Array.from(allKeys);
  }

  async getMany(keys: string[]): Promise<Map<string, string>> {
    if (keys.length === 0) return new Map();
    await this.ensureTable();
    const placeholders = keys.map((_, i) => `$${i + 1}`).join(',');
    const { rows } = await this.pool.query(
      `SELECT key, value FROM ${this.table} WHERE key IN (${placeholders}) AND (expires_at IS NULL OR expires_at > NOW())`,
      keys
    );
    const result = new Map<string, string>();
    for (const row of rows) result.set(row.key, row.value);
    return result;
  }

  async setMany(entries: Array<{ key: string; value: string; ttlSeconds?: number }>): Promise<void> {
    for (const e of entries) {
      await this.set(e.key, e.value, e.ttlSeconds);
    }
  }

  async increment(key: string, by = 1): Promise<number> {
    await this.ensureTable();
    const { rows } = await this.pool.query(
      `INSERT INTO ${this.table} (key, value) VALUES ($1, $2)
       ON CONFLICT (key) DO UPDATE SET value = (COALESCE(${this.table}.value, '0')::INTEGER + $2)::TEXT
       RETURNING value`,
      [key, String(by)]
    );
    return parseInt(rows[0].value, 10);
  }

  async listAppend(key: string, value: string): Promise<number> {
    await this.ensureTable();
    await this.pool.query(
      `INSERT INTO ${this.table}_lists (key, value) VALUES ($1, $2)`,
      [key, value]
    );
    const { rows } = await this.pool.query(
      `SELECT COUNT(*) as cnt FROM ${this.table}_lists WHERE key = $1`,
      [key]
    );
    return parseInt(rows[0].cnt, 10);
  }

  async listRange(key: string, start = 0, end = -1): Promise<string[]> {
    await this.ensureTable();
    let query: string;
    const params: any[] = [key];

    if (end === -1) {
      query = `SELECT value FROM ${this.table}_lists WHERE key = $1 ORDER BY idx OFFSET $2`;
      params.push(start);
    } else {
      query = `SELECT value FROM ${this.table}_lists WHERE key = $1 ORDER BY idx OFFSET $2 LIMIT $3`;
      params.push(start, end - start + 1);
    }

    const { rows } = await this.pool.query(query, params);
    return rows.map((r: any) => r.value);
  }

  async listLength(key: string): Promise<number> {
    await this.ensureTable();
    const { rows } = await this.pool.query(
      `SELECT COUNT(*) as cnt FROM ${this.table}_lists WHERE key = $1`,
      [key]
    );
    return parseInt(rows[0].cnt, 10);
  }

  async close(): Promise<void> {
    if (this.ownsPool) {
      await this.pool.end();
    }
  }
}

// ─── SQLite Store ────────────────────────────────────────────────────

export interface SQLiteStoreConfig {
  /** Path to the SQLite database file (default: ':memory:') */
  path?: string;
  /** Pre-configured better-sqlite3 instance */
  db?: unknown;
}

export class SQLiteStore implements SentinelStore {
  private db: any;
  private ownsDb: boolean;

  constructor(config: SQLiteStoreConfig = {}) {
    if (config.db) {
      this.db = config.db;
      this.ownsDb = false;
    } else {
      try {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const Database = require('better-sqlite3');
        this.db = new Database(config.path ?? ':memory:');
        this.ownsDb = true;
      } catch {
        throw new Error(
          'better-sqlite3 is required for SQLiteStore. Install it: npm install better-sqlite3'
        );
      }
    }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sentinel_kv (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        expires_at INTEGER
      )
    `);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sentinel_lists (
        key TEXT NOT NULL,
        idx INTEGER NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY (key, idx)
      )
    `);
  }

  async get(key: string): Promise<string | undefined> {
    const row = this.db.prepare(
      'SELECT value FROM sentinel_kv WHERE key = ? AND (expires_at IS NULL OR expires_at > ?)'
    ).get(key, Date.now());
    return row?.value ?? undefined;
  }

  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    const expiresAt = ttlSeconds ? Date.now() + ttlSeconds * 1000 : null;
    this.db.prepare(
      'INSERT OR REPLACE INTO sentinel_kv (key, value, expires_at) VALUES (?, ?, ?)'
    ).run(key, value, expiresAt);
  }

  async delete(key: string): Promise<boolean> {
    const r1 = this.db.prepare('DELETE FROM sentinel_kv WHERE key = ?').run(key);
    const r2 = this.db.prepare('DELETE FROM sentinel_lists WHERE key = ?').run(key);
    return r1.changes > 0 || r2.changes > 0;
  }

  async has(key: string): Promise<boolean> {
    const row = this.db.prepare(
      'SELECT 1 FROM sentinel_kv WHERE key = ? AND (expires_at IS NULL OR expires_at > ?) LIMIT 1'
    ).get(key, Date.now());
    return row !== undefined;
  }

  async keys(prefix: string): Promise<string[]> {
    const kvRows = this.db.prepare(
      'SELECT key FROM sentinel_kv WHERE key LIKE ? AND (expires_at IS NULL OR expires_at > ?)'
    ).all(`${prefix}%`, Date.now());
    const listRows = this.db.prepare(
      'SELECT DISTINCT key FROM sentinel_lists WHERE key LIKE ?'
    ).all(`${prefix}%`);
    const allKeys = new Set([
      ...kvRows.map((r: any) => r.key),
      ...listRows.map((r: any) => r.key),
    ]);
    return Array.from(allKeys);
  }

  async getMany(keys: string[]): Promise<Map<string, string>> {
    const result = new Map<string, string>();
    const stmt = this.db.prepare(
      'SELECT value FROM sentinel_kv WHERE key = ? AND (expires_at IS NULL OR expires_at > ?)'
    );
    for (const key of keys) {
      const row = stmt.get(key, Date.now());
      if (row) result.set(key, row.value);
    }
    return result;
  }

  async setMany(entries: Array<{ key: string; value: string; ttlSeconds?: number }>): Promise<void> {
    const tx = this.db.transaction(() => {
      for (const e of entries) {
        const expiresAt = e.ttlSeconds ? Date.now() + e.ttlSeconds * 1000 : null;
        this.db.prepare(
          'INSERT OR REPLACE INTO sentinel_kv (key, value, expires_at) VALUES (?, ?, ?)'
        ).run(e.key, e.value, expiresAt);
      }
    });
    tx();
  }

  async increment(key: string, by = 1): Promise<number> {
    const current = await this.get(key);
    const newVal = (current ? parseInt(current, 10) : 0) + by;
    await this.set(key, String(newVal));
    return newVal;
  }

  async listAppend(key: string, value: string): Promise<number> {
    const maxRow = this.db.prepare(
      'SELECT MAX(idx) as maxIdx FROM sentinel_lists WHERE key = ?'
    ).get(key);
    const nextIdx = (maxRow?.maxIdx ?? -1) + 1;
    this.db.prepare(
      'INSERT INTO sentinel_lists (key, idx, value) VALUES (?, ?, ?)'
    ).run(key, nextIdx, value);
    return nextIdx + 1;
  }

  async listRange(key: string, start = 0, end = -1): Promise<string[]> {
    let rows;
    if (end === -1) {
      rows = this.db.prepare(
        'SELECT value FROM sentinel_lists WHERE key = ? ORDER BY idx LIMIT -1 OFFSET ?'
      ).all(key, start);
    } else {
      rows = this.db.prepare(
        'SELECT value FROM sentinel_lists WHERE key = ? ORDER BY idx LIMIT ? OFFSET ?'
      ).all(key, end - start + 1, start);
    }
    return rows.map((r: any) => r.value);
  }

  async listLength(key: string): Promise<number> {
    const row = this.db.prepare(
      'SELECT COUNT(*) as cnt FROM sentinel_lists WHERE key = ?'
    ).get(key);
    return row?.cnt ?? 0;
  }

  async close(): Promise<void> {
    if (this.ownsDb) {
      this.db.close();
    }
  }
}

// ─── Store-backed wrappers for Sentinel components ───────────────────

/**
 * Convenience: create a store from a connection URL string.
 *
 *   createStoreFromUrl('redis://localhost:6379')
 *   createStoreFromUrl('postgresql://localhost:5432/sentinel')
 *   createStoreFromUrl('sqlite:///tmp/sentinel.db')
 *   createStoreFromUrl('memory://')
 */
export function createStoreFromUrl(url: string): SentinelStore {
  if (url.startsWith('redis://') || url.startsWith('rediss://')) {
    return new RedisStore({ url });
  }
  if (url.startsWith('postgresql://') || url.startsWith('postgres://')) {
    return new PostgresStore({ connectionString: url });
  }
  if (url.startsWith('sqlite://')) {
    const path = url.replace('sqlite://', '') || ':memory:';
    return new SQLiteStore({ path });
  }
  if (url === 'memory://' || url === '') {
    return new MemoryStore();
  }
  throw new Error(`Unsupported store URL scheme: ${url}. Use redis://, postgresql://, sqlite://, or memory://`);
}

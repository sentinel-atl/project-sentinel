# @sentinel-atl/store

Persistent storage adapters for the Sentinel Agent Trust Layer — Redis, PostgreSQL, SQLite, and in-memory backends.

## Install

```bash
npm install @sentinel-atl/store
```

Optional peer dependencies (install only the adapter you need):

```bash
npm install ioredis          # Redis / Valkey
npm install pg               # PostgreSQL
npm install better-sqlite3   # SQLite
```

## Quick Start

```ts
import { MemoryStore } from '@sentinel-atl/store';

const store = new MemoryStore();
await store.set('key', 'value');
await store.set('temp', 'value', 60); // TTL: 60 seconds
const val = await store.get('key');   // 'value'
```

## Adapters

### MemoryStore

Zero-dependency, in-process `Map` storage. Ideal for development and testing.

```ts
const store = new MemoryStore();
```

### RedisStore

Production-ready adapter using [ioredis](https://github.com/redis/ioredis).

```ts
import { RedisStore } from '@sentinel-atl/store';

const store = new RedisStore({
  url: 'redis://localhost:6379',
  prefix: 'sentinel:',
});
```

Options: `url`, `host`, `port`, `password`, `db`, `prefix`, `client` (existing ioredis instance).

### PostgresStore

Stores data in a PostgreSQL table with automatic schema creation.

```ts
import { PostgresStore } from '@sentinel-atl/store';

const store = new PostgresStore({
  connectionString: 'postgresql://user:pass@localhost:5432/sentinel',
  tableName: 'sentinel_kv', // default
});
```

Options: `connectionString`, `pool`, `tableName`, `schema`.

### SQLiteStore

Local file-based storage using [better-sqlite3](https://github.com/WiseLibs/better-sqlite3).

```ts
import { SQLiteStore } from '@sentinel-atl/store';

const store = new SQLiteStore('./sentinel.db');
```

## SentinelStore Interface

All adapters implement the `SentinelStore` interface:

```ts
interface SentinelStore {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string, ttlSeconds?: number): Promise<void>;
  delete(key: string): Promise<boolean>;
  has(key: string): Promise<boolean>;
  keys(prefix?: string): Promise<string[]>;
  getMany(keys: string[]): Promise<(string | undefined)[]>;
  setMany(entries: [string, string][]): Promise<void>;
  increment(key: string, by?: number): Promise<number>;
  listAppend(key: string, value: string): Promise<void>;
  listRange(key: string, start: number, end: number): Promise<string[]>;
  listLength(key: string): Promise<number>;
  close(): Promise<void>;
}
```

## License

MIT

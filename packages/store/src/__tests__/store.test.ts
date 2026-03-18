import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryStore } from '../index.js';

let store: MemoryStore;

beforeEach(() => {
  store = new MemoryStore();
});

describe('MemoryStore — basic key-value', () => {
  it('set and get a value', async () => {
    await store.set('key1', 'value1');
    expect(await store.get('key1')).toBe('value1');
  });

  it('returns undefined for missing key', async () => {
    expect(await store.get('nope')).toBeUndefined();
  });

  it('overwrites existing key', async () => {
    await store.set('key1', 'a');
    await store.set('key1', 'b');
    expect(await store.get('key1')).toBe('b');
  });

  it('has() returns true/false', async () => {
    expect(await store.has('key1')).toBe(false);
    await store.set('key1', 'val');
    expect(await store.has('key1')).toBe(true);
  });

  it('delete() removes key', async () => {
    await store.set('key1', 'val');
    expect(await store.delete('key1')).toBe(true);
    expect(await store.get('key1')).toBeUndefined();
    expect(await store.delete('key1')).toBe(false);
  });
});

describe('MemoryStore — TTL', () => {
  it('expires keys after TTL', async () => {
    // Use a tiny TTL (0.001s = 1ms) and wait for expiry
    await store.set('temp', 'value', 0.001);
    await new Promise(r => setTimeout(r, 20));
    expect(await store.get('temp')).toBeUndefined();
  });

  it('does not expire keys without TTL', async () => {
    await store.set('permanent', 'value');
    await new Promise(r => setTimeout(r, 10));
    expect(await store.get('permanent')).toBe('value');
  });

  it('has() returns false for expired keys', async () => {
    await store.set('temp', 'value', 0.001);
    await new Promise(r => setTimeout(r, 20));
    expect(await store.has('temp')).toBe(false);
  });
});

describe('MemoryStore — keys', () => {
  it('lists keys matching prefix', async () => {
    await store.set('user:1', 'a');
    await store.set('user:2', 'b');
    await store.set('session:1', 'c');

    const userKeys = await store.keys('user:');
    expect(userKeys).toHaveLength(2);
    expect(userKeys).toContain('user:1');
    expect(userKeys).toContain('user:2');
  });

  it('excludes expired keys', async () => {
    await store.set('temp:1', 'a', 0.001);
    await store.set('temp:2', 'b');
    await new Promise(r => setTimeout(r, 20));
    const keys = await store.keys('temp:');
    expect(keys).toEqual(['temp:2']);
  });
});

describe('MemoryStore — batch operations', () => {
  it('getMany returns found values', async () => {
    await store.set('k1', 'v1');
    await store.set('k2', 'v2');

    const result = await store.getMany(['k1', 'k2', 'k3']);
    expect(result.size).toBe(2);
    expect(result.get('k1')).toBe('v1');
    expect(result.get('k2')).toBe('v2');
    expect(result.has('k3')).toBe(false);
  });

  it('setMany sets multiple keys', async () => {
    await store.setMany([
      { key: 'a', value: '1' },
      { key: 'b', value: '2', ttlSeconds: 3600 },
    ]);
    expect(await store.get('a')).toBe('1');
    expect(await store.get('b')).toBe('2');
  });
});

describe('MemoryStore — increment', () => {
  it('increments from 0', async () => {
    expect(await store.increment('counter')).toBe(1);
    expect(await store.increment('counter')).toBe(2);
    expect(await store.increment('counter', 5)).toBe(7);
  });

  it('increments existing value', async () => {
    await store.set('counter', '10');
    expect(await store.increment('counter', 3)).toBe(13);
  });
});

describe('MemoryStore — lists', () => {
  it('appends and reads', async () => {
    await store.listAppend('log', 'entry1');
    await store.listAppend('log', 'entry2');
    await store.listAppend('log', 'entry3');

    const all = await store.listRange('log');
    expect(all).toEqual(['entry1', 'entry2', 'entry3']);
  });

  it('listLength returns count', async () => {
    expect(await store.listLength('log')).toBe(0);
    await store.listAppend('log', 'a');
    await store.listAppend('log', 'b');
    expect(await store.listLength('log')).toBe(2);
  });

  it('listRange with start/end', async () => {
    await store.listAppend('log', 'a');
    await store.listAppend('log', 'b');
    await store.listAppend('log', 'c');
    await store.listAppend('log', 'd');

    expect(await store.listRange('log', 1, 2)).toEqual(['b', 'c']);
    expect(await store.listRange('log', 2)).toEqual(['c', 'd']);
  });

  it('listRange with negative end', async () => {
    await store.listAppend('log', 'a');
    await store.listAppend('log', 'b');
    await store.listAppend('log', 'c');

    expect(await store.listRange('log', 0, -1)).toEqual(['a', 'b', 'c']);
    expect(await store.listRange('log', 0, -2)).toEqual(['a', 'b']);
  });

  it('delete removes lists', async () => {
    await store.listAppend('log', 'a');
    expect(await store.delete('log')).toBe(true);
    expect(await store.listLength('log')).toBe(0);
  });

  it('keys() includes list keys', async () => {
    await store.listAppend('list:1', 'a');
    await store.set('kv:1', 'b');
    const keys = await store.keys('');
    expect(keys).toContain('list:1');
    expect(keys).toContain('kv:1');
  });
});

describe('MemoryStore — close', () => {
  it('clears all data', async () => {
    await store.set('k', 'v');
    await store.listAppend('log', 'entry');
    await store.close();
    expect(await store.get('k')).toBeUndefined();
    expect(await store.listLength('log')).toBe(0);
  });
});

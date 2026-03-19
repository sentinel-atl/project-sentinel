/**
 * Tests for the pipeline package — DB, queue, blob, and schema.
 *
 * Tests the in-memory queue and local blob store. DB tests use a mock pool.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { InMemoryQueue, type ScanJob } from '../queue.js';
import { LocalBlobStore } from '../blob.js';
import { MIGRATIONS, SCHEMA_VERSION } from '../schema.js';
import { PipelineDb, type PgPool } from '../db.js';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// ─── Queue Tests ──────────────────────────────────────────────

describe('InMemoryQueue', () => {
  let queue: InMemoryQueue;

  beforeEach(() => {
    queue = new InMemoryQueue();
  });

  it('sends and receives messages', async () => {
    const job: ScanJob = { targetId: 't1', npmPackage: 'test-pkg', trigger: 'first_scan' };
    await queue.send(job);

    const msg = await queue.receive();
    expect(msg).not.toBeNull();
    expect(msg!.body.targetId).toBe('t1');
    expect(msg!.body.npmPackage).toBe('test-pkg');
    expect(msg!.dequeueCount).toBe(1);
  });

  it('returns null when queue is empty', async () => {
    const msg = await queue.receive();
    expect(msg).toBeNull();
  });

  it('removes message on complete', async () => {
    await queue.send({ targetId: 't1', trigger: 'manual' });
    const msg = await queue.receive();
    await msg!.complete();

    const msg2 = await queue.receive();
    expect(msg2).toBeNull();
    expect(await queue.approximateCount()).toBe(0);
  });

  it('tracks dequeue count', async () => {
    await queue.send({ targetId: 't1', trigger: 'scheduled' });

    // First dequeue
    const msg1 = await queue.receive(0); // 0s visibility = immediately visible again
    expect(msg1!.dequeueCount).toBe(1);

    // Second dequeue (same message)
    const msg2 = await queue.receive(0);
    expect(msg2!.dequeueCount).toBe(2);
  });

  it('handles FIFO ordering', async () => {
    await queue.send({ targetId: 't1', trigger: 'first_scan' });
    await queue.send({ targetId: 't2', trigger: 'first_scan' });
    await queue.send({ targetId: 't3', trigger: 'first_scan' });

    const m1 = await queue.receive();
    await m1!.complete();
    const m2 = await queue.receive();
    await m2!.complete();
    const m3 = await queue.receive();
    await m3!.complete();

    expect(m1!.body.targetId).toBe('t1');
    expect(m2!.body.targetId).toBe('t2');
    expect(m3!.body.targetId).toBe('t3');
  });

  it('reports approximate count', async () => {
    expect(await queue.approximateCount()).toBe(0);
    await queue.send({ targetId: 't1', trigger: 'manual' });
    await queue.send({ targetId: 't2', trigger: 'manual' });
    expect(await queue.approximateCount()).toBe(2);
  });
});

// ─── Blob Store Tests ─────────────────────────────────────────

describe('LocalBlobStore', () => {
  let tmpDir: string;
  let blob: LocalBlobStore;

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), 'sentinel-blob-test-'));
    blob = new LocalBlobStore(tmpDir);
  });

  it('uploads and downloads a report', async () => {
    const report = { packageName: 'test', trustScore: { overall: 85 } };
    const url = await blob.uploadReport('target-1', 'report-1', report);

    expect(url).toContain('target-1');
    expect(url).toContain('report-1.json');

    const downloaded = await blob.downloadReport(url);
    expect(downloaded).toEqual(report);
  });

  it('writes latest.json', async () => {
    const report = { version: '1.0.0' };
    await blob.uploadReport('target-2', 'report-abc', report);

    const latestPath = join(tmpDir, 'reports', 'target-2', 'latest.json');
    const latest = await blob.downloadReport(latestPath);
    expect(latest).toEqual(report);
  });

  it('returns null for missing blob', async () => {
    const result = await blob.downloadReport('/nonexistent/path.json');
    expect(result).toBeNull();
  });

  // Cleanup temp directory
  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  });
});

// ─── Schema Tests ─────────────────────────────────────────────

describe('Schema', () => {
  it('has correct version', () => {
    expect(SCHEMA_VERSION).toBe(2);
  });

  it('has migration entries', () => {
    expect(MIGRATIONS).toHaveLength(2);
  });

  it('V1 migration creates all tables', () => {
    const v1 = MIGRATIONS[0];
    expect(v1).toContain('CREATE TABLE IF NOT EXISTS targets');
    expect(v1).toContain('CREATE TABLE IF NOT EXISTS scan_reports');
    expect(v1).toContain('CREATE TABLE IF NOT EXISTS findings');
    expect(v1).toContain('CREATE TABLE IF NOT EXISTS publishers');
    expect(v1).toContain('CREATE TABLE IF NOT EXISTS crawl_runs');
    expect(v1).toContain('CREATE TABLE IF NOT EXISTS daily_stats');
    expect(v1).toContain('CREATE TABLE IF NOT EXISTS version_watch');
    expect(v1).toContain('CREATE TABLE IF NOT EXISTS schema_migrations');
  });

  it('V1 migration includes v0.5.0 scanner fields', () => {
    const v1 = MIGRATIONS[0];
    expect(v1).toContain('code_hash');
    expect(v1).toContain('score_integrity');
    expect(v1).toContain('score_behavior');
    expect(v1).toContain('score_provenance');
    expect(v1).toContain('ast_findings_count');
    expect(v1).toContain('scan_depth');
  });
});

// ─── DB Mock Tests ────────────────────────────────────────────

describe('PipelineDb', () => {
  let db: PipelineDb;
  let mockPool: PgPool;
  const queryResults: Map<string, { rows: Record<string, unknown>[]; rowCount: number }> = new Map();

  beforeEach(() => {
    queryResults.clear();
    mockPool = {
      query: vi.fn(async (text: string, _values?: unknown[]) => {
        // Return empty results for SELECT queries by default
        if (text.includes('SELECT')) {
          return queryResults.get(text) ?? { rows: [], rowCount: 0 };
        }
        return { rows: [], rowCount: 1 };
      }),
      end: vi.fn(async () => {}),
    };
    db = new PipelineDb({ pool: mockPool });
  });

  it('runs migrations', async () => {
    await db.migrate();
    expect(mockPool.query).toHaveBeenCalledTimes(MIGRATIONS.length);
  });

  it('upserts a new target', async () => {
    const target = {
      dedupKey: 'test-pkg',
      npmPackage: 'test-pkg',
      name: 'Test Package',
      sources: ['npm' as const],
      categories: [],
    };

    const id = await db.upsertTarget(target);
    expect(id).toBeDefined();
    expect(typeof id).toBe('string');
    // Should have called SELECT (to check existing) + INSERT
    expect(mockPool.query).toHaveBeenCalledTimes(2);
  });

  it('gets pending targets', async () => {
    const result = await db.getPendingTargets(10);
    expect(result).toEqual([]);
    expect(mockPool.query).toHaveBeenCalledWith(
      expect.stringContaining('WHERE status = \'pending\''),
      [10]
    );
  });

  it('marks target as scanning', async () => {
    await db.markScanning('target-123');
    expect(mockPool.query).toHaveBeenCalledWith(
      expect.stringContaining('UPDATE targets SET status = \'scanning\''),
      ['target-123']
    );
  });

  it('starts and completes a crawl run', async () => {
    const runId = await db.startCrawlRun('npm');
    expect(runId).toBeDefined();

    await db.completeCrawlRun(runId, 100, 50, 30);
    expect(mockPool.query).toHaveBeenCalledWith(
      expect.stringContaining('UPDATE crawl_runs'),
      expect.arrayContaining([runId, 100, 50, 30])
    );
  });

  it('closes the pool', async () => {
    await db.close();
    expect(mockPool.end).toHaveBeenCalled();
  });
});

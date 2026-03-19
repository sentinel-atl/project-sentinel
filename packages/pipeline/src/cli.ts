#!/usr/bin/env node
/**
 * Pipeline CLI — run worker, version watcher, or crawl locally.
 *
 * Usage:
 *   sentinel-worker                  — Start scanner worker
 *   sentinel-worker --crawl          — Run crawler and ingest targets
 *   sentinel-worker --watch          — Run version watcher once
 *
 * Environment:
 *   DATABASE_URL   — PostgreSQL connection string
 *   BLOB_PATH      — Local blob storage path (default: ./data/blobs)
 *   GITHUB_TOKEN   — GitHub token for crawler (optional)
 */

import { PipelineDb } from './db.js';
import { InMemoryQueue } from './queue.js';
import { LocalBlobStore } from './blob.js';
import { runWorker, checkVersionChanges } from './worker.js';

async function main() {
  const args = process.argv.slice(2);
  const mode = args.includes('--crawl') ? 'crawl' :
    args.includes('--watch') ? 'watch' : 'worker';

  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) {
    console.error('DATABASE_URL is required.');
    process.exit(1);
  }

  // Dynamic import of pg
  const { default: pg } = await import('pg');
  const pool = new pg.Pool({ connectionString: dbUrl, ssl: { rejectUnauthorized: false } });
  const db = new PipelineDb({ pool });

  // Run migrations on startup
  await db.migrate();

  const queue = new InMemoryQueue();
  const blob = new LocalBlobStore(process.env.BLOB_PATH ?? './data/blobs');

  const abortController = new AbortController();
  process.on('SIGINT', () => abortController.abort());
  process.on('SIGTERM', () => abortController.abort());

  if (mode === 'crawl') {
    console.log('Running crawlers...');
    const { crawlAll } = await import('@sentinel-atl/crawler');
    const result = await crawlAll({
      githubToken: process.env.GITHUB_TOKEN,
      sources: ['glama', 'npm', 'official'],
      onProgress: (msg, count) => console.log(`  ${msg} (${count} targets)`),
      signal: abortController.signal,
    });

    console.log(`Crawl complete: ${result.stats.totalRaw} raw → ${result.stats.totalDeduped} deduped`);
    console.log(`By source:`, result.stats.bySource);

    // Upsert all targets into DB and enqueue for scanning
    let newTargets = 0;
    for (const target of result.targets) {
      const targetId = await db.upsertTarget(target);
      if (target.npmPackage) {
        await queue.send({
          targetId,
          npmPackage: target.npmPackage,
          trigger: 'first_scan',
        });
        newTargets++;
      }
    }

    console.log(`Enqueued ${newTargets} npm packages for scanning.`);

    // If also running worker, process the queue
    if (!args.includes('--no-scan')) {
      console.log('Starting worker to process queue...');
      const stats = await runWorker({
        db, queue, blob,
        maxIdlePolls: 5,
        signal: abortController.signal,
      });
      console.log(`Worker done: ${stats.scanned} scanned, ${stats.failed} failed`);
    }
  } else if (mode === 'watch') {
    const result = await checkVersionChanges({ db, queue });
    console.log(`Version watcher: ${result.checked} checked, ${result.changed} changed`);
  } else {
    console.log('Starting scanner worker...');
    const stats = await runWorker({
      db, queue, blob,
      maxIdlePolls: 0, // never stop
      signal: abortController.signal,
    });
    console.log(`Worker stopped: ${stats.scanned} scanned, ${stats.failed} failed`);
  }

  await db.close();
}

main().catch(err => {
  console.error('Fatal:', err.message);
  process.exit(1);
});

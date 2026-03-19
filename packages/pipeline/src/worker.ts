/**
 * Scanner worker — the core loop that powers the data moat.
 *
 * Dequeue → resolve → scan → store → repeat.
 *
 * Designed to run in Azure Container Instances or locally.
 */

import { scan, resolvePackage, cleanupPackage, type ScanReport } from '@sentinel-atl/scanner';
import type { PipelineDb } from './db.js';
import type { ScanQueue, QueueMessage } from './queue.js';
import type { BlobStore } from './blob.js';

export interface WorkerConfig {
  db: PipelineDb;
  queue: ScanQueue;
  blob: BlobStore;
  /** Max consecutive empty polls before shutting down (0 = never stop) */
  maxIdlePolls?: number;
  /** Delay between polls when queue is empty (ms) */
  pollDelayMs?: number;
  /** Max retries before moving to dead letter */
  maxRetries?: number;
  /** Abort signal for graceful shutdown */
  signal?: AbortSignal;
  /** Log function */
  log?: (msg: string) => void;
}

export interface WorkerStats {
  scanned: number;
  failed: number;
  skipped: number;
  startedAt: string;
}

/**
 * Run the scanner worker loop.
 * Processes jobs from the queue until stopped or idle.
 */
export async function runWorker(config: WorkerConfig): Promise<WorkerStats> {
  const {
    db, queue, blob,
    maxIdlePolls = 20,
    pollDelayMs = 5_000,
    maxRetries = 3,
    signal,
    log = console.log,
  } = config;

  const stats: WorkerStats = {
    scanned: 0,
    failed: 0,
    skipped: 0,
    startedAt: new Date().toISOString(),
  };

  let idleCount = 0;

  while (!signal?.aborted) {
    const message = await queue.receive(300); // 5 min visibility timeout

    if (!message) {
      idleCount++;
      if (maxIdlePolls > 0 && idleCount >= maxIdlePolls) {
        log(`Worker idle for ${idleCount} polls, shutting down.`);
        break;
      }
      await sleep(pollDelayMs);
      continue;
    }

    idleCount = 0; // reset on successful dequeue
    const job = message.body;

    log(`Processing: ${job.npmPackage ?? job.repoUrl ?? job.targetId} (trigger: ${job.trigger})`);

    try {
      await processJob(message, { db, blob, log });
      stats.scanned++;
    } catch (err) {
      const error = err as Error;
      log(`Error scanning ${job.targetId}: ${error.message}`);
      stats.failed++;

      if (message.dequeueCount >= maxRetries) {
        log(`Max retries reached for ${job.targetId}, marking excluded.`);
        await db.markExcluded(job.targetId, `max_retries: ${error.message}`);
        await message.complete(); // remove from queue
      } else {
        // Message will become visible again after timeout → auto-retry
        await db.markError(job.targetId, error.message);
      }
    }
  }

  return stats;
}

async function processJob(
  message: QueueMessage,
  ctx: { db: PipelineDb; blob: BlobStore; log: (msg: string) => void }
): Promise<void> {
  const { db, blob, log } = ctx;
  const job = message.body;

  // 1. Mark target as scanning
  await db.markScanning(job.targetId);

  // 2. Resolve package to local path
  const specifier = job.npmPackage ?? job.repoUrl;
  if (!specifier) {
    throw new Error(`Job ${job.targetId} has no package or repo URL`);
  }

  const resolved = await resolvePackage(specifier);

  try {
    // 3. Run scanner
    const report: ScanReport = await scan({
      packagePath: resolved.path,
      skipDependencies: !job.npmPackage, // skip npm audit for non-npm packages
    });

    log(`  Score: ${report.trustScore.overall} (${report.trustScore.grade}) — ${report.findings.length} findings`);

    // 4. Upload full report to blob storage
    const reportId = crypto.randomUUID();
    const blobUrl = await blob.uploadReport(job.targetId, reportId, report);

    // 5. Write to PostgreSQL
    const dbReportId = await db.insertScanReport(job.targetId, report, blobUrl, job.trigger);
    await db.insertFindings(job.targetId, dbReportId, report.findings);

    // 6. Update version watch
    if (job.npmPackage) {
      await db.updateVersionWatch(job.targetId, report.packageVersion, null);
    }

    // 7. Complete message (remove from queue)
    await message.complete();
  } finally {
    // Always clean up temporary package files
    await cleanupPackage(resolved);
  }
}

// ─── Version Watcher ──────────────────────────────────────────

export interface VersionWatcherConfig {
  db: PipelineDb;
  queue: ScanQueue;
  /** Max targets to check per run */
  batchSize?: number;
  /** Concurrent requests to npm registry */
  concurrency?: number;
  /** Log function */
  log?: (msg: string) => void;
}

/**
 * Check npm registry for version changes and enqueue re-scans.
 * Runs as a periodic job (e.g., Azure Function timer, every 1h).
 */
export async function checkVersionChanges(config: VersionWatcherConfig): Promise<{ checked: number; changed: number }> {
  const { db, queue, batchSize = 500, concurrency = 20, log = console.log } = config;
  let checked = 0;
  let changed = 0;

  const targets = await db.getWatchedTargets(batchSize);
  log(`Version watcher: checking ${targets.length} targets`);

  // Process in batches of `concurrency`
  for (let i = 0; i < targets.length; i += concurrency) {
    const batch = targets.slice(i, i + concurrency);

    await Promise.allSettled(batch.map(async (target) => {
      checked++;
      try {
        const response = await fetch(
          `https://registry.npmjs.org/${encodeURIComponent(target.npm_package)}`,
          {
            headers: {
              'Accept': 'application/json',
              'User-Agent': 'sentinel-version-watcher/0.1.0',
              ...(target.npm_etag ? { 'If-None-Match': target.npm_etag } : {}),
            },
          }
        );

        if (response.status === 304) return; // no change
        if (!response.ok) return; // skip on error

        const data = await response.json() as { 'dist-tags'?: { latest?: string } };
        const latestVersion = data['dist-tags']?.latest;

        if (latestVersion && latestVersion !== target.last_known_version) {
          changed++;
          log(`  Version change: ${target.npm_package} ${target.last_known_version} → ${latestVersion}`);

          await queue.send({
            targetId: target.id,
            npmPackage: target.npm_package,
            trigger: 'version_change',
          });

          await db.updateVersionWatch(
            target.id,
            latestVersion,
            response.headers.get('etag')
          );
        } else {
          // Update check timestamp even if no change
          await db.updateVersionWatch(
            target.id,
            target.last_known_version ?? latestVersion ?? '',
            response.headers.get('etag')
          );
        }
      } catch {
        // Skip individual failures
      }
    }));

    // Rate limit batches
    await sleep(1_000);
  }

  log(`Version watcher done: ${checked} checked, ${changed} changed`);
  return { checked, changed };
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

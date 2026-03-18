/**
 * Audit log rotation — prevents unbounded log file growth.
 *
 * Supports:
 * - Size-based rotation: rotate when file exceeds maxSizeBytes
 * - Time-based rotation: rotate daily/hourly
 * - Retention: keep N rotated files, delete older ones
 * - Compression-ready: rotated files get .N suffix (gzip can be added later)
 */

import { stat, rename, unlink, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, basename, join } from 'node:path';

// ─── Types ───────────────────────────────────────────────────────────

export interface RotationConfig {
  /** Path to the active log file */
  logPath: string;
  /** Maximum size in bytes before rotation (default: 10MB) */
  maxSizeBytes?: number;
  /** Maximum number of rotated files to keep (default: 10) */
  maxFiles?: number;
  /** Rotation interval: 'size' | 'daily' | 'hourly' (default: 'size') */
  interval?: 'size' | 'daily' | 'hourly';
}

// ─── Rotation ────────────────────────────────────────────────────────

/**
 * Check if the log file needs rotation and rotate if so.
 * Returns true if rotation occurred.
 */
export async function rotateIfNeeded(config: RotationConfig): Promise<boolean> {
  const { logPath } = config;
  const maxSize = config.maxSizeBytes ?? 10_485_760; // 10 MB
  const maxFiles = config.maxFiles ?? 10;

  if (!existsSync(logPath)) return false;

  const interval = config.interval ?? 'size';

  let shouldRotate = false;

  if (interval === 'size') {
    const fileStat = await stat(logPath);
    shouldRotate = fileStat.size >= maxSize;
  } else if (interval === 'daily' || interval === 'hourly') {
    const fileStat = await stat(logPath);
    const now = new Date();
    const fileTime = new Date(fileStat.mtime);

    if (interval === 'daily') {
      shouldRotate = now.toDateString() !== fileTime.toDateString();
    } else {
      shouldRotate = now.getHours() !== fileTime.getHours() ||
                     now.toDateString() !== fileTime.toDateString();
    }
  }

  if (!shouldRotate) return false;

  await rotate(logPath, maxFiles);
  return true;
}

/**
 * Perform the rotation: shift existing files and rename current log.
 *
 * log.jsonl    → log.jsonl.1
 * log.jsonl.1  → log.jsonl.2
 * ...
 * log.jsonl.N  → deleted (if N > maxFiles)
 */
async function rotate(logPath: string, maxFiles: number): Promise<void> {
  // Delete the oldest file if it exists
  const oldest = `${logPath}.${maxFiles}`;
  if (existsSync(oldest)) {
    await unlink(oldest);
  }

  // Shift existing rotated files
  for (let i = maxFiles - 1; i >= 1; i--) {
    const from = `${logPath}.${i}`;
    const to = `${logPath}.${i + 1}`;
    if (existsSync(from)) {
      await rename(from, to);
    }
  }

  // Rotate current log
  await rename(logPath, `${logPath}.1`);
}

/**
 * Clean up rotated files beyond the retention limit.
 */
export async function cleanupRotatedFiles(config: RotationConfig): Promise<number> {
  const maxFiles = config.maxFiles ?? 10;
  const dir = dirname(config.logPath);
  const base = basename(config.logPath);

  const files = await readdir(dir);
  const rotatedFiles = files
    .filter(f => f.startsWith(base + '.') && /\.\d+$/.test(f))
    .sort((a, b) => {
      const numA = parseInt(a.split('.').pop()!);
      const numB = parseInt(b.split('.').pop()!);
      return numA - numB;
    });

  let removed = 0;
  for (const file of rotatedFiles) {
    const num = parseInt(file.split('.').pop()!);
    if (num > maxFiles) {
      await unlink(join(dir, file));
      removed++;
    }
  }

  return removed;
}

/**
 * Get total size of all log files (active + rotated).
 */
export async function totalLogSize(config: RotationConfig): Promise<number> {
  const dir = dirname(config.logPath);
  const base = basename(config.logPath);

  let total = 0;

  if (existsSync(config.logPath)) {
    total += (await stat(config.logPath)).size;
  }

  try {
    const files = await readdir(dir);
    for (const file of files) {
      if (file.startsWith(base + '.') && /\.\d+$/.test(file)) {
        total += (await stat(join(dir, file))).size;
      }
    }
  } catch {
    // Directory might not exist
  }

  return total;
}

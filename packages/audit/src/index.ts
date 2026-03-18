/**
 * @sentinel-atl/audit — Tamper-evident audit logging
 *
 * Every Sentinel event gets logged in a structured, append-only trail
 * with hash-chain integrity. Each entry includes the SHA-256 hash of the
 * previous entry — if anyone tampers with history, the chain breaks.
 *
 * This is how you answer "what happened?" after an incident.
 */

import { hash, toHex, textToBytes } from '@sentinel-atl/core';
import { appendFile, readFile, writeFile, stat, rename, unlink } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

export type AuditEventType =
  | 'identity_created'
  | 'handshake_init'
  | 'handshake_complete'
  | 'handshake_failed'
  | 'vc_issued'
  | 'vc_verified'
  | 'vc_revoked'
  | 'intent_created'
  | 'intent_validated'
  | 'intent_rejected'
  | 'session_created'
  | 'session_terminated'
  | 'reputation_vouch'
  | 'reputation_negative'
  | 'emergency_revoke'
  | 'key_rotated'
  | 'key_backup_created'
  | 'key_recovered';

export interface AuditEntry {
  timestamp: string;
  eventType: AuditEventType;
  actorDid: string;
  targetDid?: string;
  intentId?: string;
  result: 'success' | 'failure';
  reason?: string;
  metadata?: Record<string, unknown>;
  prevHash: string;
  entryHash: string;
}

export interface AuditLogConfig {
  /** Path to the audit log file */
  logPath: string;
  /** Maximum retention in days (default: 90) */
  retentionDays?: number;
  /** Maximum log file size in bytes before rotation (default: 10 MB) */
  maxSizeBytes?: number;
  /** Maximum number of rotated files to keep (default: 10) */
  maxRotatedFiles?: number;
  /** Rotation interval: 'size' | 'daily' | 'hourly' (default: 'size') */
  rotationInterval?: 'size' | 'daily' | 'hourly';
}

const GENESIS_HASH = '0'.repeat(64);

/**
 * Recursively sort all object keys for deterministic serialization.
 */
function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value !== null && typeof value === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

/**
 * Compute the hash of an audit entry (excluding entryHash itself).
 *
 * Uses recursive deep-sort to ensure deterministic serialization
 * regardless of key insertion order or undefined-valued fields.
 */
function computeEntryHash(entry: Omit<AuditEntry, 'entryHash'>): string {
  const data = JSON.stringify(sortDeep(entry));
  return toHex(hash(textToBytes(data)));
}

export class AuditLog {
  private logPath: string;
  private lastHash: string = GENESIS_HASH;
  private initialized = false;
  private rotationConfig: {
    maxSizeBytes: number;
    maxFiles: number;
    interval: 'size' | 'daily' | 'hourly';
  };
  private writesSinceRotationCheck = 0;

  constructor(config: AuditLogConfig) {
    this.logPath = config.logPath;
    this.rotationConfig = {
      maxSizeBytes: config.maxSizeBytes ?? 10_485_760,
      maxFiles: config.maxRotatedFiles ?? 10,
      interval: config.rotationInterval ?? 'size',
    };
  }

  /**
   * Initialize the audit log. Reads the last entry to get the chain hash.
   */
  async init(): Promise<void> {
    if (this.initialized) return;

    if (existsSync(this.logPath)) {
      const content = await readFile(this.logPath, 'utf-8');
      const lines = content.trim().split('\n').filter(Boolean);
      if (lines.length > 0) {
        const lastEntry: AuditEntry = JSON.parse(lines[lines.length - 1]);
        this.lastHash = lastEntry.entryHash;
      }
    }

    this.initialized = true;
  }

  /**
   * Append an audit event. Returns the entry with its hash.
   *
   * This is append-only. No mutation. No deletion.
   * The hash chain means any tampering is detectable.
   */
  async log(event: {
    eventType: AuditEventType;
    actorDid: string;
    targetDid?: string;
    intentId?: string;
    result: 'success' | 'failure';
    reason?: string;
    metadata?: Record<string, unknown>;
  }): Promise<AuditEntry> {
    await this.init();

    const entryWithoutHash = {
      timestamp: new Date().toISOString(),
      eventType: event.eventType,
      actorDid: event.actorDid,
      targetDid: event.targetDid,
      intentId: event.intentId,
      result: event.result,
      reason: event.reason,
      metadata: event.metadata,
      prevHash: this.lastHash,
    };

    const entryHash = computeEntryHash(entryWithoutHash);
    const entry: AuditEntry = { ...entryWithoutHash, entryHash };

    await appendFile(this.logPath, JSON.stringify(entry) + '\n', 'utf-8');
    this.lastHash = entryHash;

    // Check rotation every 100 writes to avoid stat() on every append
    this.writesSinceRotationCheck++;
    if (this.writesSinceRotationCheck >= 100) {
      this.writesSinceRotationCheck = 0;
      await this.maybeRotate();
    }

    return entry;
  }

  /**
   * Rotate the log file if it exceeds configured limits.
   * Rotation creates numbered backups (log.jsonl.1, .2, etc.)
   * and starts a fresh chain with GENESIS_HASH.
   */
  async maybeRotate(): Promise<boolean> {
    if (!existsSync(this.logPath)) return false;

    const { maxSizeBytes, maxFiles, interval } = this.rotationConfig;
    const fileStat = await stat(this.logPath);

    let shouldRotate = false;
    if (interval === 'size') {
      shouldRotate = fileStat.size >= maxSizeBytes;
    } else if (interval === 'daily' || interval === 'hourly') {
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

    // Shift existing rotated files
    for (let i = maxFiles - 1; i >= 1; i--) {
      const from = `${this.logPath}.${i}`;
      const to = `${this.logPath}.${i + 1}`;
      if (existsSync(from)) {
        await rename(from, to);
      }
    }
    const oldest = `${this.logPath}.${maxFiles}`;
    if (existsSync(oldest)) {
      await unlink(oldest);
    }
    await rename(this.logPath, `${this.logPath}.1`);

    // Reset chain for the new log file
    this.lastHash = GENESIS_HASH;
    return true;
  }

  /**
   * Verify the integrity of the entire audit log.
   * Returns the first broken entry or null if the chain is intact.
   */
  async verifyIntegrity(): Promise<{
    valid: boolean;
    totalEntries: number;
    brokenAt?: number;
    error?: string;
  }> {
    await this.init();

    if (!existsSync(this.logPath)) {
      return { valid: true, totalEntries: 0 };
    }

    const content = await readFile(this.logPath, 'utf-8');
    const lines = content.trim().split('\n').filter(Boolean);

    let expectedPrevHash = GENESIS_HASH;

    for (let i = 0; i < lines.length; i++) {
      const entry: AuditEntry = JSON.parse(lines[i]);

      // Check chain link
      if (entry.prevHash !== expectedPrevHash) {
        return {
          valid: false,
          totalEntries: lines.length,
          brokenAt: i,
          error: `Chain broken at entry ${i}: expected prevHash ${expectedPrevHash}, got ${entry.prevHash}`,
        };
      }

      // Recompute hash
      const { entryHash, ...rest } = entry;
      const recomputed = computeEntryHash(rest);
      if (recomputed !== entryHash) {
        return {
          valid: false,
          totalEntries: lines.length,
          brokenAt: i,
          error: `Hash mismatch at entry ${i}: entry may have been tampered with`,
        };
      }

      expectedPrevHash = entryHash;
    }

    return { valid: true, totalEntries: lines.length };
  }

  /**
   * Read all entries (for inspection/export).
   */
  async readAll(): Promise<AuditEntry[]> {
    if (!existsSync(this.logPath)) return [];
    const content = await readFile(this.logPath, 'utf-8');
    return content
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  }
}

export { GENESIS_HASH };

// ─── Standalone API ──────────────────────────────────────────────────
//
// Use Sentinel audit logging WITHOUT the full trust framework.
// No DIDs, no VCs, no handshakes — just structured, tamper-evident logs.
//
//   import { createAuditLog } from '@sentinel-atl/audit';
//   const log = await createAuditLog('./my-app-audit.jsonl');
//   await log.log({ eventType: 'vc_issued', actorDid: 'my-service', result: 'success' });
//   const integrity = await log.verifyIntegrity();

/**
 * Create an audit log with a single function call.
 * Works standalone — no Sentinel SDK or DID setup required.
 */
export async function createAuditLog(path: string): Promise<AuditLog> {
  const log = new AuditLog({ logPath: path });
  await log.init();
  return log;
}

/**
 * Quick integrity check for any Sentinel audit log file.
 */
export async function verifyAuditFile(path: string): Promise<{
  valid: boolean;
  totalEntries: number;
  brokenAt?: number;
  error?: string;
}> {
  const log = new AuditLog({ logPath: path });
  return log.verifyIntegrity();
}

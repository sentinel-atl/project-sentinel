/**
 * @sentinel/audit — Tamper-evident audit logging
 *
 * Every Sentinel event gets logged in a structured, append-only trail
 * with hash-chain integrity. Each entry includes the SHA-256 hash of the
 * previous entry — if anyone tampers with history, the chain breaks.
 *
 * This is how you answer "what happened?" after an incident.
 */

import { hash, toHex, textToBytes } from '@sentinel/core';
import { appendFile, readFile, writeFile } from 'node:fs/promises';
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

  constructor(config: AuditLogConfig) {
    this.logPath = config.logPath;
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

    return entry;
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

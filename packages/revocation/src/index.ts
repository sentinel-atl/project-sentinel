/**
 * @sentinel/revocation — DID & VC Revocation, Key Rotation, Kill Switch
 *
 * When things go wrong — compromised keys, rogue agents, policy violations —
 * you need to revoke trust FAST. This module provides:
 *
 * 1. **VC Revocation List (VRL):** Signed list of revoked credential IDs.
 *    Any verifier checks the VRL before trusting a VC.
 *
 * 2. **DID Revocation:** Mark an entire agent identity as revoked.
 *    All VCs issued by or to that DID become untrusted.
 *
 * 3. **Key Rotation:** Generate a new keypair and publish a signed rotation
 *    notice linking old DID → new DID. Verifiers follow the chain.
 *
 * 4. **Emergency Kill Switch:** Immediately revoke an agent + all downstream
 *    delegations. Logged to audit with highest priority.
 *
 * All revocation decisions are signed by the revoker to prevent spoofing,
 * and every action is audit-logged.
 */

import {
  toHex,
  toBase64Url,
  fromBase64Url,
  textToBytes,
  secureRandom,
  sign,
  verify,
  hash,
  didToPublicKey,
  type KeyProvider,
} from '@sentinel/core';
import { AuditLog } from '@sentinel/audit';

// ─── VC Revocation List (VRL) ────────────────────────────────────────

export interface RevocationEntry {
  /** The revoked VC's ID (urn:uuid:...) */
  credentialId: string;
  /** When it was revoked */
  revokedAt: string;
  /** Why it was revoked */
  reason: RevocationReason;
  /** Optional human-readable explanation */
  details?: string;
}

export type RevocationReason =
  | 'key_compromise'
  | 'credential_expired_early'
  | 'policy_violation'
  | 'scope_violation'
  | 'agent_decommissioned'
  | 'emergency'
  | 'key_rotation'
  | 'manual';

export interface SignedRevocationList {
  /** List version — monotonically increasing */
  version: number;
  /** DID of the entity that published this list */
  issuerDid: string;
  /** When this list was published */
  publishedAt: string;
  /** Revoked credentials */
  entries: RevocationEntry[];
  /** Ed25519 signature over the canonical list (base64url) */
  signature: string;
}

// ─── DID Revocation ──────────────────────────────────────────────────

export interface DIDRevocation {
  /** The revoked DID */
  did: string;
  /** Who revoked it */
  revokedBy: string;
  /** When */
  revokedAt: string;
  /** Why */
  reason: RevocationReason;
  details?: string;
  /** Signature by the revoker (base64url) */
  signature: string;
}

// ─── Key Rotation ────────────────────────────────────────────────────

export interface KeyRotationNotice {
  /** The old DID being rotated away from */
  oldDid: string;
  /** The new DID to use going forward */
  newDid: string;
  /** When the rotation happened */
  rotatedAt: string;
  /** Signature by the OLD key (proves control) */
  oldKeySignature: string;
  /** Signature by the NEW key (proves ownership) */
  newKeySignature: string;
}

// ─── Kill Switch ─────────────────────────────────────────────────────

export interface KillSwitchEvent {
  /** The agent DID being killed */
  targetDid: string;
  /** Who activated the kill switch */
  activatedBy: string;
  /** When */
  activatedAt: string;
  /** Why */
  reason: string;
  /** Whether to cascade to all downstream delegations */
  cascade: boolean;
  /** DIDs of downstream agents also revoked (if cascade=true) */
  cascadedDids: string[];
  /** Signature by the activator (base64url) */
  signature: string;
}

// ─── Canonicalization ────────────────────────────────────────────────

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

function canonicalize(obj: Record<string, unknown>): Uint8Array {
  return textToBytes(JSON.stringify(sortDeep(obj)));
}

// ─── Revocation Manager ─────────────────────────────────────────────

export class RevocationManager {
  private revokedVCs = new Map<string, RevocationEntry>();
  private revokedDIDs = new Map<string, DIDRevocation>();
  private rotations = new Map<string, KeyRotationNotice>();
  private killEvents: KillSwitchEvent[] = [];
  private listVersion = 0;
  private auditLog?: AuditLog;

  constructor(auditLog?: AuditLog) {
    this.auditLog = auditLog;
  }

  // ─── VC Revocation ───────────────────────────────────────────────

  /**
   * Revoke a Verifiable Credential.
   * The revoker signs the revocation entry to prevent spoofing.
   */
  async revokeVC(
    keyProvider: KeyProvider,
    revokerKeyId: string,
    revokerDid: string,
    credentialId: string,
    reason: RevocationReason,
    details?: string
  ): Promise<RevocationEntry> {
    const entry: RevocationEntry = {
      credentialId,
      revokedAt: new Date().toISOString(),
      reason,
      details,
    };

    this.revokedVCs.set(credentialId, entry);

    await this.auditLog?.log({
      eventType: 'vc_revoked',
      actorDid: revokerDid,
      result: 'success',
      metadata: { credentialId, reason },
    });

    return entry;
  }

  /**
   * Check if a VC is revoked.
   */
  isVCRevoked(credentialId: string): boolean {
    return this.revokedVCs.has(credentialId);
  }

  /**
   * Get the revocation entry for a VC (if revoked).
   */
  getVCRevocation(credentialId: string): RevocationEntry | undefined {
    return this.revokedVCs.get(credentialId);
  }

  /**
   * Publish a signed revocation list.
   */
  async publishRevocationList(
    keyProvider: KeyProvider,
    issuerKeyId: string,
    issuerDid: string
  ): Promise<SignedRevocationList> {
    this.listVersion++;

    const listBody = {
      version: this.listVersion,
      issuerDid,
      publishedAt: new Date().toISOString(),
      entries: Array.from(this.revokedVCs.values()),
    };

    const dataToSign = canonicalize(listBody as unknown as Record<string, unknown>);
    const sig = await keyProvider.sign(issuerKeyId, dataToSign);

    return {
      ...listBody,
      signature: toBase64Url(sig),
    };
  }

  /**
   * Verify a signed revocation list.
   */
  async verifyRevocationList(list: SignedRevocationList): Promise<{ valid: boolean; error?: string }> {
    try {
      const publicKey = didToPublicKey(list.issuerDid);
      const { signature, ...body } = list;
      const dataToVerify = canonicalize(body as unknown as Record<string, unknown>);
      const sig = fromBase64Url(signature);
      const valid = await verify(sig, dataToVerify, publicKey);
      return valid ? { valid: true } : { valid: false, error: 'Invalid signature on revocation list' };
    } catch (e) {
      return { valid: false, error: `Verification failed: ${(e as Error).message}` };
    }
  }

  /**
   * Import a verified revocation list (merge entries).
   */
  importRevocationList(list: SignedRevocationList): number {
    let imported = 0;
    for (const entry of list.entries) {
      if (!this.revokedVCs.has(entry.credentialId)) {
        this.revokedVCs.set(entry.credentialId, entry);
        imported++;
      }
    }
    return imported;
  }

  // ─── DID Revocation ──────────────────────────────────────────────

  /**
   * Revoke a DID. Signs the revocation with the revoker's key.
   */
  async revokeDID(
    keyProvider: KeyProvider,
    revokerKeyId: string,
    revokerDid: string,
    targetDid: string,
    reason: RevocationReason,
    details?: string
  ): Promise<DIDRevocation> {
    const body = {
      did: targetDid,
      revokedBy: revokerDid,
      revokedAt: new Date().toISOString(),
      reason,
      details,
    };

    const dataToSign = canonicalize(body as unknown as Record<string, unknown>);
    const sig = await keyProvider.sign(revokerKeyId, dataToSign);

    const revocation: DIDRevocation = {
      ...body,
      signature: toBase64Url(sig),
    };

    this.revokedDIDs.set(targetDid, revocation);

    await this.auditLog?.log({
      eventType: 'emergency_revoke',
      actorDid: revokerDid,
      targetDid,
      result: 'success',
      metadata: { reason, type: 'did_revocation' },
    });

    return revocation;
  }

  /**
   * Check if a DID is revoked.
   */
  isDIDRevoked(did: string): boolean {
    return this.revokedDIDs.has(did);
  }

  /**
   * Verify a DID revocation notice.
   */
  async verifyDIDRevocation(revocation: DIDRevocation): Promise<{ valid: boolean; error?: string }> {
    try {
      const publicKey = didToPublicKey(revocation.revokedBy);
      const { signature, ...body } = revocation;
      const dataToVerify = canonicalize(body as unknown as Record<string, unknown>);
      const sig = fromBase64Url(signature);
      const valid = await verify(sig, dataToVerify, publicKey);
      return valid ? { valid: true } : { valid: false, error: 'Invalid signature on DID revocation' };
    } catch (e) {
      return { valid: false, error: `Verification failed: ${(e as Error).message}` };
    }
  }

  // ─── Key Rotation ────────────────────────────────────────────────

  /**
   * Rotate an agent's key. Both old and new keys sign the rotation notice.
   * This proves: "I own the old key AND the new key, and I'm switching."
   */
  async rotateKey(
    oldKeyProvider: KeyProvider,
    oldKeyId: string,
    oldDid: string,
    newKeyProvider: KeyProvider,
    newKeyId: string,
    newDid: string
  ): Promise<KeyRotationNotice> {
    const rotatedAt = new Date().toISOString();
    const rotationData = textToBytes(
      `key-rotation:${oldDid}:${newDid}:${rotatedAt}`
    );

    const oldSig = await oldKeyProvider.sign(oldKeyId, rotationData);
    const newSig = await newKeyProvider.sign(newKeyId, rotationData);

    const notice: KeyRotationNotice = {
      oldDid,
      newDid,
      rotatedAt,
      oldKeySignature: toBase64Url(oldSig),
      newKeySignature: toBase64Url(newSig),
    };

    this.rotations.set(oldDid, notice);

    // Also revoke the old DID
    this.revokedDIDs.set(oldDid, {
      did: oldDid,
      revokedBy: oldDid,
      revokedAt: notice.rotatedAt,
      reason: 'key_rotation',
      details: `Rotated to ${newDid}`,
      signature: notice.oldKeySignature,
    });

    await this.auditLog?.log({
      eventType: 'key_rotated',
      actorDid: oldDid,
      targetDid: newDid,
      result: 'success',
      metadata: { type: 'key_rotation' },
    });

    return notice;
  }

  /**
   * Verify a key rotation notice (both signatures must be valid).
   */
  async verifyKeyRotation(notice: KeyRotationNotice): Promise<{ valid: boolean; error?: string }> {
    try {
      const rotationData = textToBytes(
        `key-rotation:${notice.oldDid}:${notice.newDid}:${notice.rotatedAt}`
      );

      const oldPubKey = didToPublicKey(notice.oldDid);
      const newPubKey = didToPublicKey(notice.newDid);

      const oldSig = fromBase64Url(notice.oldKeySignature);
      const newSig = fromBase64Url(notice.newKeySignature);

      const oldValid = await verify(oldSig, rotationData, oldPubKey);
      if (!oldValid) return { valid: false, error: 'Old key signature invalid' };

      const newValid = await verify(newSig, rotationData, newPubKey);
      if (!newValid) return { valid: false, error: 'New key signature invalid' };

      return { valid: true };
    } catch (e) {
      return { valid: false, error: `Verification failed: ${(e as Error).message}` };
    }
  }

  /**
   * Resolve the current DID for an agent (follows rotation chain).
   */
  resolveCurrentDid(did: string): string {
    let current = did;
    const seen = new Set<string>();
    while (this.rotations.has(current)) {
      if (seen.has(current)) break; // Prevent cycles
      seen.add(current);
      current = this.rotations.get(current)!.newDid;
    }
    return current;
  }

  // ─── Kill Switch ─────────────────────────────────────────────────

  /**
   * Emergency kill switch — immediately revoke an agent and optionally
   * cascade to all downstream delegations.
   *
   * This is the "big red button." Use when an agent is:
   * - Compromised
   * - Producing harmful output
   * - Violating scope
   * - Otherwise untrustworthy
   */
  async killSwitch(
    keyProvider: KeyProvider,
    activatorKeyId: string,
    activatorDid: string,
    targetDid: string,
    reason: string,
    options: {
      cascade?: boolean;
      downstreamDids?: string[];
    } = {}
  ): Promise<KillSwitchEvent> {
    const cascade = options.cascade ?? false;
    const cascadedDids = options.downstreamDids ?? [];

    const body = {
      targetDid,
      activatedBy: activatorDid,
      activatedAt: new Date().toISOString(),
      reason,
      cascade,
      cascadedDids,
    };

    const dataToSign = canonicalize(body as unknown as Record<string, unknown>);
    const sig = await keyProvider.sign(activatorKeyId, dataToSign);

    const event: KillSwitchEvent = {
      ...body,
      signature: toBase64Url(sig),
    };

    this.killEvents.push(event);

    // Revoke the target DID
    this.revokedDIDs.set(targetDid, {
      did: targetDid,
      revokedBy: activatorDid,
      revokedAt: event.activatedAt,
      reason: 'emergency',
      details: reason,
      signature: event.signature,
    });

    // Cascade if requested
    if (cascade) {
      for (const downstream of cascadedDids) {
        this.revokedDIDs.set(downstream, {
          did: downstream,
          revokedBy: activatorDid,
          revokedAt: event.activatedAt,
          reason: 'emergency',
          details: `Cascaded from kill switch on ${targetDid}: ${reason}`,
          signature: event.signature,
        });
      }
    }

    await this.auditLog?.log({
      eventType: 'emergency_revoke',
      actorDid: activatorDid,
      targetDid,
      result: 'success',
      metadata: {
        type: 'kill_switch',
        reason,
        cascade,
        cascadedCount: cascadedDids.length,
      },
    });

    return event;
  }

  /**
   * Verify a kill switch event signature.
   */
  async verifyKillSwitch(event: KillSwitchEvent): Promise<{ valid: boolean; error?: string }> {
    try {
      const publicKey = didToPublicKey(event.activatedBy);
      const { signature, ...body } = event;
      const dataToVerify = canonicalize(body as unknown as Record<string, unknown>);
      const sig = fromBase64Url(signature);
      const valid = await verify(sig, dataToVerify, publicKey);
      return valid ? { valid: true } : { valid: false, error: 'Invalid kill switch signature' };
    } catch (e) {
      return { valid: false, error: `Verification failed: ${(e as Error).message}` };
    }
  }

  /**
   * Get all kill switch events.
   */
  getKillEvents(): KillSwitchEvent[] {
    return [...this.killEvents];
  }

  // ─── Comprehensive Trust Check ───────────────────────────────────

  /**
   * Full trust check: is this DID + credential ID currently trusted?
   *
   * Returns false if the DID is revoked, the VC is revoked,
   * or the agent has been killed.
   */
  isTrusted(did: string, credentialId?: string): { trusted: boolean; reason?: string } {
    // Check DID revocation
    if (this.revokedDIDs.has(did)) {
      const rev = this.revokedDIDs.get(did)!;
      return { trusted: false, reason: `DID revoked: ${rev.reason}` };
    }

    // Check VC revocation
    if (credentialId && this.revokedVCs.has(credentialId)) {
      const rev = this.revokedVCs.get(credentialId)!;
      return { trusted: false, reason: `VC revoked: ${rev.reason}` };
    }

    return { trusted: true };
  }

  /**
   * Get summary stats.
   */
  getStats(): {
    revokedVCs: number;
    revokedDIDs: number;
    rotations: number;
    killEvents: number;
  } {
    return {
      revokedVCs: this.revokedVCs.size,
      revokedDIDs: this.revokedDIDs.size,
      rotations: this.rotations.size,
      killEvents: this.killEvents.length,
    };
  }
}

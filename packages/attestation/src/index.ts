/**
 * @sentinel/attestation — Code Attestation for AI Agents
 *
 * "Trust, but verify the code."
 *
 * Code attestation lets an agent PROVE it's running a specific, audited
 * version of its code. This is critical for:
 *
 * 1. **Supply chain security** — was this agent built from trusted code?
 * 2. **Reproducibility** — can a verifier confirm the agent's behavior?
 * 3. **Accountability** — when things go wrong, which VERSION went wrong?
 *
 * How it works:
 * 1. Agent (or its build pipeline) hashes its code → `codeHash`
 * 2. Agent signs a `CodeAttestationCredential` binding its DID to that hash
 * 3. Verifiers check: "this DID is running code with hash X, signed at time T"
 *
 * Optional: include `repositoryUrl`, `commitHash`, `buildId` for full traceability.
 */

import {
  hash,
  toHex,
  toBase64Url,
  fromBase64Url,
  textToBytes,
  sign,
  verify,
  didToPublicKey,
  type KeyProvider,
} from '@sentinel/core';
import { AuditLog } from '@sentinel/audit';
import { createHash } from 'node:crypto';
import { readFile, readdir, stat } from 'node:fs/promises';
import { join, relative } from 'node:path';

// ─── Types ───────────────────────────────────────────────────────────

export interface CodeAttestation {
  /** The agent's DID */
  agentDid: string;
  /** SHA-256 hash of the agent's code (hex) */
  codeHash: string;
  /** When the attestation was created */
  attestedAt: string;
  /** Human-readable version string */
  version?: string;
  /** Git repository URL */
  repositoryUrl?: string;
  /** Git commit hash */
  commitHash?: string;
  /** CI/CD build identifier */
  buildId?: string;
  /** Files included in the hash (relative paths) */
  includedFiles: string[];
  /** Ed25519 signature by the agent */
  signature: string;
}

export interface AttestationVerifyResult {
  valid: boolean;
  error?: string;
  codeHash?: string;
  attestedAt?: string;
}

export interface HashDirectoryOptions {
  /** File extensions to include (e.g., ['.ts', '.js']). If empty, all files included. */
  extensions?: string[];
  /** Paths to exclude (relative, e.g., ['node_modules', 'dist']). */
  exclude?: string[];
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

// ─── Directory Hashing ───────────────────────────────────────────────

/**
 * Recursively collect all files in a directory, sorted deterministically.
 */
async function collectFiles(
  dir: string,
  basePath: string,
  options: HashDirectoryOptions
): Promise<string[]> {
  const files: string[] = [];
  const entries = await readdir(dir, { withFileTypes: true });

  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const fullPath = join(dir, entry.name);
    const relPath = relative(basePath, fullPath);

    // Check exclusions
    if (options.exclude?.some(ex => relPath.startsWith(ex))) continue;

    if (entry.isDirectory()) {
      files.push(...await collectFiles(fullPath, basePath, options));
    } else if (entry.isFile()) {
      if (options.extensions && options.extensions.length > 0) {
        if (!options.extensions.some(ext => entry.name.endsWith(ext))) continue;
      }
      files.push(fullPath);
    }
  }

  return files;
}

/**
 * Compute a deterministic SHA-256 hash over a directory's contents.
 * Files are sorted lexicographically and each is hashed with its relative path.
 */
export async function hashDirectory(
  dirPath: string,
  options: HashDirectoryOptions = {}
): Promise<{ codeHash: string; includedFiles: string[] }> {
  const files = await collectFiles(dirPath, dirPath, options);
  const hasher = createHash('sha256');
  const includedFiles: string[] = [];

  for (const file of files) {
    const relPath = relative(dirPath, file);
    includedFiles.push(relPath);
    const content = await readFile(file);
    // Hash: relative_path + NUL + content
    hasher.update(relPath);
    hasher.update('\0');
    hasher.update(content);
  }

  return {
    codeHash: hasher.digest('hex'),
    includedFiles,
  };
}

/**
 * Hash a single buffer or string (for testing or simple use cases).
 */
export function hashCode(code: string | Uint8Array): string {
  const data = typeof code === 'string' ? textToBytes(code) : code;
  return toHex(hash(data));
}

// ─── Attestation Manager ─────────────────────────────────────────────

export class AttestationManager {
  private attestations = new Map<string, CodeAttestation>();
  private auditLog?: AuditLog;

  constructor(auditLog?: AuditLog) {
    this.auditLog = auditLog;
  }

  /**
   * Create a signed code attestation.
   */
  async attest(
    keyProvider: KeyProvider,
    keyId: string,
    agentDid: string,
    codeHash: string,
    includedFiles: string[],
    options: {
      version?: string;
      repositoryUrl?: string;
      commitHash?: string;
      buildId?: string;
    } = {}
  ): Promise<CodeAttestation> {
    const body = {
      agentDid,
      codeHash,
      attestedAt: new Date().toISOString(),
      version: options.version,
      repositoryUrl: options.repositoryUrl,
      commitHash: options.commitHash,
      buildId: options.buildId,
      includedFiles,
    };

    const dataToSign = canonicalize(body as unknown as Record<string, unknown>);
    const sig = await keyProvider.sign(keyId, dataToSign);

    const attestation: CodeAttestation = {
      ...body,
      signature: toBase64Url(sig),
    };

    this.attestations.set(agentDid, attestation);

    await this.auditLog?.log({
      eventType: 'vc_issued',
      actorDid: agentDid,
      result: 'success',
      metadata: {
        type: 'code_attestation',
        codeHash,
        version: options.version,
        commitHash: options.commitHash,
      },
    });

    return attestation;
  }

  /**
   * Verify a code attestation signature.
   */
  async verify(attestation: CodeAttestation): Promise<AttestationVerifyResult> {
    try {
      const publicKey = didToPublicKey(attestation.agentDid);
      const { signature, ...body } = attestation;
      const dataToVerify = canonicalize(body as unknown as Record<string, unknown>);
      const sig = fromBase64Url(signature);
      const valid = await verify(sig, dataToVerify, publicKey);

      if (valid) {
        return {
          valid: true,
          codeHash: attestation.codeHash,
          attestedAt: attestation.attestedAt,
        };
      }
      return { valid: false, error: 'Invalid attestation signature' };
    } catch (e) {
      return { valid: false, error: `Verification failed: ${(e as Error).message}` };
    }
  }

  /**
   * Verify that an agent is running a specific code hash.
   */
  async verifyCodeHash(
    agentDid: string,
    expectedHash: string
  ): Promise<{ match: boolean; attestation?: CodeAttestation; error?: string }> {
    const attestation = this.attestations.get(agentDid);
    if (!attestation) {
      return { match: false, error: 'No attestation found for this DID' };
    }

    // First verify the signature
    const sigResult = await this.verify(attestation);
    if (!sigResult.valid) {
      return { match: false, error: sigResult.error };
    }

    // Then compare hashes
    if (attestation.codeHash !== expectedHash) {
      return {
        match: false,
        attestation,
        error: `Code hash mismatch: expected ${expectedHash}, got ${attestation.codeHash}`,
      };
    }

    return { match: true, attestation };
  }

  /**
   * Get the current attestation for an agent.
   */
  getAttestation(agentDid: string): CodeAttestation | undefined {
    return this.attestations.get(agentDid);
  }

  /**
   * Get all attestations.
   */
  getAllAttestations(): CodeAttestation[] {
    return Array.from(this.attestations.values());
  }
}

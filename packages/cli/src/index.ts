#!/usr/bin/env node

/**
 * sentinel — CLI for the Agent Trust Layer
 *
 * Commands:
 *   sentinel init                    Generate agent identity (DID + keypair)
 *   sentinel whoami                  Show current agent identity
 *   sentinel sign <message>          Sign a message
 *   sentinel verify <msg> <sig> <did> Verify a signature
 *   sentinel trust-verify <package>   Verify an MCP server (npm/local/GitHub)
 *   sentinel scan <path>             Scan an MCP server package for security issues
 *   sentinel certify <path>          Scan + issue a Sentinel Trust Certificate
 *   sentinel check-cert <path>       Verify a Sentinel Trust Certificate
 *   sentinel issue-vc                Issue a Verifiable Credential
 *   sentinel verify-vc <path>        Verify a Verifiable Credential
 *   sentinel create-intent           Create a signed Intent Envelope
 *   sentinel backup-key              Split key into Shamir shares
 *   sentinel recover-key             Reconstruct key from shares
 *   sentinel revoke --did <did>      Emergency revocation
 *   sentinel audit verify            Verify audit log integrity
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

import {
  InMemoryKeyProvider,
  createIdentity,
  publicKeyToDid,
  didToPublicKey,
  resolveDid,
  issueVC,
  verifyVC,
  createIntent,
  validateIntent,
  sign,
  verify,
  toHex,
  fromHex,
  toBase64Url,
  fromBase64Url,
  textToBytes,
  bytesToText,
  createPassport,
  type CredentialType,
  type SensitivityLevel,
} from '@sentinel-atl/core';
import { AuditLog } from '@sentinel-atl/audit';
import { splitSecret, reconstructSecret, type Share } from '@sentinel-atl/recovery';
import { scan, issueSTC, verifySTC, resolvePackage, cleanupPackage, probeTools, type ScanReport, type SentinelTrustCertificate } from '@sentinel-atl/scanner';
import { hashDirectory } from '@sentinel-atl/attestation';

// ─── State Management ────────────────────────────────────────────────

const SENTINEL_DIR = join(homedir(), '.sentinel');
const KEYS_FILE = join(SENTINEL_DIR, 'keys.json');
const IDENTITY_FILE = join(SENTINEL_DIR, 'identity.json');
const AUDIT_LOG_PATH = join(SENTINEL_DIR, 'audit.jsonl');

interface StoredIdentity {
  did: string;
  keyId: string;
  publicKeyHex: string;
  privateKeyHex: string; // In v0, stored encrypted in production
  createdAt: string;
}

async function ensureDir(): Promise<void> {
  if (!existsSync(SENTINEL_DIR)) {
    await mkdir(SENTINEL_DIR, { recursive: true });
  }
}

async function loadIdentity(): Promise<StoredIdentity | null> {
  if (!existsSync(IDENTITY_FILE)) return null;
  const data = await readFile(IDENTITY_FILE, 'utf-8');
  return JSON.parse(data);
}

async function saveIdentity(identity: StoredIdentity): Promise<void> {
  await ensureDir();
  await writeFile(IDENTITY_FILE, JSON.stringify(identity, null, 2), 'utf-8');
}

function createKeyProviderFromStored(identity: StoredIdentity): InMemoryKeyProvider {
  const kp = new InMemoryKeyProvider();
  // Manually inject the loaded key
  const privateKey = fromHex(identity.privateKeyHex);
  const publicKey = fromHex(identity.publicKeyHex);
  // Use internal method to set key (workaround for InMemoryKeyProvider)
  (kp as any).keys = new Map([[identity.keyId, { publicKey, privateKey }]]);
  return kp;
}

// ─── CLI Definition ──────────────────────────────────────────────────

const program = new Command();

program
  .name('sentinel')
  .description(
    chalk.bold('🛡️  Sentinel — The Agent Trust Layer\n') +
    '   Identity, credentials, and reputation for AI agents.\n' +
    '   The trust protocol that A2A and MCP are missing.'
  )
  .version('0.1.0');

// ─── sentinel init ───────────────────────────────────────────────────

program
  .command('init')
  .description('Generate a new agent identity (Ed25519 keypair + DID)')
  .option('--name <name>', 'Agent name', 'my-agent')
  .action(async (opts) => {
    const existing = await loadIdentity();
    if (existing) {
      console.log(chalk.yellow('⚠ Identity already exists:'), existing.did);
      console.log(chalk.gray('  Use --force to regenerate (this will invalidate all VCs)'));
      return;
    }

    const kp = new InMemoryKeyProvider();
    const identity = await createIdentity(kp, opts.name);
    const privateKey = await kp.exportPrivateKey!(identity.keyId);

    const stored: StoredIdentity = {
      did: identity.did,
      keyId: identity.keyId,
      publicKeyHex: toHex(identity.publicKey),
      privateKeyHex: toHex(privateKey),
      createdAt: identity.createdAt,
    };

    await saveIdentity(stored);

    // Log to audit
    const auditLog = new AuditLog({ logPath: AUDIT_LOG_PATH });
    await auditLog.log({
      eventType: 'identity_created',
      actorDid: identity.did,
      result: 'success',
      metadata: { keyId: identity.keyId },
    });

    console.log(chalk.green('✓ Agent identity created'));
    console.log();
    console.log(chalk.bold('  DID:'), identity.did);
    console.log(chalk.bold('  Key ID:'), identity.keyId);
    console.log(chalk.bold('  Created:'), identity.createdAt);
    console.log(chalk.bold('  Stored:'), IDENTITY_FILE);
    console.log();
    console.log(chalk.gray('  Next: sentinel issue-vc --help'));
  });

// ─── sentinel whoami ─────────────────────────────────────────────────

program
  .command('whoami')
  .description('Show current agent identity')
  .action(async () => {
    const identity = await loadIdentity();
    if (!identity) {
      console.log(chalk.red('✗ No identity found. Run: sentinel init'));
      return;
    }

    const didDoc = resolveDid(identity.did);
    console.log(chalk.bold('🛡️  Agent Identity'));
    console.log();
    console.log(chalk.bold('  DID:'), identity.did);
    console.log(chalk.bold('  Key ID:'), identity.keyId);
    console.log(chalk.bold('  Created:'), identity.createdAt);
    console.log();
    console.log(chalk.bold('  DID Document:'));
    console.log(chalk.gray(JSON.stringify(didDoc, null, 4)));
  });

// ─── sentinel sign ───────────────────────────────────────────────────

program
  .command('sign <message>')
  .description('Sign a message with your agent private key')
  .action(async (message: string) => {
    const identity = await loadIdentity();
    if (!identity) {
      console.log(chalk.red('✗ No identity found. Run: sentinel init'));
      return;
    }

    const kp = createKeyProviderFromStored(identity);
    const msgBytes = textToBytes(message);
    const sig = await kp.sign(identity.keyId, msgBytes);

    console.log(chalk.green('✓ Message signed'));
    console.log();
    console.log(chalk.bold('  Signer:'), identity.did);
    console.log(chalk.bold('  Signature:'), toBase64Url(sig));
  });

// ─── sentinel verify ─────────────────────────────────────────────────

program
  .command('verify <message> <signature> <did>')
  .description('Verify an Ed25519 signature against a DID')
  .action(async (message: string, signature: string, did: string) => {
    const msgBytes = textToBytes(message);
    const sigBytes = fromBase64Url(signature);
    const publicKey = didToPublicKey(did);

    const valid = await verify(sigBytes, msgBytes, publicKey);

    if (valid) {
      console.log(chalk.green('✓ Signature is valid'));
    } else {
      console.log(chalk.red('✗ Signature is INVALID'));
      process.exitCode = 1;
    }
  });

// ─── sentinel issue-vc ───────────────────────────────────────────────

program
  .command('issue-vc')
  .description('Issue a Verifiable Credential')
  .requiredOption('--type <type>', 'Credential type (AgentAuthorization, Delegation, Reputation, NegativeReputation, Compliance, CodeAttestation)')
  .requiredOption('--subject <did>', 'Subject agent DID')
  .option('--scope <scopes>', 'Comma-separated scopes', '')
  .option('--max-delegation-depth <n>', 'Max delegation depth', '2')
  .option('--sensitivity <level>', 'Sensitivity level (low, medium, high, critical)', 'low')
  .option('--expires <hours>', 'Expiry in hours', '24')
  .option('--out <path>', 'Output file path')
  .action(async (opts) => {
    const identity = await loadIdentity();
    if (!identity) {
      console.log(chalk.red('✗ No identity found. Run: sentinel init'));
      return;
    }

    const kp = createKeyProviderFromStored(identity);
    const typeMap: Record<string, CredentialType> = {
      'AgentAuthorization': 'AgentAuthorizationCredential',
      'Delegation': 'DelegationCredential',
      'Reputation': 'ReputationCredential',
      'NegativeReputation': 'NegativeReputationCredential',
      'Compliance': 'ComplianceCredential',
      'CodeAttestation': 'CodeAttestationCredential',
    };

    const credType = typeMap[opts.type];
    if (!credType) {
      console.log(chalk.red(`✗ Unknown type: ${opts.type}`));
      console.log(chalk.gray('  Valid: ' + Object.keys(typeMap).join(', ')));
      return;
    }

    const vc = await issueVC(kp, {
      type: credType,
      issuerDid: identity.did,
      issuerKeyId: identity.keyId,
      subjectDid: opts.subject,
      scope: opts.scope ? opts.scope.split(',').map((s: string) => s.trim()) : undefined,
      maxDelegationDepth: parseInt(opts.maxDelegationDepth),
      sensitivityLevel: opts.sensitivity as SensitivityLevel,
      expiresInMs: parseFloat(opts.expires) * 3600_000,
    });

    const vcJson = JSON.stringify(vc, null, 2);

    if (opts.out) {
      await writeFile(opts.out, vcJson, 'utf-8');
      console.log(chalk.green('✓ VC written to'), opts.out);
    } else {
      console.log(chalk.green('✓ Verifiable Credential issued'));
      console.log();
      console.log(vcJson);
    }

    // Audit
    const auditLog = new AuditLog({ logPath: AUDIT_LOG_PATH });
    await auditLog.log({
      eventType: 'vc_issued',
      actorDid: identity.did,
      targetDid: opts.subject,
      result: 'success',
      metadata: { type: credType, scope: opts.scope },
    });
  });

// ─── sentinel verify-vc ──────────────────────────────────────────────

program
  .command('verify-vc <path>')
  .description('Verify a Verifiable Credential from a JSON file')
  .action(async (path: string) => {
    const data = await readFile(path, 'utf-8');
    const vc = JSON.parse(data);
    const result = await verifyVC(vc);

    if (result.valid) {
      console.log(chalk.green('✓ Credential is valid'));
      console.log(chalk.bold('  Issuer:'), vc.issuer);
      console.log(chalk.bold('  Subject:'), vc.credentialSubject.id);
      console.log(chalk.bold('  Type:'), vc.type[1]);
      console.log(chalk.bold('  Expires:'), vc.expirationDate);
      if (vc.credentialSubject.scope) {
        console.log(chalk.bold('  Scope:'), vc.credentialSubject.scope.join(', '));
      }
    } else {
      console.log(chalk.red('✗ Credential is INVALID'));
      console.log(chalk.red('  Reason:'), result.error);
      console.log(chalk.gray('  Checks:'), JSON.stringify(result.checks));
      process.exitCode = 1;
    }
  });

// ─── sentinel create-intent ──────────────────────────────────────────

program
  .command('create-intent')
  .description('Create a signed Proof of Intent envelope')
  .requiredOption('--action <action>', 'Action name (e.g., book_flight)')
  .requiredOption('--scope <scopes>', 'Comma-separated scopes')
  .requiredOption('--principal <did>', 'Principal (human) DID')
  .option('--expires <minutes>', 'Expiry in minutes', '5')
  .option('--out <path>', 'Output file path')
  .action(async (opts) => {
    const identity = await loadIdentity();
    if (!identity) {
      console.log(chalk.red('✗ No identity found. Run: sentinel init'));
      return;
    }

    const kp = createKeyProviderFromStored(identity);
    const intent = await createIntent(kp, {
      action: opts.action,
      scope: opts.scope.split(',').map((s: string) => s.trim()),
      principalDid: opts.principal,
      agentDid: identity.did,
      agentKeyId: identity.keyId,
      delegationChain: [],
      expiresInMs: parseFloat(opts.expires) * 60_000,
    });

    const json = JSON.stringify(intent, null, 2);

    if (opts.out) {
      await writeFile(opts.out, json, 'utf-8');
      console.log(chalk.green('✓ Intent envelope written to'), opts.out);
    } else {
      console.log(chalk.green('✓ Intent Envelope created'));
      console.log();
      console.log(json);
    }

    // Audit
    const auditLog = new AuditLog({ logPath: AUDIT_LOG_PATH });
    await auditLog.log({
      eventType: 'intent_created',
      actorDid: identity.did,
      result: 'success',
      metadata: { action: opts.action, scope: opts.scope },
    });
  });

// ─── sentinel backup-key ─────────────────────────────────────────────

program
  .command('backup-key')
  .description('Split your private key into Shamir shares (3-of-5)')
  .option('--shares <n>', 'Total shares', '5')
  .option('--threshold <n>', 'Shares needed to reconstruct', '3')
  .option('--out-dir <dir>', 'Directory to write share files')
  .action(async (opts) => {
    const identity = await loadIdentity();
    if (!identity) {
      console.log(chalk.red('✗ No identity found. Run: sentinel init'));
      return;
    }

    const privateKey = fromHex(identity.privateKeyHex);
    const shares = splitSecret(
      privateKey,
      parseInt(opts.shares),
      parseInt(opts.threshold)
    );

    const outDir = opts.outDir ?? join(SENTINEL_DIR, 'shares');
    await mkdir(outDir, { recursive: true });

    for (const share of shares) {
      const filename = `share-${share.index}-of-${share.totalShares}.json`;
      await writeFile(
        join(outDir, filename),
        JSON.stringify(share, null, 2),
        'utf-8'
      );
    }

    // Audit
    const auditLog = new AuditLog({ logPath: AUDIT_LOG_PATH });
    await auditLog.log({
      eventType: 'key_backup_created',
      actorDid: identity.did,
      result: 'success',
      metadata: { totalShares: shares.length, threshold: opts.threshold },
    });

    console.log(chalk.green(`✓ Key split into ${shares.length} shares (${opts.threshold} required)`));
    console.log(chalk.bold('  Shares written to:'), outDir);
    console.log();
    console.log(chalk.yellow('⚠ Distribute these shares to different trusted parties.'));
    console.log(chalk.yellow('  Anyone with ' + opts.threshold + ' shares can reconstruct your key.'));
  });

// ─── sentinel verify (the marquee command) ───────────────────────────

program
  .command('trust-verify <package>')
  .description('Verify an MCP server — the "npm audit" for AI agents')
  .option('--json', 'Output raw JSON report')
  .option('--skip-deps', 'Skip dependency vulnerability scanning')
  .option('--skip-probe', 'Skip runtime tool probing')
  .option('--probe-cmd <cmd>', 'Command to start the MCP server for probing')
  .option('--certify', 'Also issue a signed Sentinel Trust Certificate')
  .option('--out <path>', 'Output file path for certificate')
  .action(async (packageSpec: string, opts: {
    json?: boolean; skipDeps?: boolean; skipProbe?: boolean;
    probeCmd?: string; certify?: boolean; out?: string;
  }) => {
    console.log(chalk.bold('🛡️  Sentinel Trust Verification\n'));

    // Step 1: Resolve package
    console.log(chalk.gray(`  Resolving ${packageSpec}...`));
    let resolved;
    try {
      resolved = await resolvePackage(packageSpec);
    } catch (err) {
      console.log(chalk.red(`✗ Could not resolve package: ${(err as Error).message}`));
      process.exitCode = 1;
      return;
    }
    console.log(chalk.gray(`  ✓ Resolved: ${resolved.name}@${resolved.version} (${resolved.source})`));

    try {
      // Step 2: Static analysis
      console.log(chalk.gray('  Running static analysis...'));
      const report = await scan({
        packagePath: resolved.path,
        skipDependencies: opts.skipDeps,
      });

      // Step 3: Tool probing (optional)
      let probeResult = undefined;
      if (!opts.skipProbe && opts.probeCmd) {
        console.log(chalk.gray('  Probing MCP server tools...'));
        const parts = opts.probeCmd.split(' ');
        probeResult = await probeTools({
          command: parts[0],
          args: parts.slice(1),
          cwd: resolved.path,
          timeoutMs: 15_000,
        });

        if (probeResult.success) {
          console.log(chalk.gray(`  ✓ Found ${probeResult.tools.length} tools (${probeResult.serverName ?? 'unknown'})`));
          // Merge probe findings into the report
          report.findings.push(...probeResult.findings);
        } else {
          console.log(chalk.yellow(`  ⚠ Probe failed: ${probeResult.error}`));
        }
      }

      // Step 4: Output
      if (opts.json) {
        const output: Record<string, unknown> = { ...report };
        if (probeResult?.success) {
          output.tools = probeResult.tools;
          output.serverName = probeResult.serverName;
          output.serverVersion = probeResult.serverVersion;
        }
        console.log(JSON.stringify(output, null, 2));
      } else {
        console.log();
        printScanReport(report);

        if (probeResult?.success && probeResult.tools.length > 0) {
          console.log(chalk.bold('\n  MCP Tools Discovered:'));
          for (const tool of probeResult.tools.slice(0, 20)) {
            const desc = tool.description ? chalk.gray(` — ${tool.description.slice(0, 60)}`) : '';
            console.log(`    ${chalk.cyan(tool.name)}${desc}`);
          }
          if (probeResult.tools.length > 20) {
            console.log(chalk.gray(`    ... and ${probeResult.tools.length - 20} more`));
          }
        }
      }

      // Step 5: Certify (optional)
      if (opts.certify) {
        const identity = await loadIdentity();
        if (!identity) {
          console.log(chalk.yellow('\n⚠ Cannot certify — no identity. Run: sentinel init'));
        } else {
          const { codeHash } = await hashDirectory(resolved.path, {
            extensions: ['.ts', '.js', '.mjs', '.cjs'],
            exclude: ['node_modules', 'dist', '.git'],
          });

          const kp = createKeyProviderFromStored(identity);
          const stc = await issueSTC(kp, {
            scanReport: report,
            codeHash,
            issuerDid: identity.did,
            issuerKeyId: identity.keyId,
            issuerName: 'sentinel-cli',
          });

          const stcJson = JSON.stringify(stc, null, 2);
          if (opts.out) {
            await writeFile(opts.out, stcJson, 'utf-8');
            console.log(chalk.green(`\n✓ Certificate written to ${opts.out}`));
          } else {
            console.log(chalk.bold.green('\n✓ Sentinel Trust Certificate'));
            console.log(chalk.bold('  ID:'), stc.id);
            console.log(chalk.bold('  Score:'), `${stc.trustScore.overall}/100 (${stc.trustScore.grade})`);
          }
        }
      }

      // Audit
      const auditLog = new AuditLog({ logPath: AUDIT_LOG_PATH });
      await auditLog.log({
        eventType: 'vc_issued',
        actorDid: 'cli',
        result: 'success',
        metadata: {
          type: 'trust-verify',
          package: report.packageName,
          version: report.packageVersion,
          source: resolved.source,
          score: report.trustScore.overall,
          grade: report.trustScore.grade,
        },
      });
    } finally {
      // Clean up temporary downloads
      await cleanupPackage(resolved);
    }
  });

// ─── sentinel scan ───────────────────────────────────────────────────

program
  .command('scan <path>')
  .description('Scan an MCP server package for security issues')
  .option('--json', 'Output raw JSON report')
  .option('--skip-deps', 'Skip dependency vulnerability scanning')
  .action(async (packagePath: string, opts: { json?: boolean; skipDeps?: boolean }) => {
    const resolvedPath = join(process.cwd(), packagePath);
    console.log(chalk.gray(`Scanning ${resolvedPath}...`));
    console.log();

    const report = await scan({
      packagePath: resolvedPath,
      skipDependencies: opts.skipDeps,
    });

    if (opts.json) {
      console.log(JSON.stringify(report, null, 2));
      return;
    }

    printScanReport(report);

    // Audit
    const auditLog = new AuditLog({ logPath: AUDIT_LOG_PATH });
    await auditLog.log({
      eventType: 'vc_issued',
      actorDid: 'cli',
      result: 'success',
      metadata: {
        type: 'scan',
        package: report.packageName,
        score: report.trustScore.overall,
        grade: report.trustScore.grade,
      },
    });
  });

// ─── sentinel certify ────────────────────────────────────────────────

program
  .command('certify <path>')
  .description('Scan a package and issue a signed Sentinel Trust Certificate (STC)')
  .option('--out <path>', 'Output file path for the certificate')
  .option('--validity <hours>', 'Certificate validity in hours', '720')
  .option('--skip-deps', 'Skip dependency vulnerability scanning')
  .action(async (packagePath: string, opts: { out?: string; validity?: string; skipDeps?: boolean }) => {
    const identity = await loadIdentity();
    if (!identity) {
      console.log(chalk.red('✗ No identity found. Run: sentinel init'));
      return;
    }

    const resolvedPath = join(process.cwd(), packagePath);
    console.log(chalk.gray(`Scanning ${resolvedPath}...`));

    // Run scan
    const report = await scan({
      packagePath: resolvedPath,
      skipDependencies: opts.skipDeps,
    });

    // Compute code hash
    const { codeHash } = await hashDirectory(resolvedPath, {
      extensions: ['.ts', '.js', '.mjs', '.cjs'],
      exclude: ['node_modules', 'dist', '.git'],
    });

    // Issue STC
    const kp = createKeyProviderFromStored(identity);
    const stc = await issueSTC(kp, {
      scanReport: report,
      codeHash,
      issuerDid: identity.did,
      issuerKeyId: identity.keyId,
      issuerName: 'sentinel-cli',
      validityHours: parseInt(opts.validity ?? '720'),
    });

    const stcJson = JSON.stringify(stc, null, 2);

    if (opts.out) {
      await writeFile(opts.out, stcJson, 'utf-8');
      console.log(chalk.green('✓ Sentinel Trust Certificate written to'), opts.out);
    } else {
      console.log();
      printScanReport(report);
      console.log(chalk.bold.green('\n✓ Sentinel Trust Certificate issued'));
      console.log(chalk.bold('  ID:'), stc.id);
      console.log(chalk.bold('  Issuer:'), stc.issuer.did);
      console.log(chalk.bold('  Score:'), `${stc.trustScore.overall}/100 (${stc.trustScore.grade})`);
      console.log(chalk.bold('  Expires:'), stc.expiresAt);
      console.log();
      console.log(stcJson);
    }

    // Audit
    const auditLog = new AuditLog({ logPath: AUDIT_LOG_PATH });
    await auditLog.log({
      eventType: 'vc_issued',
      actorDid: identity.did,
      result: 'success',
      metadata: {
        type: 'stc',
        package: report.packageName,
        stcId: stc.id,
        score: report.trustScore.overall,
      },
    });
  });

// ─── sentinel check-cert ─────────────────────────────────────────────

program
  .command('check-cert <path>')
  .description('Verify a Sentinel Trust Certificate (STC) from a JSON file')
  .action(async (path: string) => {
    const data = await readFile(path, 'utf-8');
    const stc: SentinelTrustCertificate = JSON.parse(data);
    const result = await verifySTC(stc);

    if (result.valid) {
      console.log(chalk.green('✓ Certificate is valid'));
      console.log(chalk.bold('  ID:'), stc.id);
      console.log(chalk.bold('  Package:'), `${stc.subject.packageName}@${stc.subject.packageVersion}`);
      console.log(chalk.bold('  Score:'), `${stc.trustScore.overall}/100 (${stc.trustScore.grade})`);
      console.log(chalk.bold('  Issuer:'), stc.issuer.did);
      console.log(chalk.bold('  Issued:'), stc.issuedAt);
      console.log(chalk.bold('  Expires:'), stc.expiresAt);
      console.log(chalk.bold('  Code Hash:'), stc.subject.codeHash);
      console.log(chalk.bold('  Findings:'),
        `${stc.findingSummary.critical} critical, ${stc.findingSummary.high} high, ${stc.findingSummary.medium} medium`
      );
    } else {
      console.log(chalk.red('✗ Certificate is INVALID'));
      console.log(chalk.red('  Reason:'), result.error);
      process.exitCode = 1;
    }
  });

// ─── Scan Report Printer ──────────────────────────────────────────────

function printScanReport(report: ScanReport): void {
  const { trustScore, findings, permissions } = report;

  // Grade with color
  const gradeColor = trustScore.grade === 'A' ? chalk.green
    : trustScore.grade === 'B' ? chalk.blue
    : trustScore.grade === 'C' ? chalk.yellow
    : chalk.red;

  console.log(chalk.bold('🛡️  Sentinel Security Scan'));
  console.log();
  console.log(chalk.bold('  Package:'), `${report.packageName}@${report.packageVersion}`);
  console.log(chalk.bold('  Trust Score:'), gradeColor(`${trustScore.overall}/100 (${trustScore.grade})`));
  console.log();
  console.log(chalk.bold('  Score Breakdown:'));
  console.log(`    Dependencies:  ${colorScore(trustScore.breakdown.dependencies)}/100`);
  console.log(`    Code Patterns: ${colorScore(trustScore.breakdown.codePatterns)}/100`);
  console.log(`    Permissions:   ${colorScore(trustScore.breakdown.permissions)}/100`);
  console.log(`    Publisher:     ${colorScore(trustScore.breakdown.publisher)}/100`);

  if (permissions.kinds.length > 0) {
    console.log();
    console.log(chalk.bold('  Permissions:'), permissions.kinds.join(', '));
  }

  if (findings.length > 0) {
    console.log();
    console.log(chalk.bold(`  Findings (${findings.length}):`));
    const critical = findings.filter(f => f.severity === 'critical');
    const high = findings.filter(f => f.severity === 'high');
    const medium = findings.filter(f => f.severity === 'medium');
    const low = findings.filter(f => f.severity === 'low' || f.severity === 'info');

    if (critical.length) {
      console.log(chalk.red(`    🔴 ${critical.length} critical`));
      for (const f of critical.slice(0, 5)) {
        console.log(chalk.red(`       ${f.title}`));
      }
    }
    if (high.length) {
      console.log(chalk.yellow(`    🟠 ${high.length} high`));
      for (const f of high.slice(0, 5)) {
        console.log(chalk.yellow(`       ${f.title}`));
      }
    }
    if (medium.length) {
      console.log(chalk.blue(`    🟡 ${medium.length} medium`));
    }
    if (low.length) {
      console.log(chalk.gray(`    ⚪ ${low.length} low/info`));
    }
  } else {
    console.log();
    console.log(chalk.green('  ✓ No findings — clean package!'));
  }

  console.log();
  console.log(chalk.gray(`  Scanned in ${report.durationMs}ms`));
}

function colorScore(score: number): string {
  if (score >= 90) return chalk.green(String(score));
  if (score >= 75) return chalk.blue(String(score));
  if (score >= 60) return chalk.yellow(String(score));
  return chalk.red(String(score));
}

// ─── sentinel audit verify ───────────────────────────────────────────

program
  .command('audit')
  .description('Audit log operations')
  .command('verify')
  .description('Verify the integrity of the audit log hash chain')
  .action(async () => {
    const auditLog = new AuditLog({ logPath: AUDIT_LOG_PATH });
    const result = await auditLog.verifyIntegrity();

    if (result.valid) {
      console.log(chalk.green(`✓ Audit log is intact (${result.totalEntries} entries)`));
    } else {
      console.log(chalk.red('✗ Audit log integrity BROKEN'));
      console.log(chalk.red('  Error:'), result.error);
      if (result.brokenAt !== undefined) {
        console.log(chalk.red('  Broken at entry:'), result.brokenAt);
      }
      process.exitCode = 1;
    }
  });

// ─── Parse & Execute ─────────────────────────────────────────────────

program.parse();

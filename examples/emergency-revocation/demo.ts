/**
 * Emergency Revocation Demo
 *
 * Demonstrates the full revocation lifecycle:
 *   1. Agent operates normally with valid credentials
 *   2. Agent detected producing harmful output
 *   3. Emergency kill switch activated by principal
 *   4. All active sessions terminated
 *   5. Key rotation by the surviving agent
 *   6. Revocation list published and verified
 *
 * Run: npx tsx examples/emergency-revocation/demo.ts
 */

import {
  InMemoryKeyProvider,
  createIdentity,
  issueVC,
} from '@sentinel-atl/core';
import { AuditLog } from '@sentinel-atl/audit';
import { RevocationManager } from '@sentinel-atl/revocation';
import { SentinelGuard } from '@sentinel-atl/mcp-plugin';
import { join } from 'node:path';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';

async function main() {
  console.log('🚨 Emergency Revocation Demo\n');
  console.log('='.repeat(50));

  const tempDir = await mkdtemp(join(tmpdir(), 'sentinel-revoke-'));
  const auditLog = new AuditLog({ logPath: join(tempDir, 'audit.jsonl') });
  const revocationMgr = new RevocationManager(auditLog);

  // ─── Setup ─────────────────────────────────────────────────────

  console.log('\n📋 Step 1: Setting up agents...\n');

  const principalKP = new InMemoryKeyProvider();
  const principal = await createIdentity(principalKP, 'human-principal');

  const agentAKP = new InMemoryKeyProvider();
  const agentA = await createIdentity(agentAKP, 'agent-a');

  const rogueKP = new InMemoryKeyProvider();
  const rogue = await createIdentity(rogueKP, 'rogue-agent');

  console.log(`  👤 Principal: ${principal.did.slice(0, 30)}...`);
  console.log(`  🤖 Agent A (good): ${agentA.did.slice(0, 30)}...`);
  console.log(`  🤖 Rogue Agent: ${rogue.did.slice(0, 30)}...`);

  // Issue credentials
  const authVC = await issueVC(principalKP, {
    type: 'AgentAuthorizationCredential',
    issuerDid: principal.did,
    issuerKeyId: principal.keyId,
    subjectDid: rogue.did,
    scope: ['data:read', 'data:write'],
    maxDelegationDepth: 0,
    expiresInMs: 24 * 3600_000,
  });

  console.log(`  ✅ AuthVC issued to Rogue Agent: scope = [data:read, data:write]`);

  // ─── Normal operation ──────────────────────────────────────────

  console.log('\n📋 Step 2: Rogue agent operates normally...\n');

  const guard = new SentinelGuard({
    auditLog,
    serverDid: agentA.did,
    requiredCredentials: ['AgentAuthorizationCredential'],
    revocationManager: revocationMgr,
  });

  const check1 = await guard.verifyToolCall({
    toolName: 'read_data',
    callerDid: rogue.did,
    credentials: [authVC],
  });
  console.log(`  ✅ Tool call "read_data": ${check1.allowed ? 'ALLOWED' : 'DENIED'}`);
  console.log(`     Trust status: ${revocationMgr.isTrusted(rogue.did).trusted ? 'TRUSTED' : 'REVOKED'}`);

  // ─── Detect harmful behavior ──────────────────────────────────

  console.log('\n📋 Step 3: Rogue agent detected leaking sensitive data!\n');
  console.log('  ⚠️  Anomaly detected: Rogue agent accessed 10,000 records in 5 seconds');
  console.log('  ⚠️  Content analysis: PII detected in outbound payload');

  // ─── Revoke the credential ────────────────────────────────────

  console.log('\n📋 Step 4: Revoking credential...\n');

  await revocationMgr.revokeVC(
    principalKP, principal.keyId, principal.did,
    authVC.id, 'policy_violation', 'Unauthorized bulk data access and PII leak'
  );
  console.log(`  🚫 VC ${authVC.id.slice(0, 30)}... REVOKED`);
  console.log(`     Reason: policy_violation`);
  console.log(`     Revoked: ${revocationMgr.isVCRevoked(authVC.id)}`);

  // Try using revoked credential
  const check2 = await guard.verifyToolCall({
    toolName: 'read_data',
    callerDid: rogue.did,
    credentials: [authVC],
  });
  console.log(`\n  ❌ Tool call with revoked VC: ${check2.allowed ? 'ALLOWED (BUG!)' : 'DENIED'}`);
  console.log(`     Reason: ${check2.reason}`);

  // ─── Emergency kill switch ────────────────────────────────────

  console.log('\n📋 Step 5: EMERGENCY KILL SWITCH 🚨\n');

  const killEvent = await revocationMgr.killSwitch(
    principalKP, principal.keyId, principal.did,
    rogue.did,
    'Confirmed data exfiltration — immediate termination',
    { cascade: false }
  );

  console.log(`  🔴 Kill switch activated!`);
  console.log(`     Target: ${killEvent.targetDid.slice(0, 30)}...`);
  console.log(`     Reason: ${killEvent.reason}`);
  console.log(`     Timestamp: ${killEvent.timestamp}`);

  // Verify kill switch signature
  const killVerify = await revocationMgr.verifyKillSwitch(killEvent);
  console.log(`     Signature valid: ${killVerify.valid}`);

  // DID is now completely revoked
  const trustCheck = revocationMgr.isTrusted(rogue.did);
  console.log(`\n  🚫 Rogue DID trusted: ${trustCheck.trusted}`);
  console.log(`     Reason: ${trustCheck.reason}`);

  // Any tool call now fails at identity check
  const check3 = await guard.verifyToolCall({
    toolName: 'read_data',
    callerDid: rogue.did,
    credentials: [authVC],
  });
  console.log(`  ❌ Tool call after kill switch: ${check3.allowed ? 'ALLOWED (BUG!)' : 'DENIED'}`);

  // ─── Key rotation for Agent A ─────────────────────────────────

  console.log('\n📋 Step 6: Key rotation for Agent A (precautionary)...\n');

  const newAgentAKP = new InMemoryKeyProvider();
  const newAgentA = await createIdentity(newAgentAKP, 'agent-a-v2');

  const rotation = await revocationMgr.rotateKey(
    agentAKP, agentA.keyId,
    newAgentAKP, newAgentA.keyId,
    agentA.did, newAgentA.did
  );

  console.log(`  🔄 Key rotated: ${agentA.did.slice(0, 20)}... → ${newAgentA.did.slice(0, 20)}...`);

  const rotVerify = await revocationMgr.verifyKeyRotation(rotation);
  console.log(`     Rotation verified: ${rotVerify.valid}`);

  const resolvedDid = revocationMgr.resolveCurrentDid(agentA.did);
  console.log(`     Old DID resolves to: ${resolvedDid.slice(0, 30)}...`);
  console.log(`     Is new DID: ${resolvedDid === newAgentA.did}`);

  // ─── Publish revocation list ───────────────────────────────────

  console.log('\n📋 Step 7: Publishing signed revocation list...\n');

  const revList = await revocationMgr.publishRevocationList(
    principalKP, principal.keyId, principal.did
  );
  console.log(`  📋 Revocation List v${revList.version}`);
  console.log(`     Published by: ${revList.issuerDid.slice(0, 30)}...`);
  console.log(`     Entries: ${revList.entries.length}`);
  for (const e of revList.entries) {
    console.log(`       - ${e.credentialId.slice(0, 30)}... (${e.reason})`);
  }

  const listVerify = await revocationMgr.verifyRevocationList(revList);
  console.log(`     List signature valid: ${listVerify.valid}`);

  // ─── Final stats ───────────────────────────────────────────────

  console.log('\n📋 Step 8: Final audit...\n');

  const stats = revocationMgr.getStats();
  console.log(`  📊 Revocation Stats:`);
  console.log(`     Revoked VCs: ${stats.revokedVCs}`);
  console.log(`     Revoked DIDs: ${stats.revokedDIDs}`);
  console.log(`     Kill Events: ${stats.killEvents}`);
  console.log(`     Key Rotations: ${stats.rotations}`);

  const auditResult = await auditLog.verifyIntegrity();
  console.log(`\n  ${auditResult.valid ? '✅' : '❌'} Audit log integrity: ${auditResult.valid ? 'INTACT' : 'BROKEN'}`);
  console.log(`     Total entries: ${auditResult.totalEntries}`);

  console.log('\n' + '='.repeat(50));
  console.log('\n✅ Emergency revocation demo complete.');
  console.log('   From normal operation → detection → VC revocation →');
  console.log('   kill switch → key rotation → published revocation list.\n');
}

main().catch(console.error);

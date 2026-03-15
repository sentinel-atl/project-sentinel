/**
 * Two-Agent Handshake Demo
 *
 * This example demonstrates the full Sentinel trust pipeline:
 *
 *   1. Human principal creates identity + authorizes Agent A
 *   2. Agent A creates identity
 *   3. Agent B (sub-agent) creates identity
 *   4. Agent A and Agent B perform zero-trust handshake
 *   5. Agent A delegates narrowed scope to Agent B
 *   6. Agent A creates a Proof of Intent
 *   7. Agent B validates the intent
 *   8. Both agents exchange reputation vouches
 *   9. Everything is audit-logged with hash-chain integrity
 *
 * Run: npx tsx examples/two-agent-handshake/demo.ts
 */

import {
  InMemoryKeyProvider,
  createIdentity,
  issueVC,
  verifyVC,
  validateDelegationChain,
  createIntent,
  validateIntent,
  createPassport,
} from '@sentinel/core';
import {
  createHandshakeInit,
  processInitAndRespond,
  createVCExchange,
  verifyVCExchange,
  createSessionEstablished,
  HandshakeRateLimiter,
  type HandshakeConfig,
} from '@sentinel/handshake';
import { ReputationEngine } from '@sentinel/reputation';
import { AuditLog } from '@sentinel/audit';
import { RevocationManager } from '@sentinel/revocation';
import { AttestationManager, hashCode } from '@sentinel/attestation';
import { StepUpManager } from '@sentinel/stepup';
import { join } from 'node:path';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';

async function main() {
  console.log('🛡️  Project Sentinel — Two-Agent Handshake Demo\n');
  console.log('='.repeat(60));

  // Create a temp directory for audit logs
  const tempDir = await mkdtemp(join(tmpdir(), 'sentinel-demo-'));
  const auditLog = new AuditLog({ logPath: join(tempDir, 'audit.jsonl') });

  // ─── Step 1: Create identities ──────────────────────────────────

  console.log('\n📋 Step 1: Creating identities...\n');

  const principalKP = new InMemoryKeyProvider();
  const principal = await createIdentity(principalKP, 'human-principal');
  console.log(`  👤 Principal (Human): ${principal.did}`);

  const agentAKP = new InMemoryKeyProvider();
  const agentA = await createIdentity(agentAKP, 'travel-agent');
  console.log(`  🤖 Agent A (TravelAgent): ${agentA.did}`);

  const agentBKP = new InMemoryKeyProvider();
  const agentB = await createIdentity(agentBKP, 'payment-agent');
  console.log(`  🤖 Agent B (PayBot): ${agentB.did}`);

  await auditLog.log({
    eventType: 'identity_created', actorDid: principal.did,
    result: 'success', metadata: { role: 'principal' },
  });
  await auditLog.log({
    eventType: 'identity_created', actorDid: agentA.did,
    result: 'success', metadata: { role: 'travel-agent' },
  });
  await auditLog.log({
    eventType: 'identity_created', actorDid: agentB.did,
    result: 'success', metadata: { role: 'payment-agent' },
  });

  // ─── Step 2: Principal authorizes Agent A ────────────────────────

  console.log('\n📋 Step 2: Principal authorizes Agent A...\n');

  const authVC = await issueVC(principalKP, {
    type: 'AgentAuthorizationCredential',
    issuerDid: principal.did,
    issuerKeyId: principal.keyId,
    subjectDid: agentA.did,
    scope: ['travel:search', 'travel:book', 'payment:authorize_up_to_1000'],
    maxDelegationDepth: 2,
    sensitivityLevel: 'medium',
    expiresInMs: 24 * 3600_000,
  });

  console.log(`  ✅ VC issued: ${authVC.type[1]}`);
  console.log(`     Scope: ${authVC.credentialSubject.scope?.join(', ')}`);
  console.log(`     Max delegation depth: ${authVC.credentialSubject.maxDelegationDepth}`);
  console.log(`     Expires: ${authVC.expirationDate}`);

  // Verify the VC
  const authVerify = await verifyVC(authVC);
  console.log(`     Signature valid: ${authVerify.checks.signature}`);
  console.log(`     Not expired: ${authVerify.checks.expiry}`);

  await auditLog.log({
    eventType: 'vc_issued', actorDid: principal.did,
    targetDid: agentA.did, result: 'success',
    metadata: { type: 'AgentAuthorizationCredential' },
  });

  // ─── Step 3: Agent A creates a Compliance VC for itself ──────────

  console.log('\n📋 Step 3: Agent A creates compliance credential...\n');

  const complianceVC = await issueVC(agentAKP, {
    type: 'ComplianceCredential',
    issuerDid: agentA.did,
    issuerKeyId: agentA.keyId,
    subjectDid: agentA.did,
    scope: ['SOC2'],
    expiresInMs: 365 * 24 * 3600_000,
  });

  console.log(`  ✅ Compliance VC: SOC2`);

  // ─── Step 4: Zero-Trust Handshake ────────────────────────────────

  console.log('\n📋 Step 4: Zero-Trust Handshake (Agent A ↔ Agent B)...\n');

  const passportA = createPassport({
    did: agentA.did,
    name: 'TravelAgent',
    capabilities: ['flight_search', 'hotel_booking'],
    requiredCredentials: ['AgentAuthorizationCredential'],
    offeredCredentials: ['AgentAuthorizationCredential', 'ComplianceCredential'],
    trustRoots: [principal.did],
  });

  const passportB = createPassport({
    did: agentB.did,
    name: 'PayBot',
    capabilities: ['payment_processing'],
    requiredCredentials: ['DelegationCredential'],
    offeredCredentials: ['AgentAuthorizationCredential'],
    trustRoots: [],
  });

  const configA: HandshakeConfig = {
    selfDid: agentA.did,
    selfKeyId: agentA.keyId,
    passport: passportA,
    keyProvider: agentAKP,
    auditLog,
  };

  const configB: HandshakeConfig = {
    selfDid: agentB.did,
    selfKeyId: agentB.keyId,
    passport: passportB,
    keyProvider: agentBKP,
    auditLog,
  };

  // Step 4a: Agent A sends HandshakeInit
  const rateLimiter = new HandshakeRateLimiter();
  const rateCheck = rateLimiter.check(agentA.did);
  console.log(`  → Step 1/5: HandshakeInit (rate limit OK: ${rateCheck.allowed})`);

  const init = createHandshakeInit(configA);
  console.log(`    Protocol: v${init.protocolVersion}`);
  console.log(`    Nonce: ${init.nonce.slice(0, 16)}...`);

  await auditLog.log({
    eventType: 'handshake_init', actorDid: agentA.did,
    targetDid: agentB.did, result: 'success',
  });

  // Step 4b: Agent B responds
  const response = processInitAndRespond(init, configB);
  if (response.type === 'handshake_error') {
    console.log(`  ✗ Handshake failed: ${response.message}`);
    return;
  }
  console.log(`  ← Step 2/5: HandshakeResponse`);
  console.log(`    Requested VCs: ${response.requestedVCTypes.join(', ')}`);

  // Step 4c: Agent A sends VCs
  const exchangeA = await createVCExchange(configA, response.nonce, [authVC, complianceVC]);
  console.log(`  → Step 3/5: VC Exchange (Agent A sends ${exchangeA.credentials.length} VCs)`);

  // Step 4d: Agent B verifies and sends back
  const verifyA = await verifyVCExchange(exchangeA, response.nonce);
  console.log(`    Agent B verifies Agent A's VCs: ${verifyA.valid ? '✅' : '❌ ' + verifyA.error}`);

  // Agent B creates an auth VC for itself (from its own principal)
  const agentBAuthVC = await issueVC(agentBKP, {
    type: 'AgentAuthorizationCredential',
    issuerDid: agentB.did,
    issuerKeyId: agentB.keyId,
    subjectDid: agentB.did,
    scope: ['payment:process'],
    expiresInMs: 24 * 3600_000,
  });

  const exchangeB = await createVCExchange(configB, init.nonce, [agentBAuthVC]);
  console.log(`  ← Step 4/5: VC Exchange (Agent B sends ${exchangeB.credentials.length} VCs)`);

  const verifyB = await verifyVCExchange(exchangeB, init.nonce);
  console.log(`    Agent A verifies Agent B's VCs: ${verifyB.valid ? '✅' : '❌ ' + verifyB.error}`);

  // Step 4e: Session established
  const session = createSessionEstablished(agentA.did, agentB.did);
  console.log(`  ✅ Step 5/5: Session established`);
  console.log(`     Session ID: ${session.sessionId}`);
  console.log(`     Expires: ${session.expiresAt}`);

  await auditLog.log({
    eventType: 'handshake_complete', actorDid: agentA.did,
    targetDid: agentB.did, result: 'success',
    metadata: { sessionId: session.sessionId },
  });

  // ─── Step 5: Agent A delegates to Agent B (narrowed scope) ───────

  console.log('\n📋 Step 5: Delegation with scope narrowing...\n');

  const delegationVC = await issueVC(agentAKP, {
    type: 'DelegationCredential',
    issuerDid: agentA.did,
    issuerKeyId: agentA.keyId,
    subjectDid: agentB.did,
    scope: ['payment:authorize_up_to_1000'], // Strict subset of parent's scope
    maxDelegationDepth: 0, // PayBot CANNOT delegate further
    sensitivityLevel: 'high',
    expiresInMs: 3600_000,
  });

  console.log(`  ✅ Delegation VC issued`);
  console.log(`     Scope narrowed: [travel:search, travel:book, payment:authorize_up_to_1000] → [payment:authorize_up_to_1000]`);
  console.log(`     Max delegation depth: 0 (leaf agent — cannot delegate)`);
  console.log(`     Sensitivity: high (triggers step-up auth)`);

  // Validate delegation chain
  const chainResult = await validateDelegationChain([authVC, delegationVC]);
  console.log(`     Chain valid: ${chainResult.valid} (depth: ${chainResult.depth})`);

  // ─── Step 6: Proof of Intent ─────────────────────────────────────

  console.log('\n📋 Step 6: Creating Proof of Intent (Sentinel\'s key differentiator)...\n');

  const intent = await createIntent(agentAKP, {
    action: 'book_flight',
    scope: ['travel:book', 'payment:authorize_up_to_1000'],
    principalDid: principal.did,
    agentDid: agentA.did,
    agentKeyId: agentA.keyId,
    delegationChain: [authVC.id, delegationVC.id],
    expiresInMs: 5 * 60_000,
  });

  console.log(`  ✅ Intent Envelope created`);
  console.log(`     ID: ${intent.intentId}`);
  console.log(`     Action: ${intent.action}`);
  console.log(`     Scope: ${intent.scope.join(', ')}`);
  console.log(`     Chain: ${intent.delegationChain.length} VCs`);
  console.log(`     Nonce: ${intent.nonce.slice(0, 16)}... (replay-proof)`);
  console.log(`     Expires: ${intent.expiry}`);

  // Agent B validates the intent
  const seenNonces = new Set<string>();
  const intentResult = await validateIntent(intent, seenNonces);
  console.log(`     Agent B validates: ${intentResult.valid ? '✅' : '❌ ' + intentResult.error}`);

  // Try to replay — should fail
  const replayResult = await validateIntent(intent, seenNonces);
  console.log(`     Replay attempt: ${replayResult.valid ? '❌ Should have failed!' : '✅ Blocked (' + replayResult.error + ')'}`);

  await auditLog.log({
    eventType: 'intent_validated', actorDid: agentB.did,
    intentId: intent.intentId, result: 'success',
  });

  // ─── Step 7: Reputation Vouches ──────────────────────────────────

  console.log('\n📋 Step 7: Post-task reputation vouches...\n');

  const reputation = new ReputationEngine();

  // Agent A vouches for Agent B (positive)
  reputation.addVouch({
    voucherDid: agentA.did,
    subjectDid: agentB.did,
    polarity: 'positive',
    weight: 0.8,
    voucherVerified: true,
    timestamp: new Date().toISOString(),
  });
  console.log(`  👍 Agent A vouches for Agent B (positive, weight: 0.8)`);

  // Agent B vouches for Agent A (positive)
  reputation.addVouch({
    voucherDid: agentB.did,
    subjectDid: agentA.did,
    polarity: 'positive',
    weight: 0.7,
    voucherVerified: true,
    timestamp: new Date().toISOString(),
  });
  console.log(`  👍 Agent B vouches for Agent A (positive, weight: 0.7)`);

  // Check scores
  const scoreA = reputation.computeScore(agentA.did);
  const scoreB = reputation.computeScore(agentB.did);
  console.log(`\n  📊 Reputation Scores:`);
  console.log(`     Agent A: ${scoreA.score}/100 (${scoreA.positiveVouches}+ / ${scoreA.negativeVouches}-)`);
  console.log(`     Agent B: ${scoreB.score}/100 (${scoreB.positiveVouches}+ / ${scoreB.negativeVouches}-)`);

  // Self-vouch attempt — should be rejected
  const selfVouch = reputation.checkVouchRateLimit(agentA.did, agentA.did);
  console.log(`     Self-vouch attempt: ${selfVouch.allowed ? '❌ Should have failed!' : '✅ Blocked (' + selfVouch.reason + ')'}`);

  // Rate limit — second vouch to same peer should be blocked
  const rateVouch = reputation.checkVouchRateLimit(agentA.did, agentB.did);
  console.log(`     Repeat vouch attempt: ${rateVouch.allowed ? '❌ Should have failed!' : '✅ Blocked (' + rateVouch.reason + ')'}`);

  await auditLog.log({
    eventType: 'reputation_vouch', actorDid: agentA.did,
    targetDid: agentB.did, result: 'success',
  });

  // ─── Step 8: Verify Audit Log Integrity ──────────────────────────

  console.log('\n📋 Step 8: Audit log verification...\n');

  const auditResult = await auditLog.verifyIntegrity();
  console.log(`  ${auditResult.valid ? '✅' : '❌'} Audit log integrity: ${auditResult.valid ? 'INTACT' : 'BROKEN'}`);
  console.log(`     Total entries: ${auditResult.totalEntries}`);
  console.log(`     Log path: ${tempDir}/audit.jsonl`);

  // ─── Done ────────────────────────────────────────────────────────

  console.log('\n' + '='.repeat(60));
  console.log('\n🔒 Phase 2: Revocation, Attestation, Step-Up Auth, Kill Switch');
  console.log('='.repeat(60));

  // ─── Step 9: Code Attestation ─────────────────────────────────────

  console.log('\n📋 Step 9: Code Attestation...\n');

  const attestationMgr = new AttestationManager(auditLog);

  const agentACodeHash = hashCode('// TravelAgent v1.0 — flight search + booking');
  const agentBCodeHash = hashCode('// PayBot v1.0 — payment processing');

  const attestA = await attestationMgr.attest(
    agentAKP, agentA.keyId, agentA.did,
    agentACodeHash, ['travel-agent.ts'],
    { version: '1.0.0', commitHash: 'abc123def' }
  );
  console.log(`  ✅ Agent A attested: code hash ${attestA.codeHash.slice(0, 16)}...`);
  console.log(`     Version: ${attestA.version}, Commit: ${attestA.commitHash}`);

  const attestB = await attestationMgr.attest(
    agentBKP, agentB.keyId, agentB.did,
    agentBCodeHash, ['payment-agent.ts'],
    { version: '1.0.0' }
  );
  console.log(`  ✅ Agent B attested: code hash ${attestB.codeHash.slice(0, 16)}...`);

  // Verify attestations
  const verifyAttestA = await attestationMgr.verify(attestA);
  const verifyAttestB = await attestationMgr.verify(attestB);
  console.log(`     Agent A attestation valid: ${verifyAttestA.valid}`);
  console.log(`     Agent B attestation valid: ${verifyAttestB.valid}`);

  // Verify expected code hash
  const hashMatch = await attestationMgr.verifyCodeHash(agentA.did, agentACodeHash);
  console.log(`     Agent A running expected code: ${hashMatch.match}`);

  // ─── Step 10: Step-Up Authentication ──────────────────────────────

  console.log('\n📋 Step 10: Step-Up Authentication for sensitive payment...\n');

  const stepUpMgr = new StepUpManager({
    alwaysRequireActions: ['payment:authorize_over_500'],
    sensitivityLevels: ['high', 'critical'],
  });

  // Check if action requires step-up
  const stepUpCheck = stepUpMgr.requiresStepUp('payment:authorize_over_500');
  console.log(`  🔐 Action "payment:authorize_over_500" requires step-up: ${stepUpCheck.required}`);
  console.log(`     Trigger: ${stepUpCheck.trigger}`);

  // Create challenge for the human principal
  const challenge = stepUpMgr.createChallenge(
    agentB.did, principal.did,
    'payment:authorize_over_500',
    ['payment:authorize_up_to_1000'],
    'policy_rule',
    'Authorize payment of $750 to Tokyo Airlines for flight TK-1234'
  );
  console.log(`  📨 Challenge sent to principal: ${challenge.challengeId}`);
  console.log(`     Action: ${challenge.actionDescription}`);
  console.log(`     Expires: ${challenge.expiresAt}`);

  // Principal approves (signs the approval)
  const approval = await stepUpMgr.signApproval(
    principalKP, principal.keyId, challenge, 'approved'
  );
  console.log(`  ✍️  Principal signed approval: ${approval.decision}`);

  // Verify the approval
  const stepUpResult = await stepUpMgr.verifyApproval(approval);
  console.log(`  ${stepUpResult.approved ? '✅' : '❌'} Step-up result: ${stepUpResult.approved ? 'APPROVED — payment can proceed' : stepUpResult.error}`);

  // ─── Step 11: Revocation & Kill Switch ────────────────────────────

  console.log('\n📋 Step 11: Revocation & Kill Switch...\n');

  const revocationMgr = new RevocationManager(auditLog);

  // Revoke Agent B's delegation VC (scenario: payment completed, no longer needed)
  await revocationMgr.revokeVC(
    principalKP, principal.keyId, principal.did,
    delegationVC.id, 'manual', 'Payment completed, delegation no longer needed'
  );
  console.log(`  🚫 Delegation VC revoked: ${delegationVC.id.slice(0, 30)}...`);
  console.log(`     Is revoked: ${revocationMgr.isVCRevoked(delegationVC.id)}`);

  // Trust check
  const trustCheck = revocationMgr.isTrusted(agentB.did, delegationVC.id);
  console.log(`     Agent B with delegation VC trusted: ${trustCheck.trusted} (${trustCheck.reason})`);

  // Publish signed revocation list
  const revList = await revocationMgr.publishRevocationList(
    principalKP, principal.keyId, principal.did
  );
  console.log(`\n  📋 Published Revocation List v${revList.version}`);
  console.log(`     Entries: ${revList.entries.length}`);

  // Verify the list signature
  const listVerify = await revocationMgr.verifyRevocationList(revList);
  console.log(`     Signature valid: ${listVerify.valid}`);

  // Simulate: Agent B goes rogue → emergency kill switch
  console.log('\n  🚨 EMERGENCY: Agent B detected producing harmful output!');

  const killEvent = await revocationMgr.killSwitch(
    principalKP, principal.keyId, principal.did,
    agentB.did,
    'Producing harmful output — immediate termination',
    { cascade: false }
  );
  console.log(`  🔴 Kill switch activated by ${killEvent.activatedBy.slice(0, 20)}...`);
  console.log(`     Target: Agent B (${killEvent.targetDid.slice(0, 20)}...)`);
  console.log(`     Reason: ${killEvent.reason}`);
  console.log(`     Agent B DID now revoked: ${revocationMgr.isDIDRevoked(agentB.did)}`);

  // Verify kill switch signature
  const killVerify = await revocationMgr.verifyKillSwitch(killEvent);
  console.log(`     Kill switch signature valid: ${killVerify.valid}`);

  // Stats
  const stats = revocationMgr.getStats();
  console.log(`\n  📊 Revocation Stats: ${stats.revokedVCs} VCs, ${stats.revokedDIDs} DIDs, ${stats.killEvents} kill events`);

  // ─── Step 12: Final Audit Verification ────────────────────────────

  console.log('\n📋 Step 12: Final audit log verification...\n');

  const finalAudit = await auditLog.verifyIntegrity();
  console.log(`  ${finalAudit.valid ? '✅' : '❌'} Audit log integrity: ${finalAudit.valid ? 'INTACT' : 'BROKEN'}`);
  console.log(`     Total entries: ${finalAudit.totalEntries}`);

  // ─── Summary ──────────────────────────────────────────────────────

  console.log('\n' + '='.repeat(60));
  console.log('\n✅ Full demo complete. Trust pipeline demonstrated:');
  console.log('   Phase 1:');
  console.log('   1. Identity creation (DID + Ed25519)');
  console.log('   2. Verifiable Credential issuance + verification');
  console.log('   3. Zero-trust handshake with mutual VC exchange');
  console.log('   4. Delegation with scope narrowing');
  console.log('   5. Proof of Intent with replay protection');
  console.log('   6. Reputation vouching with rate limits + self-vouch rejection');
  console.log('   7. Tamper-evident audit log with hash-chain integrity');
  console.log('   Phase 2:');
  console.log('   8. Code attestation (bind agent DID → verified code hash)');
  console.log('   9. Step-up authentication (human approves sensitive actions)');
  console.log('   10. VC revocation + signed revocation lists');
  console.log('   11. Emergency kill switch (instant agent termination)');
  console.log();
}

main().catch(console.error);

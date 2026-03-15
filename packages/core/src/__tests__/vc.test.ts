import { describe, it, expect } from 'vitest';
import { InMemoryKeyProvider } from '../key-provider.js';
import { createIdentity } from '../did.js';
import {
  issueVC,
  verifyVC,
  validateScopeNarrowing,
  validateDelegationChain,
} from '../vc.js';

async function makeIdentity(name: string) {
  const kp = new InMemoryKeyProvider();
  const identity = await createIdentity(kp, name);
  return { kp, identity };
}

describe('issueVC / verifyVC', () => {
  it('issues a VC and verifies it successfully', async () => {
    const { kp: issuerKP, identity: issuer } = await makeIdentity('issuer');
    const { identity: subject } = await makeIdentity('subject');

    const vc = await issueVC(issuerKP, {
      type: 'AgentAuthorizationCredential',
      issuerDid: issuer.did,
      issuerKeyId: issuer.keyId,
      subjectDid: subject.did,
      scope: ['read:email', 'send:email'],
      maxDelegationDepth: 2,
      expiresInMs: 3600_000,
    });

    expect(vc['@context']).toContain('https://www.w3.org/ns/credentials/v2');
    expect(vc.type).toEqual(['VerifiableCredential', 'AgentAuthorizationCredential']);
    expect(vc.issuer).toBe(issuer.did);
    expect(vc.credentialSubject.id).toBe(subject.did);
    expect(vc.credentialSubject.scope).toEqual(['read:email', 'send:email']);
    expect(vc.credentialSubject.maxDelegationDepth).toBe(2);
    expect(vc.proof.type).toBe('Ed25519Signature2020');
    expect(vc.proof.proofPurpose).toBe('assertionMethod');

    const result = await verifyVC(vc);
    expect(result.valid).toBe(true);
    expect(result.checks.signature).toBe(true);
    expect(result.checks.expiry).toBe(true);
    expect(result.checks.issuerResolvable).toBe(true);
  });

  it('rejects a VC with a tampered subject', async () => {
    const { kp, identity: issuer } = await makeIdentity('issuer');
    const { identity: subject } = await makeIdentity('subject');

    const vc = await issueVC(kp, {
      type: 'AgentAuthorizationCredential',
      issuerDid: issuer.did,
      issuerKeyId: issuer.keyId,
      subjectDid: subject.did,
      scope: ['read:email'],
      expiresInMs: 3600_000,
    });

    // Tamper with the subject
    vc.credentialSubject.scope = ['admin:all'];

    const result = await verifyVC(vc);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Invalid signature');
  });

  it('rejects an expired VC', async () => {
    const { kp, identity: issuer } = await makeIdentity('issuer');
    const { identity: subject } = await makeIdentity('subject');

    const vc = await issueVC(kp, {
      type: 'AgentAuthorizationCredential',
      issuerDid: issuer.did,
      issuerKeyId: issuer.keyId,
      subjectDid: subject.did,
      expiresInMs: 1, // Expires immediately
    });

    // Wait for expiry + clock tolerance
    await new Promise((r) => setTimeout(r, 50));

    // Manually override the expiration to be in the past (beyond tolerance)
    vc.expirationDate = new Date(Date.now() - 60_000).toISOString();

    const result = await verifyVC(vc);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Credential has expired');
  });

  it('supports all credential types', async () => {
    const { kp, identity: issuer } = await makeIdentity('issuer');
    const { identity: subject } = await makeIdentity('subject');

    const types = [
      'AgentAuthorizationCredential',
      'DelegationCredential',
      'ComplianceCredential',
      'ReputationCredential',
      'NegativeReputationCredential',
      'CodeAttestationCredential',
    ] as const;

    for (const type of types) {
      const vc = await issueVC(kp, {
        type,
        issuerDid: issuer.did,
        issuerKeyId: issuer.keyId,
        subjectDid: subject.did,
        expiresInMs: 3600_000,
      });
      expect(vc.type[1]).toBe(type);
      const result = await verifyVC(vc);
      expect(result.valid).toBe(true);
    }
  });

  it('includes optional fields when provided', async () => {
    const { kp, identity: issuer } = await makeIdentity('issuer');
    const { identity: subject } = await makeIdentity('subject');

    const vc = await issueVC(kp, {
      type: 'NegativeReputationCredential',
      issuerDid: issuer.did,
      issuerKeyId: issuer.keyId,
      subjectDid: subject.did,
      reason: 'scope_violation',
      details: 'Accessed data outside authorized scope',
      sensitivityLevel: 'critical',
      expiresInMs: 3600_000,
    });

    expect(vc.credentialSubject.reason).toBe('scope_violation');
    expect(vc.credentialSubject.details).toBe('Accessed data outside authorized scope');
    expect(vc.credentialSubject.sensitivityLevel).toBe('critical');
  });
});

describe('validateScopeNarrowing', () => {
  it('allows a strict subset', () => {
    const result = validateScopeNarrowing(
      ['read:email', 'send:email', 'read:calendar'],
      ['read:email']
    );
    expect(result.valid).toBe(true);
  });

  it('allows an equal scope set', () => {
    const result = validateScopeNarrowing(
      ['read:email', 'send:email'],
      ['read:email', 'send:email']
    );
    expect(result.valid).toBe(true);
  });

  it('rejects scope widening', () => {
    const result = validateScopeNarrowing(
      ['read:email'],
      ['read:email', 'admin:all']
    );
    expect(result.valid).toBe(false);
    expect(result.error).toContain('admin:all');
    expect(result.error).toContain('not present in parent');
  });

  it('allows empty child scope', () => {
    const result = validateScopeNarrowing(['read:email'], []);
    expect(result.valid).toBe(true);
  });
});

describe('validateDelegationChain', () => {
  it('validates a two-VC chain', async () => {
    const { kp: principalKP, identity: principal } = await makeIdentity('principal');
    const { kp: agentKP, identity: agentA } = await makeIdentity('agent-a');
    const { identity: agentB } = await makeIdentity('agent-b');

    const authVC = await issueVC(principalKP, {
      type: 'AgentAuthorizationCredential',
      issuerDid: principal.did,
      issuerKeyId: principal.keyId,
      subjectDid: agentA.did,
      scope: ['travel:search', 'travel:book'],
      maxDelegationDepth: 2,
      expiresInMs: 3600_000,
    });

    const delegationVC = await issueVC(agentKP, {
      type: 'DelegationCredential',
      issuerDid: agentA.did,
      issuerKeyId: agentA.keyId,
      subjectDid: agentB.did,
      scope: ['travel:search'], // Narrowed
      maxDelegationDepth: 0,
      expiresInMs: 3600_000,
    });

    const result = await validateDelegationChain([authVC, delegationVC]);
    expect(result.valid).toBe(true);
    expect(result.depth).toBe(2);
  });

  it('rejects an empty chain', async () => {
    const result = await validateDelegationChain([]);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Empty');
  });

  it('rejects scope widening in a chain', async () => {
    const { kp: principalKP, identity: principal } = await makeIdentity('principal');
    const { kp: agentKP, identity: agentA } = await makeIdentity('agent-a');
    const { identity: agentB } = await makeIdentity('agent-b');

    const authVC = await issueVC(principalKP, {
      type: 'AgentAuthorizationCredential',
      issuerDid: principal.did,
      issuerKeyId: principal.keyId,
      subjectDid: agentA.did,
      scope: ['travel:search'],
      maxDelegationDepth: 2,
      expiresInMs: 3600_000,
    });

    const delegationVC = await issueVC(agentKP, {
      type: 'DelegationCredential',
      issuerDid: agentA.did,
      issuerKeyId: agentA.keyId,
      subjectDid: agentB.did,
      scope: ['travel:search', 'payment:process'], // Widened!
      maxDelegationDepth: 0,
      expiresInMs: 3600_000,
    });

    const result = await validateDelegationChain([authVC, delegationVC]);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('payment:process');
  });
});

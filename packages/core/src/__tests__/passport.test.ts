import { describe, it, expect } from 'vitest';
import { createPassport, checkPassportCompatibility } from '../passport.js';

describe('createPassport', () => {
  it('creates a passport with defaults', () => {
    const passport = createPassport({
      did: 'did:key:z6MkTest',
      name: 'TestAgent',
    });

    expect(passport['@context']).toEqual(['https://sentinel-protocol.org/v1']);
    expect(passport.did).toBe('did:key:z6MkTest');
    expect(passport.name).toBe('TestAgent');
    expect(passport.version).toBe('0.1.0');
    expect(passport.capabilities).toEqual([]);
    expect(passport.requiredCredentials).toEqual(['AgentAuthorizationCredential']);
    expect(passport.protocolVersions).toEqual(['1.0']);
    expect(passport.maxDelegationDepth).toBe(2);
  });

  it('respects custom values', () => {
    const passport = createPassport({
      did: 'did:key:z6MkCustom',
      name: 'CustomBot',
      version: '1.2.3',
      capabilities: ['payment_processing'],
      requiredCredentials: ['DelegationCredential'],
      offeredCredentials: ['ComplianceCredential'],
      trustRoots: ['did:key:z6MkRoot'],
      maxDelegationDepth: 0,
      minPeerReputation: 60,
      contentSafetyCompliant: true,
    });

    expect(passport.version).toBe('1.2.3');
    expect(passport.capabilities).toEqual(['payment_processing']);
    expect(passport.requiredCredentials).toEqual(['DelegationCredential']);
    expect(passport.offeredCredentials).toEqual(['ComplianceCredential']);
    expect(passport.trustRoots).toEqual(['did:key:z6MkRoot']);
    expect(passport.maxDelegationDepth).toBe(0);
    expect(passport.minPeerReputation).toBe(60);
    expect(passport.contentSafetyCompliant).toBe(true);
  });
});

describe('checkPassportCompatibility', () => {
  it('returns no issues for compatible passports', () => {
    const a = createPassport({
      did: 'did:key:z6MkA',
      name: 'AgentA',
      offeredCredentials: ['AgentAuthorizationCredential'],
      requiredCredentials: ['AgentAuthorizationCredential'],
    });

    const b = createPassport({
      did: 'did:key:z6MkB',
      name: 'AgentB',
      offeredCredentials: ['AgentAuthorizationCredential'],
      requiredCredentials: ['AgentAuthorizationCredential'],
    });

    const issues = checkPassportCompatibility(a, b);
    expect(issues).toEqual([]);
  });

  it('detects missing required credentials', () => {
    const a = createPassport({
      did: 'did:key:z6MkA',
      name: 'AgentA',
      offeredCredentials: [],
      requiredCredentials: ['DelegationCredential'],
    });

    const b = createPassport({
      did: 'did:key:z6MkB',
      name: 'AgentB',
      offeredCredentials: [],
      requiredCredentials: ['AgentAuthorizationCredential'],
    });

    const issues = checkPassportCompatibility(a, b);
    expect(issues.length).toBeGreaterThanOrEqual(1);
    expect(issues.some((i) => i.includes('cannot provide required credential'))).toBe(true);
  });

  it('detects protocol version mismatch', () => {
    const a = createPassport({ did: 'did:key:z6MkA', name: 'A' });
    const b = createPassport({ did: 'did:key:z6MkB', name: 'B' });
    // Override protocol versions to force mismatch
    (a as any).protocolVersions = ['2.0'];
    (b as any).protocolVersions = ['1.0'];

    const issues = checkPassportCompatibility(a, b);
    expect(issues).toContain('No common protocol version');
  });
});

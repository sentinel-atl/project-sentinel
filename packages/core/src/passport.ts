/**
 * @sentinel-atl/core — Agent Passport
 *
 * Machine-readable trust profile in JSON-LD.
 * This is what agents publish to declare: "Here's who I am, what I can do,
 * what credentials I need, and how to reach me."
 *
 * Similar to A2A's Agent Cards but with trust semantics built in.
 */

export interface AgentPassport {
  '@context': ['https://sentinel-protocol.org/v1'];
  /** Agent's DID */
  did: string;
  /** Human-readable name */
  name: string;
  /** Semantic version of the agent */
  version: string;
  /** List of capabilities this agent offers */
  capabilities: string[];
  /** Credential types required before this agent will interact */
  requiredCredentials: string[];
  /** Credential types this agent can present */
  offeredCredentials: string[];
  /** DIDs of trust roots (e.g., company root CA) */
  trustRoots: string[];
  /** Max depth this agent allows for delegation */
  maxDelegationDepth: number;
  /** SHA-256 of the agent's deployment artifact (optional in v0) */
  codeHash?: string;
  /** Supported protocol versions */
  protocolVersions: string[];
  /** Service endpoints */
  endpoints: {
    handshake?: string;
    reputation?: string;
  };
  /** Minimum reputation score required for peers (0-100) */
  minPeerReputation?: number;
  /** Whether this agent supports content safety hooks */
  contentSafetyCompliant?: boolean;
}

/**
 * Create an Agent Passport.
 */
export function createPassport(options: {
  did: string;
  name: string;
  version?: string;
  capabilities?: string[];
  requiredCredentials?: string[];
  offeredCredentials?: string[];
  trustRoots?: string[];
  maxDelegationDepth?: number;
  codeHash?: string;
  endpoints?: { handshake?: string; reputation?: string };
  minPeerReputation?: number;
  contentSafetyCompliant?: boolean;
}): AgentPassport {
  return {
    '@context': ['https://sentinel-protocol.org/v1'],
    did: options.did,
    name: options.name,
    version: options.version ?? '0.1.0',
    capabilities: options.capabilities ?? [],
    requiredCredentials: options.requiredCredentials ?? ['AgentAuthorizationCredential'],
    offeredCredentials: options.offeredCredentials ?? [],
    trustRoots: options.trustRoots ?? [],
    maxDelegationDepth: options.maxDelegationDepth ?? 2,
    codeHash: options.codeHash,
    protocolVersions: ['1.0'],
    endpoints: options.endpoints ?? {},
    minPeerReputation: options.minPeerReputation,
    contentSafetyCompliant: options.contentSafetyCompliant,
  };
}

/**
 * Check if two passports are compatible for a handshake.
 * Returns the issues (empty array = compatible).
 */
export function checkPassportCompatibility(
  initiator: AgentPassport,
  responder: AgentPassport
): string[] {
  const issues: string[] = [];

  // Check protocol version overlap
  const commonVersions = initiator.protocolVersions.filter((v) =>
    responder.protocolVersions.includes(v)
  );
  if (commonVersions.length === 0) {
    issues.push('No common protocol version');
  }

  // Check if initiator can satisfy responder's required credentials
  for (const required of responder.requiredCredentials) {
    if (!initiator.offeredCredentials.includes(required)) {
      issues.push(`Initiator cannot provide required credential: ${required}`);
    }
  }

  // Check if responder can satisfy initiator's required credentials
  for (const required of initiator.requiredCredentials) {
    if (!responder.offeredCredentials.includes(required)) {
      issues.push(`Responder cannot provide required credential: ${required}`);
    }
  }

  return issues;
}

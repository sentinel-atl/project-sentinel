/**
 * @sentinel/core — Public API
 *
 * The Agent Trust Layer. Identity, credentials, and reputation for AI agents.
 */

// Crypto primitives
export {
  generateKeyPair,
  sign,
  verify,
  hash,
  secureRandom,
  toHex,
  fromHex,
  toBase64Url,
  fromBase64Url,
  textToBytes,
  bytesToText,
  type KeyPair,
} from './crypto.js';

// Key management
export { InMemoryKeyProvider, type KeyProvider } from './key-provider.js';

// DID (Decentralized Identifiers)
export {
  publicKeyToDid,
  didToPublicKey,
  resolveDid,
  createIdentity,
  type DIDDocument,
  type AgentIdentity,
} from './did.js';

// Verifiable Credentials
export {
  issueVC,
  verifyVC,
  validateScopeNarrowing,
  validateDelegationChain,
  type VerifiableCredential,
  type CredentialType,
  type CredentialSubject,
  type CredentialProof,
  type IssueVCOptions,
  type VerifyVCResult,
  type SensitivityLevel,
  type NegativeReason,
} from './vc.js';

// Proof of Intent (Sentinel's key differentiator)
export {
  createIntent,
  validateIntent,
  isActionInScope,
  type IntentEnvelope,
  type CreateIntentOptions,
  type ValidateIntentResult,
} from './intent.js';

// Agent Passport
export {
  createPassport,
  checkPassportCompatibility,
  type AgentPassport,
} from './passport.js';

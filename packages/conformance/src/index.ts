/**
 * @sentinel/conformance — STP Conformance Test Suite
 *
 * Verifies that an STP server implementation conforms to the
 * Sentinel Trust Protocol v1.0 specification.
 *
 * Usage:
 *   # Against the reference @sentinel/server:
 *   npx vitest run packages/conformance
 *
 *   # Against an external server:
 *   STP_SERVER_URL=http://localhost:3100 npx vitest run packages/conformance
 *
 * Conformance Levels:
 *   - STP-Lite:     Discovery + Identity + Credentials + Token
 *   - STP-Standard: + Reputation + Revocation + Audit
 *   - STP-Full:     + Intent + Safety
 */

export const STP_VERSION = '1.0';

export const CONFORMANCE_LEVELS = {
  'STP-Lite': [
    'Discovery (.well-known/sentinel-configuration)',
    'Identity (POST /v1/identity, GET /v1/identity/:did)',
    'Token (POST /v1/token, STP token format)',
    'Credentials (issue, verify, revoke)',
  ],
  'STP-Standard': [
    'Reputation (GET /v1/reputation/:did, POST /v1/reputation/vouch)',
    'Revocation (status, list, kill-switch)',
    'Audit (GET /v1/audit, POST /v1/audit/verify)',
  ],
  'STP-Full': [
    'Intent (POST /v1/intents, POST /v1/intents/validate)',
    'Safety (POST /v1/safety/check)',
  ],
} as const;

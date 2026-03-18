/**
 * @sentinel-atl/trust-gateway — YAML-Configured MCP Trust Gateway
 *
 * A runtime trust enforcement proxy for MCP servers.
 * Reads a sentinel.yaml config file and enforces trust policies:
 *
 *   Client → [Trust Gateway: verify STC, check score, enforce permissions] → MCP Server
 *
 * Usage:
 *   sentinel-gateway --config sentinel.yaml
 */

export {
  loadConfig,
  validateConfig,
  type GatewayConfig,
  type ServerPolicy,
  type TrustRequirements,
} from './config.js';

export {
  TrustGateway,
  type GatewayRequest,
  type GatewayResponse,
  type TrustDecision,
} from './gateway.js';

export {
  TrustStore,
  type StoredCertificate,
  type TrustStoreOptions,
} from './trust-store.js';

export {
  TrustGatewayProxy,
  type ProxyOptions,
} from './proxy.js';

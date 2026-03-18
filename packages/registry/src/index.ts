/**
 * @sentinel-atl/registry — Trust Registry API
 *
 * Publish, query, and verify Sentinel Trust Certificates.
 * Serves SVG trust badges for READMEs and dashboards.
 *
 * Usage:
 *   sentinel-registry --port 3200
 */

export {
  CertificateStore,
  type CertificateStoreOptions,
  type RegistryEntry,
  type RegistryQuery,
  type RegistryStats,
} from './store.js';

export {
  RegistryServer,
  type RegistryServerOptions,
} from './server.js';

export {
  gradeBadge,
  scoreBadge,
  verifiedBadge,
  notFoundBadge,
  type BadgeStyle,
  type BadgeOptions,
} from './badge.js';

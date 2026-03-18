#!/usr/bin/env node

process.on('unhandledRejection', (err) => {
  console.error('Unhandled rejection:', err);
  process.exit(1);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
  process.exit(1);
});

/**
 * sentinel-gateway — CLI for running the Sentinel Trust Gateway
 *
 * Usage:
 *   sentinel-gateway --config sentinel.yaml
 *   sentinel-gateway validate sentinel.yaml
 */

import { readFile } from 'node:fs/promises';
import { loadConfig, validateConfig } from './config.js';
import { TrustGateway } from './gateway.js';
import { TrustGatewayProxy } from './proxy.js';
import { parse as parseYaml } from 'yaml';
import {
  authConfigFromEnv,
  corsConfigFromEnv,
  tlsConfigFromEnv,
} from '@sentinel-atl/hardening';
import type { AuthConfig, CorsConfig, TlsConfig } from '@sentinel-atl/hardening';

const args = process.argv.slice(2);

if (args[0] === 'validate') {
  // Validate a config file
  const configPath = args[1];
  if (!configPath) {
    console.error('Usage: sentinel-gateway validate <config.yaml>');
    process.exit(1);
  }

  try {
    const raw = await readFile(configPath, 'utf-8');
    const config = parseYaml(raw);
    const errors = validateConfig(config);

    if (errors.length === 0) {
      console.log('✓ Configuration is valid');
      console.log(`  Gateway: ${config.gateway.name}`);
      console.log(`  Mode: ${config.gateway.mode}`);
      console.log(`  Servers: ${config.servers.length}`);
      for (const server of config.servers) {
        console.log(`    - ${server.name} → ${server.upstream}`);
      }
    } else {
      console.error('✗ Configuration errors:');
      for (const err of errors) {
        console.error(`  ${err.path}: ${err.message}`);
      }
      process.exit(1);
    }
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }
} else if (args.includes('--config')) {
  const configIdx = args.indexOf('--config');
  const configPath = args[configIdx + 1];
  if (!configPath) {
    console.error('Usage: sentinel-gateway --config <sentinel.yaml>');
    process.exit(1);
  }

  try {
    const config = await loadConfig(configPath);
    console.log(`🛡️  Sentinel Trust Gateway`);
    console.log(`  Name: ${config.gateway.name}`);
    console.log(`  Mode: ${config.gateway.mode}`);
    console.log(`  Port: ${config.gateway.port}`);
    console.log(`  Servers: ${config.servers.length}`);
    for (const server of config.servers) {
      console.log(`    - ${server.name} → ${server.upstream}`);
    }

    const gateway = new TrustGateway(config);

    // Load certificates
    for (const server of config.servers) {
      if (server.certificatePath) {
        try {
          const stored = await gateway.getTrustStore().loadCertificate(server.name, server.certificatePath);
          const status = stored.verified ? '✓ verified' : '✗ invalid';
          console.log(`  [${status}] ${server.name}: score ${stored.certificate.trustScore.overall}/100`);
        } catch (err) {
          console.error(`  ✗ Failed to load certificate for ${server.name}: ${(err as Error).message}`);
        }
      }
    }

    // Start HTTP proxy with hardening config (YAML > env > defaults)
    const authConfig: AuthConfig | undefined = config.gateway.apiKeys?.length
      ? { enabled: true, keys: config.gateway.apiKeys.map(k => ({ key: k, scopes: ['read' as const, 'write' as const, 'admin' as const] })) }
      : authConfigFromEnv();

    const corsConfig: CorsConfig | undefined = config.gateway.corsOrigins?.length
      ? { allowedOrigins: config.gateway.corsOrigins }
      : corsConfigFromEnv();

    const tlsConfig: TlsConfig | undefined = (config.gateway.tlsCert && config.gateway.tlsKey)
      ? { enabled: true, certPath: config.gateway.tlsCert, keyPath: config.gateway.tlsKey }
      : tlsConfigFromEnv();

    const proxy = new TrustGatewayProxy({
      config,
      trustStore: gateway.getTrustStore(),
      auth: authConfig,
      cors: corsConfig,
      tls: tlsConfig,
    });
    const { port } = await proxy.start();

    const proto = tlsConfig ? 'https' : 'http';
    console.log(`\n  🚀 HTTP proxy listening on ${proto}://localhost:${port}`);
    console.log('  Endpoints:');
    console.log(`    GET  /sse?server=<name>   SSE stream`);
    console.log(`    POST /message?server=<name>  JSON-RPC relay`);
    console.log(`    GET  /health              Health check`);
    console.log(`    GET  /stats               Gateway stats`);
    console.log();

    // Graceful shutdown
    const shutdown = async () => {
      console.log('\n  Shutting down...');
      await proxy.stop();
      process.exit(0);
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }
} else {
  console.log('🛡️  Sentinel Trust Gateway');
  console.log();
  console.log('Usage:');
  console.log('  sentinel-gateway --config <sentinel.yaml>   Start the HTTP proxy');
  console.log('  sentinel-gateway validate <config.yaml>     Validate config');
  console.log();
  console.log('Example sentinel.yaml:');
  console.log(`
gateway:
  name: my-gateway
  port: 3100
  mode: strict
  minTrustScore: 60

servers:
  - name: filesystem
    upstream: stdio://node server.js
    trust:
      minScore: 75
      requireCertificate: true
      allowedPermissions: [filesystem]
    blockedTools: [delete_file]
  `);
}

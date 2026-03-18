#!/usr/bin/env node

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
import { parse as parseYaml } from 'yaml';

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

    console.log(`\n  Gateway ready. Trust enforcement active.\n`);

    // In a full implementation, this would start the HTTP proxy server.
    // For now, the gateway is used programmatically via TrustGateway.processRequest()
    console.log('  Note: HTTP proxy mode coming in Phase 2.5');
    console.log('  Use TrustGateway class programmatically for now.');
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }
} else {
  console.log('🛡️  Sentinel Trust Gateway');
  console.log();
  console.log('Usage:');
  console.log('  sentinel-gateway --config <sentinel.yaml>   Start the gateway');
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

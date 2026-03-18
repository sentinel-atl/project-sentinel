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
 * sentinel-registry — CLI for running the Trust Registry API server.
 *
 * Usage:
 *   sentinel-registry                    Start on default port 3200
 *   sentinel-registry --port 8080        Start on custom port
 */

import { RegistryServer } from './server.js';
import { authConfigFromEnv, corsConfigFromEnv, tlsConfigFromEnv } from '@sentinel-atl/hardening';

const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
  console.log('🗂️  Sentinel Trust Registry');
  console.log();
  console.log('Usage:');
  console.log('  sentinel-registry                    Start on port 3200');
  console.log('  sentinel-registry --port <port>      Start on custom port');
  console.log();
  console.log('Endpoints:');
  console.log('  POST   /api/v1/certificates          Register an STC');
  console.log('  GET    /api/v1/certificates/:id       Get by ID');
  console.log('  GET    /api/v1/certificates           Query certificates');
  console.log('  DELETE /api/v1/certificates/:id       Remove');
  console.log('  GET    /api/v1/packages/:name         Latest cert for package');
  console.log('  GET    /api/v1/packages/:name/badge   SVG trust badge');
  console.log('  GET    /api/v1/stats                  Registry stats');
  console.log('  GET    /health                        Health check');
  process.exit(0);
}

const portIdx = args.indexOf('--port');
const port = portIdx !== -1 ? parseInt(args[portIdx + 1]) : 3200;

const server = new RegistryServer({
  port,
  auth: authConfigFromEnv(),
  cors: corsConfigFromEnv(),
  tls: tlsConfigFromEnv(),
});

console.log('🗂️  Sentinel Trust Registry');
const { port: actualPort } = await server.start();
const proto = server.isTLS() ? 'https' : 'http';
console.log(`  Listening on ${proto}://localhost:${actualPort}`);
console.log();
console.log('  Endpoints:');
console.log('    POST   /api/v1/certificates');
console.log('    GET    /api/v1/certificates/:id');
console.log('    GET    /api/v1/packages/:name');
console.log('    GET    /api/v1/packages/:name/badge');
console.log('    GET    /api/v1/stats');
console.log('    GET    /health');
console.log();

const shutdown = async () => {
  console.log('\n  Shutting down...');
  await server.stop();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

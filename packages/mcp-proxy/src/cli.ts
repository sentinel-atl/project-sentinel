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
 * sentinel-proxy — CLI for the MCP Security Proxy
 *
 * Usage:
 *   npx sentinel-proxy --listen 3100 --upstream "stdio://node my-server.js"
 *   npx sentinel-proxy --listen 3100 --upstream "http://localhost:3000/sse"
 *   npx sentinel-proxy --listen 3100 --upstream "stdio://python mcp_server.py" --block dangerous_tool
 */

import { MCPSecurityProxy } from './index.js';

function parseArgs(argv: string[]): Record<string, string | string[]> {
  const args: Record<string, string | string[]> = {};
  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const val = argv[i + 1];
      if (val && !val.startsWith('--')) {
        if (args[key]) {
          if (Array.isArray(args[key])) {
            (args[key] as string[]).push(val);
          } else {
            args[key] = [args[key] as string, val];
          }
        } else {
          args[key] = val;
        }
        i++;
      } else {
        args[key] = 'true';
      }
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv);

  if (args['help'] === 'true' || (!args['upstream'] && !args['version'])) {
    console.log(`
  sentinel-proxy — MCP Security Proxy

  Intercepts MCP traffic, adds security checks, forwards to upstream.

  USAGE:
    sentinel-proxy --listen <port> --upstream <connection-string> [options]

  OPTIONS:
    --listen <port>        Port to listen on (default: 3100)
    --upstream <string>    Upstream MCP server
                           stdio://command args...
                           http://host:port/sse
    --block <tool>         Block a tool (can be repeated)
    --rate-limit <n>       Max requests per caller per minute (default: 100)
    --no-audit             Disable audit logging
    --safety               Enable content safety checks
    --cors <origin>        CORS origin (default: *)
    --version              Show version
    --help                 Show this help

  EXAMPLES:
    sentinel-proxy --listen 3100 --upstream "stdio://node server.js"
    sentinel-proxy --listen 3100 --upstream "http://localhost:3000/sse" --block dangerous_tool
    sentinel-proxy --listen 3100 --upstream "stdio://python mcp_server.py" --rate-limit 50
    `);
    process.exit(0);
  }

  if (args['version'] === 'true') {
    console.log('sentinel-proxy v0.1.2');
    process.exit(0);
  }

  const port = parseInt(args['listen'] as string ?? '3100', 10);
  const upstream = args['upstream'] as string;
  const blockedTools = Array.isArray(args['block']) ? args['block'] : args['block'] ? [args['block']] : [];
  const rateLimit = parseInt(args['rate-limit'] as string ?? '100', 10);
  const enableAudit = args['no-audit'] !== 'true';
  const enableSafety = args['safety'] === 'true';
  const corsOrigin = args['cors'] as string ?? '*';

  if (!upstream) {
    console.error('Error: --upstream is required');
    process.exit(1);
  }

  const proxy = new MCPSecurityProxy({
    port,
    upstream,
    blockedTools: blockedTools as string[],
    rateLimit,
    enableAudit,
    enableSafety,
    corsOrigin,
  });

  console.log(`\n  🛡️  Sentinel MCP Security Proxy`);
  console.log(`  ─────────────────────────────────`);
  console.log(`  Listening:  http://localhost:${port}`);
  console.log(`  Upstream:   ${upstream}`);
  console.log(`  Rate limit: ${rateLimit} req/min/caller`);
  if (blockedTools.length > 0) {
    console.log(`  Blocked:    ${(blockedTools as string[]).join(', ')}`);
  }
  console.log(`  Safety:     ${enableSafety ? 'ON' : 'OFF'}`);
  console.log(`  Audit:      ${enableAudit ? 'ON' : 'OFF'}`);
  console.log(`  ─────────────────────────────────`);
  console.log(`  Endpoints:`);
  console.log(`    SSE:     GET  http://localhost:${port}/sse`);
  console.log(`    Message: POST http://localhost:${port}/message`);
  console.log(`    Health:  GET  http://localhost:${port}/health`);
  console.log(`    Stats:   GET  http://localhost:${port}/stats`);
  console.log(`    Audit:   GET  http://localhost:${port}/audit`);
  console.log(`\n  Ctrl+C to stop\n`);

  await proxy.start();

  // Graceful shutdown
  const shutdown = async () => {
    console.log('\n  Shutting down proxy...');
    await proxy.stop();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((err) => {
  console.error('Fatal:', err.message);
  process.exit(1);
});

/**
 * Load/stress benchmark for Sentinel STP Server.
 *
 * Measures throughput and latency under concurrent load.
 *
 * Run: npx tsx packages/server/src/benchmark.ts
 */

import { createSTPServer, type STPServer } from './index.js';
import { InMemoryKeyProvider, createIdentity, createSTPToken } from '@sentinel-atl/core';
import http from 'node:http';
import { unlinkSync, existsSync } from 'node:fs';

const PORT = 13580;
const AUDIT_FILE = `stp-server-benchmark-audit.jsonl`;
const CONCURRENCY = 50;
const TOTAL_REQUESTS = 500;

function httpGet(port: number, path: string): Promise<{ status: number; latencyMs: number }> {
  const start = performance.now();
  return new Promise((resolve, reject) => {
    http.get(`http://localhost:${port}${path}`, (res) => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode!, latencyMs: performance.now() - start }));
    }).on('error', reject);
  });
}

async function runBatch(port: number, path: string, total: number, concurrency: number) {
  const latencies: number[] = [];
  let completed = 0;
  let errors = 0;

  const worker = async () => {
    while (completed < total) {
      completed++;
      try {
        const { latencyMs } = await httpGet(port, path);
        latencies.push(latencyMs);
      } catch {
        errors++;
      }
    }
  };

  const start = performance.now();
  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  const elapsed = performance.now() - start;

  latencies.sort((a, b) => a - b);
  const p50 = latencies[Math.floor(latencies.length * 0.5)];
  const p95 = latencies[Math.floor(latencies.length * 0.95)];
  const p99 = latencies[Math.floor(latencies.length * 0.99)];
  const rps = (latencies.length / (elapsed / 1000)).toFixed(1);

  return { total: latencies.length, errors, rps, p50: p50.toFixed(1), p95: p95.toFixed(1), p99: p99.toFixed(1), elapsed: elapsed.toFixed(0) };
}

async function main() {
  if (existsSync(AUDIT_FILE)) unlinkSync(AUDIT_FILE);

  const kp = new InMemoryKeyProvider();
  const server = await createSTPServer({ name: 'benchmark', port: PORT, keyProvider: kp, securityHeaders: false });
  await server.start();

  console.log(`\n  Sentinel STP Server Benchmark`);
  console.log(`  Concurrency: ${CONCURRENCY}  |  Total: ${TOTAL_REQUESTS}\n`);

  // Health endpoint
  {
    const r = await runBatch(PORT, '/health', TOTAL_REQUESTS, CONCURRENCY);
    console.log(`  GET /health              ${r.rps} req/s  p50=${r.p50}ms  p95=${r.p95}ms  p99=${r.p99}ms  errors=${r.errors}`);
  }

  // Discovery
  {
    const r = await runBatch(PORT, '/.well-known/sentinel-configuration', TOTAL_REQUESTS, CONCURRENCY);
    console.log(`  GET /.well-known         ${r.rps} req/s  p50=${r.p50}ms  p95=${r.p95}ms  p99=${r.p99}ms  errors=${r.errors}`);
  }

  // Reputation query
  {
    const r = await runBatch(PORT, `/v1/reputation/${encodeURIComponent(server.did)}`, TOTAL_REQUESTS, CONCURRENCY);
    console.log(`  GET /v1/reputation/:did  ${r.rps} req/s  p50=${r.p50}ms  p95=${r.p95}ms  p99=${r.p99}ms  errors=${r.errors}`);
  }

  console.log();
  await server.stop();
  if (existsSync(AUDIT_FILE)) unlinkSync(AUDIT_FILE);
}

main().catch(console.error);

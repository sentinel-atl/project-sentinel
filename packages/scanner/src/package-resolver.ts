/**
 * NPM package resolver — download and extract npm packages for scanning.
 *
 * Supports:
 * - npm package names: "@modelcontextprotocol/server-filesystem"
 * - npm package@version: "@scope/name@1.2.3"
 * - Local paths: "./my-server" or "/abs/path"
 * - GitHub URLs (future): "github:user/repo"
 */

import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, isAbsolute } from 'node:path';

export interface ResolvedPackage {
  /** Absolute path to the extracted package directory */
  path: string;
  /** Package name from package.json */
  name: string;
  /** Package version from package.json */
  version: string;
  /** Source type */
  source: 'npm' | 'local';
  /** Whether we need to clean up (true for npm downloads) */
  isTemporary: boolean;
}

/**
 * Resolve a package specifier to a local directory ready for scanning.
 */
export async function resolvePackage(specifier: string): Promise<ResolvedPackage> {
  // Check if it's a local path (starts with . or / or is absolute, or exists on disk)
  const absPath = resolve(specifier);
  if (specifier.startsWith('.') || specifier.startsWith('/') || isAbsolute(specifier) || existsSync(absPath)) {
    if (!existsSync(absPath)) {
      throw new Error(`Local path not found: ${absPath}`);
    }
    const pkg = await readPackageJson(absPath);
    return {
      path: absPath,
      name: pkg.name ?? 'unknown',
      version: pkg.version ?? '0.0.0',
      source: 'local',
      isTemporary: false,
    };
  }

  // npm package
  return resolveFromNpm(specifier);
}

/**
 * Download a package from npm registry and extract it.
 */
async function resolveFromNpm(specifier: string): Promise<ResolvedPackage> {
  const tmpDir = await mkdtemp(join(tmpdir(), 'sentinel-scan-'));

  try {
    // Use `npm pack` to download the tarball, then extract
    // CRITICAL: --ignore-scripts prevents prepack/prepare lifecycle hooks from executing
    // attacker code before we even begin scanning.
    await execPromise('npm', ['pack', specifier, '--pack-destination', tmpDir, '--ignore-scripts'], { cwd: tmpDir });

    // Find the .tgz file
    const { readdir } = await import('node:fs/promises');
    const files = await readdir(tmpDir);
    const tgz = files.find(f => f.endsWith('.tgz'));
    if (!tgz) {
      throw new Error(`npm pack did not produce a tarball for: ${specifier}`);
    }

    // Extract
    await execPromise('tar', ['xzf', join(tmpDir, tgz), '-C', tmpDir]);

    // npm pack extracts to a `package/` subdirectory
    const packageDir = join(tmpDir, 'package');
    if (!existsSync(packageDir)) {
      throw new Error('Extracted package directory not found');
    }

    const pkg = await readPackageJson(packageDir);

    return {
      path: packageDir,
      name: pkg.name ?? specifier,
      version: pkg.version ?? '0.0.0',
      source: 'npm',
      isTemporary: true,
    };
  } catch (err) {
    // Clean up on failure
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    throw new Error(`Failed to resolve npm package "${specifier}": ${(err as Error).message}`);
  }
}

/**
 * Clean up a temporary package directory.
 */
export async function cleanupPackage(resolved: ResolvedPackage): Promise<void> {
  if (resolved.isTemporary) {
    // Go up one directory from 'package/' to the tmp dir
    const tmpDir = join(resolved.path, '..');
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}

async function readPackageJson(dir: string): Promise<{ name?: string; version?: string; [k: string]: unknown }> {
  try {
    const raw = await readFile(join(dir, 'package.json'), 'utf-8');
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

function execPromise(cmd: string, args: string[], options?: { cwd?: string }): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { ...options, maxBuffer: 10 * 1024 * 1024, timeout: 60_000 }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(`${cmd} ${args.join(' ')} failed: ${stderr || error.message}`));
      } else {
        resolve(stdout);
      }
    });
  });
}

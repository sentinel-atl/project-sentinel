/**
 * Dependency scanner — checks for known vulnerabilities via npm audit.
 */

import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding } from './scanner.js';

export interface VulnerablePackage {
  name: string;
  severity: 'critical' | 'high' | 'moderate' | 'low' | 'info';
  title: string;
  url?: string;
  range?: string;
  fixAvailable: boolean;
}

export interface DependencyScanResult {
  vulnerabilities: VulnerablePackage[];
  totalDependencies: number;
  findings: Finding[];
}

/**
 * Run `npm audit --json` against a package directory and parse results.
 */
export async function scanDependencies(packagePath: string): Promise<DependencyScanResult> {
  const findings: Finding[] = [];
  const vulnerabilities: VulnerablePackage[] = [];

  // Check if package-lock.json exists (npm audit requires it)
  const lockPath = join(packagePath, 'package-lock.json');
  if (!existsSync(lockPath)) {
    return { vulnerabilities: [], totalDependencies: 0, findings };
  }

  try {
    const auditOutput = await runNpmAudit(packagePath);
    const audit = JSON.parse(auditOutput);

    const totalDependencies = audit.metadata?.totalDependencies ?? 0;

    // Parse npm audit v2 format
    if (audit.vulnerabilities) {
      for (const [name, info] of Object.entries(audit.vulnerabilities) as Array<[string, any]>) {
        const vuln: VulnerablePackage = {
          name,
          severity: info.severity ?? 'info',
          title: info.via?.[0]?.title ?? info.via?.[0] ?? 'Unknown vulnerability',
          url: info.via?.[0]?.url,
          range: info.range,
          fixAvailable: !!info.fixAvailable,
        };
        vulnerabilities.push(vuln);

        const severityMap: Record<string, Finding['severity']> = {
          critical: 'critical',
          high: 'high',
          moderate: 'medium',
          low: 'low',
          info: 'info',
        };

        findings.push({
          severity: severityMap[vuln.severity] ?? 'info',
          category: 'vulnerability',
          title: `Vulnerable dependency: ${name}`,
          description: typeof vuln.title === 'string' ? vuln.title : `Vulnerability in ${name}`,
          evidence: vuln.url,
        });
      }
    }

    return { vulnerabilities, totalDependencies, findings };
  } catch {
    // npm audit failed — could be no lockfile, network issue, etc.
    return { vulnerabilities: [], totalDependencies: 0, findings };
  }
}

function runNpmAudit(cwd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile('npm', ['audit', '--json', '--omit=dev'], { cwd, maxBuffer: 10 * 1024 * 1024 }, (error, stdout) => {
      // npm audit exits with non-zero when vulnerabilities exist, but still outputs JSON
      if (stdout) {
        resolve(stdout);
      } else {
        reject(error ?? new Error('npm audit produced no output'));
      }
    });
  });
}

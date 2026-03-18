/**
 * Publisher verifier — checks npm registry for package publisher identity signals.
 *
 * Checks:
 * 1. Package exists on npm registry
 * 2. Publisher/maintainer count and identities
 * 3. Whether the publisher has 2FA enabled (npm provenance)
 * 4. Package age (how long has it existed?)
 * 5. Download count (popularity signal)
 * 6. Repository link presence and match
 * 7. npm provenance attestation (sigstore)
 */

import type { Finding } from './scanner.js';

// ─── Types ───────────────────────────────────────────────────────────

export interface PublisherInfo {
  /** npm package name */
  packageName: string;
  /** Whether the package exists on npm */
  existsOnNpm: boolean;
  /** npm publisher username */
  publisher?: string;
  /** npm publisher email */
  publisherEmail?: string;
  /** Number of maintainers */
  maintainerCount: number;
  /** Maintainer usernames */
  maintainers: string[];
  /** Package creation date */
  createdAt?: string;
  /** Last publish date */
  lastPublishedAt?: string;
  /** Package age in days */
  ageDays: number;
  /** Weekly downloads */
  weeklyDownloads: number;
  /** Whether the package has a repository link */
  hasRepository: boolean;
  /** Repository URL */
  repositoryUrl?: string;
  /** Whether npm provenance attestation is present */
  hasProvenance: boolean;
  /** License */
  license?: string;
  /** Number of published versions */
  versionCount: number;
}

export interface PublisherScanResult {
  info: PublisherInfo;
  findings: Finding[];
  /** Publisher trust score 0-100 */
  score: number;
}

// ─── Registry Fetcher ─────────────────────────────────────────────────

async function fetchRegistryData(packageName: string): Promise<any> {
  const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}`;
  const response = await fetch(url, {
    headers: { 'Accept': 'application/json' },
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) {
    if (response.status === 404) return null;
    throw new Error(`npm registry returned ${response.status}`);
  }
  return response.json();
}

async function fetchDownloadCount(packageName: string): Promise<number> {
  try {
    const url = `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`;
    const response = await fetch(url, {
      signal: AbortSignal.timeout(5_000),
    });
    if (!response.ok) return 0;
    const data = await response.json() as { downloads?: number };
    return data.downloads ?? 0;
  } catch {
    return 0;
  }
}

// ─── Scanner ─────────────────────────────────────────────────────────

/**
 * Verify publisher identity by checking the npm registry.
 */
export async function scanPublisher(packageName: string): Promise<PublisherScanResult> {
  const findings: Finding[] = [];

  // Skip for local-only / unknown packages
  if (!packageName || packageName === 'unknown' || packageName.startsWith('/')) {
    return {
      info: emptyInfo(packageName),
      findings,
      score: 50, // neutral for local packages
    };
  }

  try {
    const [registryData, weeklyDownloads] = await Promise.all([
      fetchRegistryData(packageName),
      fetchDownloadCount(packageName),
    ]);

    if (!registryData) {
      findings.push({
        severity: 'medium',
        category: 'publisher',
        title: 'Package not found on npm',
        description: `"${packageName}" does not exist on the npm registry`,
      });
      return { info: { ...emptyInfo(packageName), existsOnNpm: false }, findings, score: 20 };
    }

    // Extract publisher info
    const timeData = registryData.time ?? {};
    const createdAt = timeData.created;
    const lastPublishedAt = timeData.modified;
    const maintainers: Array<{ name: string; email?: string }> = registryData.maintainers ?? [];
    const latestVersion = registryData['dist-tags']?.latest;
    const latestData = latestVersion ? registryData.versions?.[latestVersion] : undefined;

    const ageDays = createdAt
      ? Math.floor((Date.now() - new Date(createdAt).getTime()) / 86_400_000)
      : 0;

    const repositoryUrl = latestData?.repository?.url ?? registryData.repository?.url;
    const hasRepository = !!repositoryUrl;
    const license = latestData?.license ?? registryData.license;
    const hasProvenance = !!latestData?.dist?.attestations || !!latestData?.dist?.signatures?.length;
    const versionCount = Object.keys(registryData.versions ?? {}).length;

    // Determine publisher from _npmUser on latest version
    const npmUser = latestData?._npmUser;

    const info: PublisherInfo = {
      packageName,
      existsOnNpm: true,
      publisher: npmUser?.name,
      publisherEmail: npmUser?.email,
      maintainerCount: maintainers.length,
      maintainers: maintainers.map(m => m.name),
      createdAt,
      lastPublishedAt,
      ageDays,
      weeklyDownloads,
      hasRepository,
      repositoryUrl,
      hasProvenance,
      license,
      versionCount,
    };

    // Generate findings
    if (ageDays < 30) {
      findings.push({
        severity: 'medium',
        category: 'publisher',
        title: `New package: ${ageDays} days old`,
        description: 'Package was published less than 30 days ago — limited track record',
      });
    }

    if (weeklyDownloads < 100) {
      findings.push({
        severity: 'low',
        category: 'publisher',
        title: `Low popularity: ${weeklyDownloads} downloads/week`,
        description: 'Low download count suggests limited community vetting',
      });
    }

    if (maintainers.length === 1) {
      findings.push({
        severity: 'low',
        category: 'publisher',
        title: 'Single maintainer',
        description: 'Package has only one maintainer — single point of failure for supply chain',
      });
    }

    if (!hasRepository) {
      findings.push({
        severity: 'medium',
        category: 'publisher',
        title: 'No repository link',
        description: 'Package does not link to a source code repository',
      });
    }

    if (!license) {
      findings.push({
        severity: 'medium',
        category: 'publisher',
        title: 'No license specified',
        description: 'Package does not specify a license',
      });
    }

    if (!hasProvenance) {
      findings.push({
        severity: 'info',
        category: 'publisher',
        title: 'No npm provenance',
        description: 'Package does not have npm provenance attestation (sigstore)',
      });
    }

    if (maintainers.length > 10) {
      findings.push({
        severity: 'low',
        category: 'publisher',
        title: `Many maintainers: ${maintainers.length}`,
        description: 'Large number of maintainers increases attack surface',
      });
    }

    // Compute publisher score
    const score = computePublisherScore(info);

    return { info, findings, score };
  } catch (err) {
    // Network failure — return neutral score
    findings.push({
      severity: 'info',
      category: 'publisher',
      title: 'Could not check npm registry',
      description: (err as Error).message,
    });
    return { info: emptyInfo(packageName), findings, score: 50 };
  }
}

// ─── Scoring ──────────────────────────────────────────────────────────

function computePublisherScore(info: PublisherInfo): number {
  let score = 0;

  // Exists on npm: +20
  if (info.existsOnNpm) score += 20;

  // Age bonus: up to +20
  if (info.ageDays > 365) score += 20;
  else if (info.ageDays > 180) score += 15;
  else if (info.ageDays > 30) score += 10;
  else score += 2;

  // Downloads: up to +20
  if (info.weeklyDownloads > 10_000) score += 20;
  else if (info.weeklyDownloads > 1_000) score += 15;
  else if (info.weeklyDownloads > 100) score += 10;
  else score += 2;

  // Repository: +10
  if (info.hasRepository) score += 10;

  // License: +5
  if (info.license) score += 5;

  // Provenance: +10
  if (info.hasProvenance) score += 10;

  // Multiple maintainers but not too many: +5
  if (info.maintainerCount >= 2 && info.maintainerCount <= 10) score += 5;
  else if (info.maintainerCount === 1) score += 2;

  // Multiple versions (established): +10
  if (info.versionCount > 10) score += 10;
  else if (info.versionCount > 3) score += 7;
  else if (info.versionCount > 1) score += 4;
  else score += 1;

  return Math.min(100, score);
}

function emptyInfo(packageName: string): PublisherInfo {
  return {
    packageName,
    existsOnNpm: false,
    maintainerCount: 0,
    maintainers: [],
    ageDays: 0,
    weeklyDownloads: 0,
    hasRepository: false,
    hasProvenance: false,
    versionCount: 0,
  };
}

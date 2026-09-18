/**
 * lockcheck — main scan orchestrator.
 * Coordinates parsers, analyzers, and reporter.
 */

import { parseNpmLockfile, readSnapshot } from './parsers/npm.js';
import { analyzeNewDeps } from './analyzers/new-deps.js';
import { analyzeVersionJumps } from './analyzers/version-jump.js';
import { analyzeTyposquats } from './analyzers/typosquat.js';
import { analyzeRegistries } from './analyzers/registry.js';
import { analyzeInstallScripts } from './analyzers/scripts.js';
import { analyzeFreshness } from './analyzers/freshness.js';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * Run a full lockcheck scan.
 * @param {string} dir - Directory to scan
 * @param {{ noNetwork?: boolean, strict?: boolean, ignore?: string[], onProgress?: (msg: string) => void }} options
 * @returns {Promise<{ findings: Array, stats: object, isFirstRun: boolean, exitCode: number }>}
 */
export async function scan(dir, options = {}) {
  const allFindings = [];

  // 1. Parse the lock file
  const { packages, lockfileVersion } = parseNpmLockfile(dir);

  // 2. Load previous snapshot
  const previousPackages = readSnapshot(dir);
  const isFirstRun = previousPackages === null;

  // 3. Run analyzers
  // 3a. New dependencies
  const newDeps = analyzeNewDeps(packages, previousPackages);
  allFindings.push(...newDeps.findings);

  // 3b. Version jumps
  const versionJumps = analyzeVersionJumps(packages, previousPackages);
  allFindings.push(...versionJumps.findings);

  // 3c. Typosquat detection (runs on ALL packages, not just new ones)
  const typosquats = analyzeTyposquats(packages);
  allFindings.push(...typosquats.findings);

  // 3d. Registry anomalies
  const registries = analyzeRegistries(packages, previousPackages);
  allFindings.push(...registries.findings);

  // 3e. Install scripts
  const scripts = analyzeInstallScripts(packages);
  allFindings.push(...scripts.findings);

  // 3f. Freshness check (network-dependent)
  if (!options.noNetwork && !isFirstRun) {
    if (options.onProgress) options.onProgress('Checking npm registry...');

    try {
      const freshness = await analyzeFreshness(packages, previousPackages, {
        onProgress: (name) => {
          if (options.onProgress) options.onProgress(`Checking ${name}...`);
        },
      });
      allFindings.push(...freshness.findings);
    } catch {
      // Network failure is non-fatal
      allFindings.push({
        severity: 'info',
        name: 'lockcheck',
        version: '-',
        message: 'Could not reach npm registry for freshness checks. Use --no-network to suppress.',
      });
    }
  }

  // 4. Calculate stats
  let newPackages = 0;
  let changedPackages = 0;

  if (previousPackages) {
    for (const [name, pkg] of packages) {
      const prev = previousPackages.get(name);
      if (!prev) {
        newPackages++;
      } else if (prev.version !== pkg.version) {
        changedPackages++;
      }
    }
  }

  const stats = {
    totalPackages: packages.size,
    newPackages,
    changedPackages,
    lockfileType: `package-lock.json (v${lockfileVersion})`,
    scannedAt: new Date().toISOString(),
  };

  // 5. Save snapshot for next run
  saveSnapshotSync(dir, packages);

  // 6. Apply --ignore (package names, case-sensitive match on finding.name)
  const ignore = new Set((options.ignore || []).filter(Boolean));
  const findings = ignore.size
    ? allFindings.filter(f => !ignore.has(f.name))
    : allFindings;

  // 7. Determine exit code (after ignore filter)
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const warningCount = findings.filter(f => f.severity === 'warning').length;

  let exitCode = 0;
  if (criticalCount > 0) exitCode = 1;
  if (options.strict && warningCount > 0) exitCode = 1;

  return {
    findings,
    stats,
    isFirstRun,
    exitCode,
  };
}

/**
 * Save snapshot synchronously.
 */
function saveSnapshotSync(dir, packages) {
  const snapshotPath = resolve(dir, '.lockcheck-snapshot.json');
  const data = {
    createdAt: new Date().toISOString(),
    version: '1.0.0',
    packageCount: packages.size,
    packages: Object.fromEntries(packages),
  };
  writeFileSync(snapshotPath, JSON.stringify(data, null, 2));
}

export { parseNpmLockfile } from './parsers/npm.js';
export { detectTyposquat } from './analyzers/typosquat.js';

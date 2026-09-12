/**
 * Parser for package-lock.json (lockfileVersion 2 and 3).
 * Extracts normalized package data for analysis.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * Parse a package-lock.json file and return normalized package data.
 * @param {string} dir - Directory containing package-lock.json
 * @returns {{ packages: Map<string, PackageInfo>, lockfileVersion: number, raw: object }}
 */
export function parseNpmLockfile(dir) {
  const lockfilePath = resolve(dir, 'package-lock.json');
  let raw;

  try {
    const content = readFileSync(lockfilePath, 'utf-8');
    raw = JSON.parse(content);
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error(`No package-lock.json found in ${dir}`);
    }
    // Empty or corrupted lockfiles (e.g. merge conflicts) throw SyntaxError from JSON.parse.
    // Surface a clear message so the CLI exits 2 without a raw Node stack trace.
    if (err instanceof SyntaxError) {
      throw new Error(
        'package-lock.json contains invalid JSON (possibly a merge conflict).'
      );
    }
    throw new Error(`Failed to parse package-lock.json: ${err.message}`);
  }

  const lockfileVersion = raw.lockfileVersion || 1;
  const packages = new Map();

  if (lockfileVersion >= 2 && raw.packages) {
    // lockfileVersion 2 or 3 — use the "packages" field
    for (const [path, pkg] of Object.entries(raw.packages)) {
      // Skip the root entry (empty string key)
      if (path === '') continue;

      // Extract package name from path (e.g., "node_modules/lodash" → "lodash")
      const name = extractPackageName(path);
      if (!name) continue;

      packages.set(name, {
        name,
        version: pkg.version || 'unknown',
        resolved: pkg.resolved || null,
        integrity: pkg.integrity || null,
        dev: !!pkg.dev,
        optional: !!pkg.optional,
        hasInstallScripts: !!(pkg.hasInstallScript),
        funding: pkg.funding || null,
        engines: pkg.engines || null,
        path,
      });
    }
  } else if (raw.dependencies) {
    // lockfileVersion 1 fallback — uses "dependencies" field
    flattenDepsV1(raw.dependencies, packages);
  }

  return { packages, lockfileVersion, raw };
}

/**
 * Extract the package name from a lockfile path.
 * Handles scoped packages and nested node_modules.
 * @param {string} path - e.g., "node_modules/@babel/core" or "node_modules/lodash"
 * @returns {string | null}
 */
function extractPackageName(path) {
  // Remove leading "node_modules/" and handle nested
  const match = path.match(/node_modules\/(.+)$/);
  if (!match) return null;

  const rest = match[1];

  // Handle nested node_modules: take only the last package
  const lastModules = rest.lastIndexOf('node_modules/');
  if (lastModules !== -1) {
    return rest.slice(lastModules + 'node_modules/'.length);
  }

  return rest;
}

/**
 * Flatten lockfileVersion 1 dependencies into normalized format.
 */
function flattenDepsV1(deps, packages, prefix = '') {
  for (const [name, info] of Object.entries(deps)) {
    const fullName = prefix ? `${prefix}/${name}` : name;

    packages.set(name, {
      name,
      version: info.version || 'unknown',
      resolved: info.resolved || null,
      integrity: info.integrity || null,
      dev: !!info.dev,
      optional: !!info.optional,
      hasInstallScripts: false, // v1 doesn't track this directly
      path: `node_modules/${name}`,
    });

    // Recurse into nested dependencies
    if (info.dependencies) {
      flattenDepsV1(info.dependencies, packages, name);
    }
  }
}

/**
 * Read the saved snapshot for comparison.
 * @param {string} dir
 * @returns {Map<string, PackageInfo> | null}
 */
export function readSnapshot(dir) {
  const snapshotPath = resolve(dir, '.lockcheck-snapshot.json');

  try {
    const content = readFileSync(snapshotPath, 'utf-8');
    const data = JSON.parse(content);
    return new Map(Object.entries(data.packages || {}));
  } catch {
    return null;
  }
}

/**
 * Save current lockfile state as snapshot for future comparison.
 * @param {string} dir
 * @param {Map<string, PackageInfo>} packages
 */
export function saveSnapshot(dir, packages) {
  const snapshotPath = resolve(dir, '.lockcheck-snapshot.json');

  const data = {
    createdAt: new Date().toISOString(),
    packageCount: packages.size,
    packages: Object.fromEntries(packages),
  };

  writeFileSync(snapshotPath, JSON.stringify(data, null, 2));
}

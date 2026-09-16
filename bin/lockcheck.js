#!/usr/bin/env node

// Node 18+ required (native fetch for registry checks)
{
  const major = Number.parseInt(process.versions.node.split('.')[0], 10);
  if (Number.isFinite(major) && major < 18) {
    console.error(
      `lockcheck requires Node.js 18 or newer (native fetch). Current: ${process.version}`
    );
    process.exit(1);
  }
}


/**
 * lockcheck CLI — Detect malicious dependency diffs in lock files.
 *
 * Usage:
 *   npx lockcheck              # Scan current directory
 *   npx lockcheck ./my-project # Scan a specific directory
 *   npx lockcheck --json       # Output as JSON (for CI/CD)
 *   npx lockcheck --strict     # Exit 1 on warnings too
 *   npx lockcheck --no-network # Skip npm registry checks
 *   npx lockcheck --help       # Show help
 */

import { scan } from '../src/index.js';
import { printReport, printJsonReport } from '../src/reporters/terminal.js';
import {
  bold, dim, cyan, yellow, red, green, gray,
  ICONS,
} from '../src/utils/colors.js';

// Parse CLI arguments (no dependency needed)
const args = process.argv.slice(2);
const flags = {
  help: args.includes('--help') || args.includes('-h'),
  json: args.includes('--json'),
  strict: args.includes('--strict'),
  noNetwork: args.includes('--no-network'),
  version: args.includes('--version') || args.includes('-v'),
};

// Extract directory argument (first non-flag arg)
const dir = args.find(a => !a.startsWith('-')) || '.';

if (flags.version) {
  // Read version from package.json
  const { readFileSync } = await import('node:fs');
  const { resolve, dirname } = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const pkg = JSON.parse(readFileSync(resolve(__dirname, '..', 'package.json'), 'utf-8'));
  console.log(`lockcheck v${pkg.version}`);
  process.exit(0);
}

if (flags.help) {
  printHelp();
  process.exit(0);
}

// Run the scan
try {
  const results = await scan(dir, {
    noNetwork: flags.noNetwork,
    strict: flags.strict,
    onProgress: flags.json ? null : (msg) => {
      process.stdout.write(`\r  ${ICONS.search} ${dim(msg)}${''.padEnd(40)}`);
    },
  });

  // Clear progress line
  if (!flags.json) {
    process.stdout.write('\r' + ' '.repeat(60) + '\r');
  }

  // Output results
  if (flags.json) {
    printJsonReport(results);
  } else {
    printReport(results);
  }

  process.exit(results.exitCode);
} catch (err) {
  if (flags.json) {
    console.log(JSON.stringify({ error: err.message }, null, 2));
  } else {
    console.error('');
    console.error(`  ${ICONS.critical} ${red(bold('Error:'))} ${err.message}`);
    console.error('');

    if (err.message.includes('No package-lock.json')) {
      console.error(dim('  Make sure you are in a directory with a package-lock.json file,'));
      console.error(dim('  or specify the path: npx lockcheck ./my-project'));
    }

    console.error('');
  }
  process.exit(2);
}

function printHelp() {
  console.log(`
  ${bold(cyan(`${ICONS.lock} lockcheck`))} — Detect malicious dependency diffs in lock files

  ${bold('USAGE')}

    ${green('npx @dhanushnehru/lockcheck')} ${dim('[directory] [options]')}

  ${bold('OPTIONS')}

    ${yellow('--json')}         Output results as JSON (for CI/CD pipelines)
    ${yellow('--strict')}       Exit with code 1 on warnings (not just criticals)
    ${yellow('--no-network')}   Skip npm registry checks (offline mode)
    ${yellow('--help, -h')}     Show this help message
    ${yellow('--version, -v')}  Show version number

  ${bold('EXAMPLES')}

    ${dim('# Scan the current directory')}
    ${green('npx @dhanushnehru/lockcheck')}

    ${dim('# Scan a specific project')}
    ${green('npx @dhanushnehru/lockcheck ./my-app')}

    ${dim('# Use in CI/CD pipeline')}
    ${green('npx @dhanushnehru/lockcheck --json --strict')}

    ${dim('# Offline mode (skip registry checks)')}
    ${green('npx @dhanushnehru/lockcheck --no-network')}

  ${bold('HOW IT WORKS')}

    1. Parses your ${cyan('package-lock.json')}
    2. Compares against a saved snapshot (${cyan('.lockcheck-snapshot.json')})
    3. Runs 6 security analyzers:
       ${ICONS.bullet} New dependency detection
       ${ICONS.bullet} Suspicious version jumps
       ${ICONS.bullet} Typosquat detection
       ${ICONS.bullet} Registry anomaly detection
       ${ICONS.bullet} Install script analysis
       ${ICONS.bullet} Package freshness checks
    4. Reports findings with severity levels

  ${bold('EXIT CODES')}

    ${green('0')}  No critical issues found
    ${red('1')}  Critical issues detected (or warnings in --strict mode)
    ${red('2')}  Runtime error (missing lockfile, etc.)

  ${dim('https://github.com/DhanushNehru/lockcheck')}
`);
}

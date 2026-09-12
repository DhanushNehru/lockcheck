/**
 * Terminal reporter — beautiful CLI output with ANSI colors.
 * No dependencies. Box-drawing characters for premium look.
 */

import {
  bold, dim, red, green, yellow, cyan, white, gray,
  brightRed, brightGreen, brightYellow, brightCyan,
  error, warning, success, info,
  ICONS,
} from '../utils/colors.js';

const BOX = {
  topLeft: '┌', topRight: '┐',
  bottomLeft: '└', bottomRight: '┘',
  horizontal: '─', vertical: '│',
  teeRight: '├', teeLeft: '┤',
};

/**
 * Print the scan results to the terminal.
 * @param {{ findings: Array, stats: object, isFirstRun: boolean }} results
 */
export function printReport(results) {
  const { findings, stats, isFirstRun } = results;

  console.log('');
  printHeader();
  console.log('');

  if (isFirstRun) {
    printFirstRun(stats);
    return;
  }

  // Group findings by severity
  const critical = findings.filter(f => f.severity === 'critical');
  const warnings = findings.filter(f => f.severity === 'warning');
  const infos = findings.filter(f => f.severity === 'info');

  if (critical.length > 0) {
    printSection(ICONS.critical + ' CRITICAL', critical, brightRed);
  }

  if (warnings.length > 0) {
    printSection(ICONS.warning + 'WARNINGS', warnings, brightYellow);
  }

  if (infos.length > 0) {
    printSection('ℹ️  INFO', infos, brightCyan);
  }

  console.log('');
  printSummary(stats, critical.length, warnings.length, infos.length);
  console.log('');
}

function printHeader() {
  const title = `${ICONS.lock} lockcheck`;
  const subtitle = 'Supply chain security scanner for lock files';
  const line = BOX.horizontal.repeat(52);

  console.log(gray(BOX.topLeft + line + BOX.topRight));
  console.log(gray(BOX.vertical) + ' ' + bold(cyan(title)) + ' '.repeat(52 - title.length + 1) + gray(BOX.vertical));
  console.log(gray(BOX.vertical) + ' ' + dim(subtitle) + ' '.repeat(52 - subtitle.length - 1) + gray(BOX.vertical));
  console.log(gray(BOX.bottomLeft + line + BOX.bottomRight));
}

function printFirstRun(stats) {
  console.log(success(`  ${ICONS.shield} Baseline established!`));
  console.log('');
  console.log(`  ${dim('Scanned')} ${bold(String(stats.totalPackages))} ${dim('packages in')} ${bold(stats.lockfileType)}`);
  console.log(`  ${dim('Snapshot saved to')} ${cyan('.lockcheck-snapshot.json')}`);
  console.log('');
  console.log(dim('  Run lockcheck again after your next npm install to'));
  console.log(dim('  detect suspicious changes in your dependencies.'));
  console.log('');
}

function printSection(title, findings, colorFn) {
  console.log(`  ${colorFn(bold(title))}`);
  console.log(gray('  ' + BOX.horizontal.repeat(48)));

  for (const finding of findings) {
    const icon = finding.severity === 'critical' ? ICONS.critical
      : finding.severity === 'warning' ? ICONS.warning
      : ICONS.bullet;

    console.log(`  ${icon} ${bold(finding.name)} ${dim('@' + finding.version)}`);
    console.log(`    ${finding.message}`);
    if (finding.detail) {
      console.log(`    ${dim(finding.detail)}`);
    }
    console.log('');
  }
}

function printSummary(stats, criticalCount, warningCount, infoCount) {
  const line = BOX.horizontal.repeat(52);
  console.log(gray(BOX.topLeft + line + BOX.topRight));

  // Stats line
  const statsLine = `  ${ICONS.package} ${bold(String(stats.totalPackages))} packages scanned`;
  console.log(gray(BOX.vertical) + statsLine + ' '.repeat(Math.max(0, 52 - stripAnsi(statsLine).length)) + gray(BOX.vertical));

  if (typeof stats.durationMs === 'number' && Number.isFinite(stats.durationMs)) {
    const seconds = (stats.durationMs / 1000).toFixed(2);
    const timeLine = `  ⏱️  Scanned in ${bold(seconds + 's')}`;
    console.log(gray(BOX.vertical) + timeLine + ' '.repeat(Math.max(0, 52 - stripAnsi(timeLine).length)) + gray(BOX.vertical));
  }

  if (stats.newPackages > 0) {
    const newLine = `  ${ICONS.new} ${bold(String(stats.newPackages))} new dependencies`;
    console.log(gray(BOX.vertical) + newLine + ' '.repeat(Math.max(0, 52 - stripAnsi(newLine).length)) + gray(BOX.vertical));
  }

  if (stats.changedPackages > 0) {
    const changedLine = `  ${ICONS.arrow} ${bold(String(stats.changedPackages))} version changes`;
    console.log(gray(BOX.vertical) + changedLine + ' '.repeat(Math.max(0, 52 - stripAnsi(changedLine).length)) + gray(BOX.vertical));
  }

  // Separator
  console.log(gray(BOX.teeRight + line + BOX.teeLeft));

  // Results line
  const totalIssues = criticalCount + warningCount;

  if (totalIssues === 0) {
    const safeLine = `  ${ICONS.shield} ${success('No issues found — your dependencies look safe!')}`;
    console.log(gray(BOX.vertical) + safeLine + ' '.repeat(Math.max(0, 52 - stripAnsi(safeLine).length)) + gray(BOX.vertical));
  } else {
    if (criticalCount > 0) {
      const critLine = `  ${ICONS.critical} ${error(`${criticalCount} critical`)}`;
      console.log(gray(BOX.vertical) + critLine + ' '.repeat(Math.max(0, 52 - stripAnsi(critLine).length)) + gray(BOX.vertical));
    }
    if (warningCount > 0) {
      const warnLine = `  ${ICONS.warning}${warning(`${warningCount} warning(s)`)}`;
      console.log(gray(BOX.vertical) + warnLine + ' '.repeat(Math.max(0, 52 - stripAnsi(warnLine).length)) + gray(BOX.vertical));
    }
    if (infoCount > 0) {
      const infoLine = `  ℹ️  ${info(`${infoCount} info`)}`;
      console.log(gray(BOX.vertical) + infoLine + ' '.repeat(Math.max(0, 52 - stripAnsi(infoLine).length)) + gray(BOX.vertical));
    }
  }

  console.log(gray(BOX.bottomLeft + line + BOX.bottomRight));
}

/**
 * Print results as JSON for CI/CD integration.
 */
export function printJsonReport(results) {
  console.log(JSON.stringify(results, null, 2));
}

/**
 * Strip ANSI escape codes for length calculation.
 */
function stripAnsi(str) {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\x1b\[[0-9;]*m/g, '');
}

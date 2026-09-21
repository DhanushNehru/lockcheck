<div align="center">

# 🔒 lockcheck

**Detect malicious dependency diffs in lock files.**
Catches supply chain attacks before they catch you.

[![npm version](https://img.shields.io/npm/v/@dhanushnehru/lockcheck.svg?style=flat-square&color=cb3837)](https://www.npmjs.com/package/@dhanushnehru/lockcheck)
[![license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/DhanushNehru/lockcheck?style=flat-square&color=yellow)](https://github.com/DhanushNehru/lockcheck/stargazers)
[![zero deps](https://img.shields.io/badge/dependencies-0-brightgreen?style=flat-square)](package.json)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen?style=flat-square)](package.json)

</div>

---

Every time you run `npm install`, your lockfile changes. **Nobody reviews those diffs.** Attackers exploit this by injecting typosquatted, hijacked, or backdoored packages.

`lockcheck` scans your `package-lock.json`, diffs it against a saved snapshot, and flags anything suspicious — **before it reaches production**.

## ⚡ Quick Start

```bash
npx @dhanushnehru/lockcheck
```

That's it. No install required. No configuration. No dependencies.

## 🔍 What It Detects

```
┌────────────────────────────────────────────────────┐
│ 🔒 lockcheck                                       │
│ Supply chain security scanner for lock files       │
└────────────────────────────────────────────────────┘

  🔴 CRITICAL
  ────────────────────────────────────────────────────
  🔴 ev4l-js @1.0.0
    Possible typosquat of "eval-js" (edit distance 1)
    Levenshtein distance: 1

  🔴 lodash @4.99.0
    Integrity hash changed without version change!
    This could indicate the package was republished.

  ⚠️  WARNINGS
  ────────────────────────────────────────────────────
  ⚠️  sketchy-lib @1.0.0
    New dependency added: sketchy-lib@1.0.0
    (production dependency)

  ⚠️  sketchy-lib @1.0.0
    Published 2 day(s) ago
    New packages should be reviewed carefully.

  ⚠️  sketchy-lib @1.0.0
    Very low download count: 47 weekly downloads
    Low-download packages are higher risk.

  ⚠️  random-helper @2.0.0
    Has install scripts (preinstall/install/postinstall)
    Install scripts can execute arbitrary code.

┌────────────────────────────────────────────────────┐
│  📦 847 packages scanned                           │
│  🆕 3 new dependencies                             │
│  → 12 version changes                              │
├────────────────────────────────────────────────────┤
│  🔴 2 critical                                     │
│  ⚠️  4 warning(s)                                  │
└────────────────────────────────────────────────────┘
```

## 🛡️ 6 Security Analyzers

| Analyzer | What It Catches |
|----------|----------------|
| **New Dependencies** | Packages added since last scan — the primary attack vector |
| **Version Jumps** | Suspicious semver changes: 4.17.21 → 4.99.0, downgrades |
| **Typosquat Detection** | Names similar to popular packages: `1odash`, `reqest`, `epress` |
| **Registry Anomalies** | Non-standard registries, registry switches, integrity hash changes |
| **Install Scripts** | Packages with `postinstall` scripts (primary code execution vector) |
| **Freshness Checks** | Newly published packages with low downloads (via npm registry API) |

## 📖 Usage

```bash
# Scan current directory
npx @dhanushnehru/lockcheck

# Scan a specific project
npx @dhanushnehru/lockcheck ./my-app

# CI/CD mode (JSON output + strict exit codes)
npx @dhanushnehru/lockcheck --json --strict

# Offline mode (skip npm registry checks)
npx @dhanushnehru/lockcheck --no-network

# Show help
npx @dhanushnehru/lockcheck --help
```

## 🏗️ How It Works

1. **Parse** — Reads your `package-lock.json` (supports lockfileVersion 1, 2, and 3)
2. **Snapshot** — Compares against a saved `.lockcheck-snapshot.json` baseline
3. **Analyze** — Runs 6 independent security analyzers
4. **Report** — Outputs findings with severity levels (critical/warning/info)
5. **Exit** — Returns code `0` (safe) or `1` (issues found) for CI integration

On first run, lockcheck creates a baseline snapshot. On subsequent runs, it diffs against that baseline to detect changes.

## 🤖 GitHub Action

Add lockcheck to your CI pipeline to automatically scan every PR:

```yaml
# .github/workflows/lockcheck.yml
name: Lockfile Security

on:
  pull_request:
    paths:
      - 'package-lock.json'

jobs:
  lockcheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: DhanushNehru/lockcheck@v1
        with:
          strict: true
```

Or use it directly:

```yaml
- name: Run lockcheck
  run: npx @dhanushnehru/lockcheck --strict
```

## 🔧 Options

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON for CI/CD pipelines |
| `--strict` | Exit with code 1 on warnings (not just criticals) |
| `--no-network` | Skip npm registry API checks (offline mode) |
| `--help, -h` | Show help message |
| `--version, -v` | Show version number |

## 💡 Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No critical issues found |
| `1` | Critical issues detected (or warnings in `--strict` mode) |
| `2` | Runtime error (missing lockfile, etc.) |

## 🕵️ Why lockcheck?

### The Problem
Supply chain attacks on npm have exploded:
- **Typosquatting** — Packages named `1odash`, `angu1ar`, `reqest` that execute malicious code
- **Package hijacking** — Maintainer accounts get compromised, legit packages get backdoored
- **Dependency confusion** — Private package names are registered on the public registry
- **Postinstall payloads** — Malicious code runs immediately on `npm install`

### What Exists Today
- `npm audit` only checks **known CVEs** — it doesn't catch zero-day supply chain attacks
- Lock file diffs are **thousands of lines** that no human reviews
- CI pipelines auto-merge Dependabot PRs with **zero lockfile inspection**

### What lockcheck Does Differently
- **Proactive detection** — Catches suspicious patterns before they become CVEs
- **Zero dependencies** — Eats its own dogfood. Nothing to get supply-chain attacked through.
- **Snapshot diffing** — Tracks changes over time instead of point-in-time scanning
- **Smart heuristics** — Typosquat detection, version jump analysis, registry anomaly detection

## 🏛️ Architecture

```
lockcheck/
├── bin/lockcheck.js          # CLI entry point
├── src/
│   ├── index.js              # Scan orchestrator
│   ├── parsers/npm.js        # package-lock.json parser
│   ├── analyzers/            # 6 independent security analyzers
│   ├── reporters/terminal.js # Beautiful terminal output
│   └── utils/                # Colors, semver, levenshtein, registry
├── action.yml                # GitHub Action
└── package.json              # Zero dependencies
```

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Adding a new analyzer is easy** — create a file in `src/analyzers/`, export a function that returns `{ findings: [] }`, and wire it up in `src/index.js`.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

<div align="center">

**If lockcheck helped you, give it a ⭐ — it helps others find it!**

*Built with zero dependencies.*

</div>

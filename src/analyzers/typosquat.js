/**
 * Analyzer: Detect typosquatted package names.
 * Uses Levenshtein distance + pattern matching against popular npm packages.
 */

import { levenshtein, checkTyposquatPatterns } from '../utils/levenshtein.js';

// Top 200 most popular npm packages (curated list)
const POPULAR_PACKAGES = [
  '@anthropic-ai/sdk', '@apollo/client', '@aws-sdk/client-s3', '@babel/core', '@babel/preset-env',
  '@babel/preset-react', '@clerk/nextjs', '@commitlint/cli', '@emotion/react', '@emotion/styled',
  '@prisma/client', '@radix-ui/react-dialog', '@tanstack/react-query', '@tanstack/react-table', '@testing-library/jest-dom',
  '@testing-library/react', '@types/jest', '@types/node', '@types/react', 'ajv',
  'amqplib', 'angular', 'apollo-server', 'astro', 'autoprefixer',
  'aws-sdk', 'axios', 'babel-core', 'bcrypt', 'bcryptjs',
  'better-auth', 'better-sqlite3', 'biome', 'body-parser', 'boxen',
  'bull', 'bullmq', 'bunyan', 'busboy', 'chai',
  'chalk', 'cheerio', 'chokidar', 'cli-table3', 'clsx',
  'commander', 'commitlint', 'compression', 'concurrently', 'connect-redis',
  'consola', 'cookie-parser', 'cors', 'cron', 'cross-env',
  'cross-spawn', 'crypto-js', 'css-loader', 'csurf', 'cypress',
  'date-fns', 'dayjs', 'debug', 'del', 'dompurify',
  'dotenv', 'drizzle-orm', 'ejs', 'ember-source', 'esbuild',
  'eslint', 'execa', 'express', 'express-rate-limit', 'express-session',
  'fastify', 'figures', 'firebase', 'firebase-admin', 'formidable',
  'framer-motion', 'fs-extra', 'gatsby', 'glob', 'globby',
  'got', 'graphql', 'handlebars', 'hapi', 'helmet',
  'highlight.js', 'hpp', 'husky', 'i18next', 'inquirer',
  'ioredis', 'jest', 'jimp', 'joi', 'jose',
  'jotai', 'jsdom', 'jsonwebtoken', 'kafkajs', 'knex',
  'koa', 'ky', 'langchain', 'less', 'lint-staged',
  'listr2', 'lit', 'lodash', 'loglevel', 'luxon',
  'markdown-it', 'marked', 'meow', 'mikro-orm', 'minimist',
  'mixpanel', 'mkdirp', 'mocha', 'moment', 'mongodb',
  'mongoose', 'morgan', 'multer', 'mysql2', 'nanoid',
  'next', 'next-auth', 'nock', 'node-cron', 'node-fetch',
  'nodemailer', 'nodemon', 'nunjucks', 'nuxt', 'ofetch',
  'ollama', 'openai', 'ora', 'parcel', 'passport',
  'pdf-lib', 'pg', 'pino', 'playwright', 'pm2',
  'postcss', 'posthog-js', 'preact', 'prettier', 'prisma',
  'progress', 'pug', 'puppeteer', 'puppeteer-core', 'ramda',
  'rate-limiter-flexible', 'react', 'react-dom', 'react-hook-form', 'redis',
  'remix', 'rimraf', 'rollup', 'rxjs', 'sanitize-html',
  'sass', 'sequelize', 'sharp', 'shelljs', 'sinon',
  'socket.io', 'solid-js', 'sqlite3', 'stripe', 'style-loader',
  'styled-components', 'stylelint', 'superagent', 'supertest', 'svelte',
  'swc', 'tailwindcss', 'ts-node', 'tsup', 'tsx',
  'turbo', 'typeorm', 'typescript', 'underscore', 'undici',
  'uuid', 'vite', 'vitest', 'vue', 'webpack',
  'winston', 'ws', 'xss', 'yargs', 'yup',
  'zod', 'zustand',
];

// Well-known legitimate packages that are short or look like typosquats but aren't
const KNOWN_SAFE = new Set([
  'ms', 'qs', 'on', 'ee', 'ip', 'he', 'os', 'pg', 'pn',
  'co', 'is', 'to', 'yn', 'or', 'pi', 'rc',
  ...POPULAR_PACKAGES,
]);

// Trusted scopes that should NOT trigger scope confusion
const TRUSTED_SCOPES = new Set([
  '@types', '@babel', '@emotion', '@testing-library', '@angular',
  '@vue', '@nuxt', '@nestjs', '@prisma', '@apollo', '@aws-sdk',
  '@commitlint', '@eslint', '@swc', '@biomejs', '@parcel',
  '@playwright', '@storybook', '@tanstack', '@trpc', '@vercel',
  '@vitejs', '@remix-run', '@astrojs', '@nextui-org', '@radix-ui',
  '@headlessui', '@grpc', '@hapi', '@fastify', '@types',
]);

/**
 * Check if a package name looks like a typosquat of a popular package.
 * @param {string} name - Package name to check
 * @returns {{ isTyposquat: boolean, similarTo: string | null, distance: number | null, pattern: string | null }}
 */
export function detectTyposquat(name) {
  // Skip if it IS a popular or known-safe package
  if (KNOWN_SAFE.has(name)) {
    return { isTyposquat: false, similarTo: null, distance: null, pattern: null };
  }

  // Skip packages from trusted scopes
  const scopeMatch = name.match(/^(@[^/]+)\//); 
  if (scopeMatch && TRUSTED_SCOPES.has(scopeMatch[1])) {
    return { isTyposquat: false, similarTo: null, distance: null, pattern: null };
  }

  // Check pattern-based matches first (more specific)
  for (const popular of POPULAR_PACKAGES) {
    const patternResult = checkTyposquatPatterns(name, popular);
    if (patternResult.match) {
      return {
        isTyposquat: true,
        similarTo: popular,
        distance: null,
        pattern: patternResult.pattern,
      };
    }
  }

  // Check Levenshtein distance
  for (const popular of POPULAR_PACKAGES) {
    // Skip very short names â too many false positives (ms vs ws, qs vs ws, etc.)
    if (name.length <= 2 || popular.length <= 2) continue;

    // Only compare packages of similar length to reduce false positives
    if (Math.abs(name.length - popular.length) > 2) continue;

    const distance = levenshtein(name, popular);

    // Strict threshold: distance of 1 for short names, 2 for longer ones (8+ chars)
    const threshold = popular.length <= 6 ? 1 : 2;

    if (distance > 0 && distance <= threshold) {
      return {
        isTyposquat: true,
        similarTo: popular,
        distance,
        pattern: `edit distance ${distance}`,
      };
    }
  }

  return { isTyposquat: false, similarTo: null, distance: null, pattern: null };
}

/**
 * Analyze all packages for typosquatting.
 * @param {Map<string, object>} packages
 * @returns {{ findings: Array }}
 */
export function analyzeTyposquats(packages) {
  const findings = [];

  for (const [name, pkg] of packages) {
    const result = detectTyposquat(name);

    if (result.isTyposquat) {
      findings.push({
        severity: 'critical',
        name,
        version: pkg.version,
        message: `Possible typosquat of "${result.similarTo}" (${result.pattern})`,
        detail: result.distance !== null
          ? `Levenshtein distance: ${result.distance}`
          : `Pattern: ${result.pattern}`,
      });
    }
  }

  return { findings };
}

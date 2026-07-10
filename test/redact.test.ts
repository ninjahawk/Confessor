import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redactMiddle, redactCard, redactEmail, redactSsn, redactUrlCreds } from '../src/redact.js';
import { scanText, ALL_RULES, buildPreview } from '../src/detect/index.js';
import { PLANTS } from './helpers/plants.js';

test('redactMiddle keeps only edges', () => {
  const r = redactMiddle(PLANTS.awsKeyId);
  assert.equal(r, 'AKIA••••••••••••MPLE');
  assert.ok(!r.includes('IOSFODNN'));
  assert.equal(redactMiddle('short'), '•••••');
});

test('typed redactors', () => {
  assert.equal(redactCard(PLANTS.card), '•••• •••• •••• 1111');
  assert.equal(redactEmail(PLANTS.email), 'j•••@gmail.com');
  assert.equal(redactSsn(PLANTS.ssn), '•••-••-9999');
  const uri = redactUrlCreds(PLANTS.pgUri);
  assert.ok(!uri.includes('S3cr3tDbPass'));
  assert.ok(uri.includes('appuser'));
  assert.ok(uri.includes('db.internal.corp'));
});

test('previews scrub neighboring findings too', () => {
  const text = `creds: AWS_ACCESS_KEY_ID=${PLANTS.awsKeyId} GITHUB_TOKEN=${PLANTS.ghToken} done`;
  const spans = scanText(text, ALL_RULES);
  assert.ok(spans.length >= 2);
  for (const span of spans) {
    const preview = buildPreview(text, span, spans);
    assert.ok(!preview.includes(PLANTS.awsKeyId), `raw aws key leaked in preview: ${preview}`);
    assert.ok(!preview.includes(PLANTS.ghToken), `raw gh token leaked in preview: ${preview}`);
  }
});

test('long secrets collapse instead of flooding the preview', () => {
  const text = `key file:\n-----BEGIN RSA PRIVATE KEY-----\n${'A1b2C3d4'.repeat(64)}\n-----END RSA PRIVATE KEY-----\nend`;
  const spans = scanText(text, ALL_RULES);
  const pk = spans.find((s) => s.rule.id === 'private-key-block');
  assert.ok(pk);
  const preview = buildPreview(text, pk!, spans);
  assert.ok(preview.length <= 240);
  assert.ok(preview.includes('REDACTED'));
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanText, SECRET_RULES } from '../src/detect/index.js';
import { PLANTS, PRIVATE_KEY_PEM } from './helpers/plants.js';

function types(text: string): string[] {
  return scanText(text, SECRET_RULES).map((s) => s.rule.id);
}

test('detects provider-prefixed API keys', () => {
  assert.deepEqual(types(`key=${PLANTS.anthropicKey}`), ['anthropic-api-key']);
  assert.deepEqual(types('here: sk-proj-mF9xQ2Lp7Kn4Rv8Tw1Yz5Ui3Po6As0Dg2Hk4Jl6Zc8Vb'), ['openai-api-key']);
  assert.deepEqual(types(`GITHUB_TOKEN=${PLANTS.ghToken}`), ['github-token']);
  assert.deepEqual(types(`STRIPE=${PLANTS.stripeLive}`), ['stripe-live-key']);
  assert.deepEqual(types('rk_test_4X9mQ2pL7nR8vT1wY5uI3oK6').includes('stripe-test-key'), true);
  assert.deepEqual(types(`maps: ${PLANTS.googleKey}`), ['google-api-key']);
  assert.deepEqual(types(`SLACK_BOT=${PLANTS.slackToken}`), ['slack-token']);
  assert.deepEqual(types(`publish with ${PLANTS.npmToken}`), ['npm-token']);
  assert.deepEqual(types('hf_ABCdefGHIjklMNOpqrSTUvwxYZ012345 for the model'), ['huggingface-token']);
  assert.deepEqual(types('token glpat-Xy7Kq2mNp9Lr4Tv8Wz1J here'), ['gitlab-token']);
});

test('anthropic key is not double-flagged as openai', () => {
  const found = types(`both? ${PLANTS.anthropicKey}`);
  assert.deepEqual(found, ['anthropic-api-key']);
});

test('aws pair: key id anywhere, secret only with aws context', () => {
  assert.deepEqual(types(`id ${PLANTS.awsKeyId} end`), ['aws-access-key-id']);
  const both = types(`AWS_ACCESS_KEY_ID=${PLANTS.awsKeyId}\nAWS_SECRET_ACCESS_KEY=${PLANTS.awsSecret}`);
  assert.ok(both.includes('aws-access-key-id'));
  assert.ok(both.includes('aws-secret-access-key'));
  // 40 base64-ish chars with no aws context nearby → not flagged
  assert.deepEqual(types(`random blob ${PLANTS.awsSecret} in text`), []);
});

test('private key blocks, db uris, url creds, jwts', () => {
  assert.deepEqual(types(PRIVATE_KEY_PEM), ['private-key-block']);
  assert.deepEqual(types(`conn: ${PLANTS.pgUri}`), ['db-connection-uri']);
  assert.deepEqual(types(`curl ${PLANTS.urlAuth}`), ['url-basic-auth']);
  assert.deepEqual(types(`Authorization: ${PLANTS.jwt}`), ['jwt']);
  // Bearer prefix should still resolve to the (more specific) JWT rule
  assert.deepEqual(types(`Authorization: Bearer ${PLANTS.jwt}`), ['jwt']);
});

test('generic assignments require entropy and non-placeholder values', () => {
  assert.deepEqual(types(`token = ${PLANTS.genericToken}`), ['generic-secret-assignment']);
  assert.deepEqual(types('api_key = "your_api_key_here"'), []);
  assert.deepEqual(types('token = "aaaaaaaaaaaaaaaaaaaaaa"'), []);
  assert.deepEqual(types('api_key=<YOUR_KEY>'), []);
  assert.deepEqual(types('secret: ${VAULT_SECRET}'), []);
  assert.deepEqual(types('max_tokens = 409600000000'), []);
  assert.deepEqual(types('the token is stored in the TOKEN env var'), []);
});

test('passwords: real values flagged, prose not', () => {
  assert.deepEqual(types(`password: ${PLANTS.password}`), ['password-assignment']);
  assert.deepEqual(types('my password is hunter2secret!'), ['password-assignment']);
  assert.deepEqual(types('password is required'), []);
  assert.deepEqual(types('the password is incorrect'), []);
  assert.deepEqual(types('password: ********'), []);
  assert.deepEqual(types('password = getPassword()'), []);
});

test('context-gated vendors need their context', () => {
  const twilioKey = 'SK0123456789abcdef0123456789abcdef';
  assert.deepEqual(types(`value ${twilioKey}`), []);
  assert.deepEqual(types(`twilio api key ${twilioKey}`), ['twilio-api-key']);
});

test('sk- prose does not false-positive', () => {
  assert.deepEqual(types('use sk-learn for the model'), []);
  assert.deepEqual(types('sklearn and sk-image are libraries'), []);
});

test('every secret rule redacts its own match', () => {
  const samples: Record<string, string> = {
    'anthropic-api-key': PLANTS.anthropicKey,
    'github-token': PLANTS.ghToken,
    'db-connection-uri': PLANTS.pgUri,
    jwt: PLANTS.jwt,
  };
  for (const [id, value] of Object.entries(samples)) {
    const rule = SECRET_RULES.find((r) => r.id === id);
    assert.ok(rule, id);
    const redacted = rule!.redact(value);
    assert.ok(!redacted.includes(value), `${id} leaked raw value`);
  }
});

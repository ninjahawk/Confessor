import { test } from 'node:test';
import assert from 'node:assert/strict';
import { audit, renderReport } from '../src/index.js';
import { ALL_FIXTURE_INPUTS } from './helpers/paths.js';
import { MUST_NOT_LEAK } from './helpers/plants.js';

let html: string | null = null;
async function report(): Promise<string> {
  if (!html) html = renderReport(await audit(ALL_FIXTURE_INPUTS));
  return html;
}

test('THE GUARANTEE: no planted secret ever appears in the report', async () => {
  const out = await report();
  for (const raw of MUST_NOT_LEAK) {
    assert.ok(!out.includes(raw), `RAW VALUE IN REPORT: ${raw.slice(0, 12)}…`);
  }
});

test('redacted forms are what actually renders', async () => {
  const out = await report();
  assert.ok(out.includes('AKIA••••••••••••MPLE'));
  assert.ok(out.includes('•••• •••• •••• 1111'));
  assert.ok(out.includes('j•••@gmail.com'));
  assert.ok(out.includes('•••-••-9999'));
});

test('scanned content cannot inject markup (XSS)', async () => {
  const out = await report();
  assert.ok(!out.includes('<script>alert'), 'unescaped script tag from scanned content');
  assert.ok(!out.includes('<img src=x'), 'unescaped img tag from scanned content');
  assert.ok(out.includes('&lt;script&gt;alert'), 'expected the escaped payload to be visible');
});

test('fully offline: CSP present, zero external resource loads', async () => {
  const out = await report();
  assert.ok(out.includes('Content-Security-Policy'));
  assert.ok(out.includes("default-src 'none'"));
  assert.ok(!/<script[^>]+src\s*=/i.test(out), 'external script');
  assert.ok(!/<link[^>]+href\s*=/i.test(out), 'external stylesheet');
  assert.ok(!/<img[^>]+src\s*=\s*["']https?:/i.test(out), 'external image');
  assert.ok(!/@import/i.test(out), 'css import');
  assert.ok(!/\bfetch\s*\(/.test(out), 'fetch call in report JS');
  assert.ok(!/XMLHttpRequest|WebSocket/.test(out), 'network API in report JS');
});

test('report structure: all eight sections render', async () => {
  const out = await report();
  for (const marker of [
    'What your AI agent did on this computer',
    'Exposure paths',
    'Where it came from',
    'What we found',
    "What you've shared about yourself",
    'Month by month',
    'Chats to clean up first',
    'What to do now',
    'Share your grade',
    'share-canvas',
    'timeline-svg',
  ]) {
    assert.ok(out.includes(marker), `missing section: ${marker}`);
  }
});

test('share card data is counts-only', async () => {
  const out = await report();
  const m = out.match(/window\.__CONFESSOR_STATS__ = (\{.*?\});<\/script>/s);
  assert.ok(m, 'stats payload missing');
  const stats = JSON.parse(m![1]) as Record<string, unknown>;
  assert.deepEqual(
    Object.keys(stats).sort(),
    ['conversations', 'critical', 'date', 'grade', 'gradeColor', 'high', 'medium', 'messages', 'providers', 'score'].sort(),
  );
});

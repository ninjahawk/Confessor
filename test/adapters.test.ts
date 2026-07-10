import { test } from 'node:test';
import assert from 'node:assert/strict';
import { messagesFromPath } from '../src/adapters/index.js';
import { prettifyProjectDir } from '../src/adapters/claude-code.js';
import type { SourceMessage } from '../src/types.js';
import { FIXTURE_PATHS } from './helpers/paths.js';

async function collect(p: string): Promise<SourceMessage[]> {
  const out: SourceMessage[] = [];
  for await (const m of messagesFromPath(p)) out.push(m);
  return out;
}

test('claude code: roles, isMeta skip, summary title, timestamps', async () => {
  const msgs = await collect(FIXTURE_PATHS.claudeCodeHome);
  assert.equal(msgs.length, 8);
  assert.equal(msgs.filter((m) => m.role === 'user').length, 5);
  assert.equal(msgs.filter((m) => m.role === 'assistant').length, 1);
  assert.equal(msgs.filter((m) => m.role === 'tool').length, 2);
  // Title comes from the summary line (XSS payload intact here; escaped at render time).
  assert.ok(msgs[0].conversationTitle.includes('Deploy scripts'));
  assert.ok(msgs.every((m) => m.provider === 'claude-code'));
  assert.ok(msgs.every((m) => typeof m.timestamp === 'number' && m.timestamp! > 0));
  // The isMeta caveat line must not be scanned.
  assert.ok(!msgs.some((m) => m.text.includes('Caveat')));
});

test('claude code: project dir names prettify', () => {
  assert.equal(prettifyProjectDir('C--Users-demo-app'), 'C:/Users/demo/app');
  assert.equal(prettifyProjectDir('-Users-demo-app'), '/Users/demo/app');
});

test('chatgpt export: mapping walk, roles, chronological order', async () => {
  const msgs = await collect(FIXTURE_PATHS.chatgptDir);
  assert.equal(msgs.length, 8);
  const conv1 = msgs.filter((m) => m.conversationId === 'gpt-conv-1');
  assert.equal(conv1.length, 4);
  assert.equal(conv1[0].role, 'user');
  assert.equal(conv1[1].role, 'assistant');
  assert.equal(conv1[0].conversationTitle, 'Stripe webhook 500s');
  const times = conv1.map((m) => m.timestamp ?? 0);
  assert.deepEqual(times, [...times].sort((a, b) => a - b));
});

test('claude.ai export: sender mapping and content parts', async () => {
  const msgs = await collect(FIXTURE_PATHS.claudeAiDir);
  assert.equal(msgs.length, 2);
  assert.equal(msgs[0].role, 'user');
  assert.equal(msgs[1].role, 'assistant');
  assert.equal(msgs[0].provider, 'claude');
  assert.ok(msgs[0].text.includes('401s'));
});

test('gemini takeout html (beta): prompts only, dates parsed', async () => {
  const msgs = await collect(FIXTURE_PATHS.geminiHtml);
  assert.equal(msgs.length, 2);
  assert.ok(msgs.every((m) => m.role === 'user' && m.provider === 'gemini'));
  assert.ok(msgs[0].text.startsWith('My name is John Carter'));
  assert.ok(!msgs[0].text.startsWith('Prompted'));
  const d = new Date(msgs[0].timestamp ?? 0);
  assert.equal(d.getFullYear(), 2023);
});

test('generic folder: one conversation per file', async () => {
  const msgs = await collect(FIXTURE_PATHS.genericDir);
  assert.equal(msgs.length, 2);
  assert.ok(msgs.every((m) => m.provider === 'generic' && m.role === 'user'));
  const titles = msgs.map((m) => m.conversationTitle).sort();
  assert.deepEqual(titles, ['dump.txt', 'notes.md']);
});

test('missing paths throw a friendly error', async () => {
  await assert.rejects(collect('definitely-not-a-real-path-xyz'), /path not found/);
});

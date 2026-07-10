import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { ZipReader } from '../src/zip.js';
import { writeZip } from './helpers/zipwrite.js';
import { FIXTURE_PATHS } from './helpers/paths.js';
import { messagesFromPath } from '../src/adapters/index.js';
import type { SourceMessage } from '../src/types.js';

function tmpZip(name: string, buf: Buffer): string {
  const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'confessor-test-')), name);
  fs.writeFileSync(p, buf);
  return p;
}

test('round-trips stored and deflated entries', () => {
  const big = 'hello confessor '.repeat(5000);
  const zipPath = tmpZip('roundtrip.zip', writeZip([
    { name: 'a/stored.txt', data: 'plain stored data', method: 0 },
    { name: 'b/deflated.txt', data: big, method: 8 },
  ]));
  const zip = new ZipReader(zipPath);
  try {
    assert.equal(zip.entries.length, 2);
    const stored = zip.find((n) => n.endsWith('stored.txt'))[0];
    const deflated = zip.find((n) => n.endsWith('deflated.txt'))[0];
    assert.equal(zip.read(stored).toString('utf8'), 'plain stored data');
    assert.equal(zip.read(deflated).toString('utf8'), big);
  } finally {
    zip.close();
  }
});

test('rejects non-zip files with a clear error', () => {
  const p = tmpZip('not-a.zip', Buffer.from('definitely not a zip file, just text'));
  assert.throws(() => new ZipReader(p), /end-of-central-directory|too small/);
});

test('a zipped ChatGPT export scans end-to-end', async () => {
  const conversations = fs.readFileSync(FIXTURE_PATHS.chatgptJson);
  const zipPath = tmpZip('chatgpt-export.zip', writeZip([
    { name: 'conversations.json', data: conversations, method: 8 },
    { name: 'user.json', data: '{"id":"user-x"}', method: 8 },
  ]));
  const messages: SourceMessage[] = [];
  for await (const m of messagesFromPath(zipPath)) messages.push(m);
  assert.equal(messages.length, 8);
  assert.ok(messages.every((m) => m.provider === 'chatgpt'));
});

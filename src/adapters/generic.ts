/**
 * Generic fallback adapter: scan any .txt/.md/.json/.jsonl/.log/.csv file or
 * folder of them. Each file becomes one "conversation" attributed to you.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { SourceMessage } from '../types.js';
import { walkFiles } from '../util.js';

export const GENERIC_EXTS = new Set(['.txt', '.md', '.markdown', '.json', '.jsonl', '.log', '.csv']);

const MAX_FILE_BYTES = 64 * 1024 * 1024;

export function* messagesFromGenericFile(file: string, root?: string): Generator<SourceMessage> {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(file);
  } catch {
    return;
  }
  if (stat.size === 0 || stat.size > MAX_FILE_BYTES) return;
  let text: string;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    return;
  }
  if (!text.trim()) return;
  const rel = root ? path.relative(root, file) : path.basename(file);
  yield {
    provider: 'generic',
    conversationId: rel,
    conversationTitle: rel,
    role: 'user',
    text,
    timestamp: stat.mtimeMs,
  };
}

export function* messagesFromGenericDir(dir: string, onFile?: (f: string) => void): Generator<SourceMessage> {
  for (const file of walkFiles(dir, { exts: GENERIC_EXTS })) {
    onFile?.(file);
    yield* messagesFromGenericFile(file, dir);
  }
}

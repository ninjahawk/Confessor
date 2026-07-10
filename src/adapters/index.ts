/**
 * Path → adapter dispatch. Figures out what a given file/folder/zip is
 * (Claude Code logs, ChatGPT export, Claude.ai export, Gemini Takeout, or
 * plain files) and yields normalized messages.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { SourceMessage } from '../types.js';
import { walkFiles } from '../util.js';
import { ZipReader } from '../zip.js';
import {
  messagesFromClaudeCodeDir,
  messagesFromClaudeCodeFile,
  claudeCodeDefaultDir,
} from './claude-code.js';
import { looksLikeChatGptExport, messagesFromChatGpt } from './chatgpt.js';
import { looksLikeClaudeExport, messagesFromClaudeAi } from './claude-ai.js';
import {
  looksLikeGeminiJson,
  messagesFromGeminiJson,
  messagesFromGeminiHtml,
} from './gemini.js';
import { messagesFromGenericDir, messagesFromGenericFile, GENERIC_EXTS } from './generic.js';

export { claudeCodeDefaultDir } from './claude-code.js';

export interface ScanCallbacks {
  onFile?: (file: string) => void;
  warn?: (message: string) => void;
}

function stripBom(s: string): string {
  return s.charCodeAt(0) === 0xfeff ? s.slice(1) : s;
}

function parseJsonLoose(text: string): unknown {
  return JSON.parse(stripBom(text));
}

/** Dispatch a parsed conversations.json-shaped value to the right parser. */
function* messagesFromConversationsJson(data: unknown, origin: string, warn?: (m: string) => void): Generator<SourceMessage> {
  if (looksLikeChatGptExport(data)) {
    yield* messagesFromChatGpt(data);
  } else if (looksLikeClaudeExport(data)) {
    yield* messagesFromClaudeAi(data);
  } else if (looksLikeGeminiJson(data)) {
    yield* messagesFromGeminiJson(data);
  } else if (Array.isArray(data) && data.length === 0) {
    warn?.(`${origin}: export contains no conversations`);
  } else {
    warn?.(`${origin}: unrecognized conversations.json shape — skipping`);
  }
}

async function* messagesFromZip(zipPath: string, cb?: ScanCallbacks): AsyncGenerator<SourceMessage> {
  const zip = new ZipReader(zipPath);
  try {
    const convs = zip.find((n) => n.toLowerCase().endsWith('conversations.json'));
    const activities = zip.find((n) => /myactivity\.(?:html|json)$/i.test(n));
    if (convs.length === 0 && activities.length === 0) {
      throw new Error(
        `${zipPath}: no conversations.json or MyActivity file found inside — if this is an export, extract it and run: confessor scan <folder>`,
      );
    }
    for (const entry of convs) {
      cb?.onFile?.(`${zipPath}!${entry.name}`);
      let data: unknown;
      try {
        data = parseJsonLoose(zip.read(entry).toString('utf8'));
      } catch (err) {
        cb?.warn?.(`${zipPath}!${entry.name}: ${(err as Error).message}`);
        continue;
      }
      yield* messagesFromConversationsJson(data, entry.name, cb?.warn);
    }
    for (const entry of activities) {
      cb?.onFile?.(`${zipPath}!${entry.name}`);
      try {
        const text = zip.read(entry).toString('utf8');
        if (entry.name.toLowerCase().endsWith('.json')) {
          const data = parseJsonLoose(text);
          if (looksLikeGeminiJson(data)) yield* messagesFromGeminiJson(data);
        } else {
          yield* messagesFromGeminiHtml(text);
        }
      } catch (err) {
        cb?.warn?.(`${zipPath}!${entry.name}: ${(err as Error).message}`);
      }
    }
  } finally {
    zip.close();
  }
}

async function* messagesFromJsonFile(file: string, cb?: ScanCallbacks): AsyncGenerator<SourceMessage> {
  cb?.onFile?.(file);
  let data: unknown;
  try {
    data = parseJsonLoose(fs.readFileSync(file, 'utf8'));
  } catch {
    // Not valid JSON → scan it as plain text instead of failing.
    yield* messagesFromGenericFile(file);
    return;
  }
  if (looksLikeChatGptExport(data) || looksLikeClaudeExport(data) || looksLikeGeminiJson(data)) {
    yield* messagesFromConversationsJson(data, file, cb?.warn);
  } else {
    yield* messagesFromGenericFile(file);
  }
}

function findFirst(dir: string, pred: (name: string) => boolean, maxDepth = 6): string | undefined {
  for (const f of walkFiles(dir, { maxDepth })) {
    if (pred(path.basename(f).toLowerCase())) return f;
  }
  return undefined;
}

function hasJsonlSessions(dir: string): boolean {
  for (const f of walkFiles(dir, { exts: new Set(['.jsonl']), maxDepth: 3 })) {
    void f;
    return true;
  }
  return false;
}

/** Yield messages for one user-supplied path (file, folder, or zip). */
export async function* messagesFromPath(p: string, cb?: ScanCallbacks): AsyncGenerator<SourceMessage> {
  const resolved = path.resolve(p);
  let stat: fs.Stats;
  try {
    stat = fs.statSync(resolved);
  } catch {
    throw new Error(`path not found: ${p}`);
  }

  if (stat.isFile()) {
    const base = path.basename(resolved).toLowerCase();
    const ext = path.extname(base);
    if (ext === '.zip') {
      yield* messagesFromZip(resolved, cb);
    } else if (ext === '.jsonl') {
      cb?.onFile?.(resolved);
      yield* messagesFromClaudeCodeFile(resolved);
    } else if (ext === '.json') {
      yield* messagesFromJsonFile(resolved, cb);
    } else if (ext === '.html' || ext === '.htm') {
      cb?.onFile?.(resolved);
      const text = fs.readFileSync(resolved, 'utf8');
      if (text.includes('content-cell')) {
        yield* messagesFromGeminiHtml(text);
      } else {
        cb?.warn?.(`${p}: HTML file doesn't look like a Google Takeout activity page — skipping`);
      }
    } else if (GENERIC_EXTS.has(ext)) {
      cb?.onFile?.(resolved);
      yield* messagesFromGenericFile(resolved);
    } else {
      cb?.warn?.(`${p}: unsupported file type '${ext}' — supported: .zip .json .jsonl .html .txt .md .log .csv`);
    }
    return;
  }

  // Directory.
  const projectsSub = path.join(resolved, 'projects');
  if (fs.existsSync(projectsSub) && fs.statSync(projectsSub).isDirectory() && hasJsonlSessions(projectsSub)) {
    yield* messagesFromClaudeCodeDir(projectsSub, cb?.onFile);
    return;
  }
  if (path.basename(resolved) === 'projects' && hasJsonlSessions(resolved)) {
    yield* messagesFromClaudeCodeDir(resolved, cb?.onFile);
    return;
  }
  const convJson = path.join(resolved, 'conversations.json');
  if (fs.existsSync(convJson)) {
    yield* messagesFromJsonFile(convJson, cb);
    // Exports may also carry a Claude-style projects.json or nothing else useful.
    return;
  }
  const activity = findFirst(resolved, (n) => /^myactivity\.(?:html|json)$/.test(n));
  if (activity) {
    cb?.onFile?.(activity);
    const text = fs.readFileSync(activity, 'utf8');
    if (activity.toLowerCase().endsWith('.json')) {
      const data = parseJsonLoose(text);
      if (looksLikeGeminiJson(data)) yield* messagesFromGeminiJson(data);
      else cb?.warn?.(`${activity}: unrecognized activity JSON shape`);
    } else {
      yield* messagesFromGeminiHtml(text);
    }
    return;
  }
  if (hasJsonlSessions(resolved)) {
    // A bare project dir full of .jsonl session logs.
    yield* messagesFromClaudeCodeDir(resolved, cb?.onFile);
    return;
  }
  yield* messagesFromGenericDir(resolved, cb?.onFile);
}

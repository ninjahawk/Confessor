/**
 * Claude Code adapter: parses the .jsonl session logs under ~/.claude/projects/.
 * These live on disk already — no export step needed. Tool inputs and results
 * are extracted too, because file contents flowing through tools are the
 * highest-risk surface (a `cat .env` lands in the log).
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as readline from 'node:readline';
import type { SourceMessage, Role } from '../types.js';
import { toMs, walkFiles } from '../util.js';

/** '-Users-demo-app' / 'C--Users-demo-app' → readable path. */
export function prettifyProjectDir(name: string): string {
  const drive = name.match(/^([A-Za-z])--(.*)$/);
  if (drive) return `${drive[1]}:/${drive[2].replace(/-/g, '/')}`;
  if (name.startsWith('-')) return '/' + name.slice(1).replace(/-/g, '/');
  return name;
}

function lastSegment(prettyPath: string): string {
  const parts = prettyPath.split('/').filter(Boolean);
  return parts[parts.length - 1] ?? prettyPath;
}

interface ContentPart {
  type?: string;
  text?: string;
  thinking?: string;
  input?: unknown;
  content?: unknown;
}

function toolResultText(content: unknown): string {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .map((p) => (typeof p === 'string' ? p : typeof (p as ContentPart)?.text === 'string' ? (p as ContentPart).text : ''))
      .filter(Boolean)
      .join('\n');
  }
  return '';
}

/** Scan the head of a session file for a `summary` line to use as the title. */
async function readTitleHint(file: string): Promise<string | undefined> {
  try {
    const fd = fs.openSync(file, 'r');
    const buf = Buffer.alloc(64 * 1024);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    fs.closeSync(fd);
    const head = buf.subarray(0, n).toString('utf8');
    for (const line of head.split('\n')) {
      if (!line.includes('"summary"')) continue;
      try {
        const obj = JSON.parse(line) as { type?: string; summary?: string };
        if (obj.type === 'summary' && typeof obj.summary === 'string' && obj.summary.trim()) {
          return obj.summary.trim();
        }
      } catch {
        /* partial line at buffer end */
      }
    }
  } catch {
    /* unreadable */
  }
  return undefined;
}

export async function* messagesFromClaudeCodeFile(file: string, projectsRoot?: string): AsyncGenerator<SourceMessage> {
  const projDir = path.basename(path.dirname(file));
  const pretty = prettifyProjectDir(projDir);
  const sessionId = path.basename(file, '.jsonl');
  const titleHint = await readTitleHint(file);
  const title = titleHint ?? `${lastSegment(pretty)} · ${sessionId.slice(0, 8)}`;
  const conversationId = projectsRoot ? path.relative(projectsRoot, file) : `${projDir}/${sessionId}`;

  const stream = fs.createReadStream(file, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

  const base = {
    provider: 'claude-code' as const,
    conversationId,
    conversationTitle: title,
    meta: { project: pretty, file },
  };

  try {
    for await (const line of rl) {
      if (!line || line[0] !== '{') continue;
      let ev: Record<string, unknown>;
      try {
        ev = JSON.parse(line) as Record<string, unknown>;
      } catch {
        continue;
      }
      const type = ev.type;
      const timestamp = toMs(ev.timestamp);
      if (ev.isMeta === true) continue;

      if (type === 'system' && typeof ev.content === 'string' && ev.content.trim()) {
        yield { ...base, role: 'system', text: ev.content, timestamp };
        continue;
      }
      if (type !== 'user' && type !== 'assistant') continue;
      const message = ev.message as { role?: string; content?: unknown } | undefined;
      if (!message) continue;
      const content = message.content;

      if (typeof content === 'string') {
        if (content.trim()) {
          yield { ...base, role: type === 'user' ? 'user' : 'assistant', text: content, timestamp };
        }
        continue;
      }
      if (!Array.isArray(content)) continue;

      const textParts: string[] = [];
      for (const raw of content) {
        const part = raw as ContentPart;
        if (part?.type === 'text' && typeof part.text === 'string') {
          textParts.push(part.text);
        } else if (part?.type === 'thinking' && typeof part.thinking === 'string') {
          textParts.push(part.thinking);
        } else if (part?.type === 'tool_use') {
          let inputText = '';
          try {
            inputText = JSON.stringify(part.input);
          } catch {
            inputText = '';
          }
          if (inputText && inputText !== '{}' && inputText.length > 2) {
            yield { ...base, role: 'tool', text: inputText, timestamp };
          }
        } else if (part?.type === 'tool_result') {
          const t = toolResultText(part.content);
          if (t.trim()) yield { ...base, role: 'tool', text: t, timestamp };
        }
      }
      const joined = textParts.join('\n').trim();
      if (joined) {
        const role: Role = type === 'user' ? 'user' : 'assistant';
        yield { ...base, role, text: joined, timestamp };
      }
    }
  } finally {
    rl.close();
    stream.destroy();
  }
}

/** Scan a Claude Code `projects` directory (or a single project subdir). */
export async function* messagesFromClaudeCodeDir(
  projectsDir: string,
  onFile?: (file: string) => void,
): AsyncGenerator<SourceMessage> {
  for (const file of walkFiles(projectsDir, { exts: new Set(['.jsonl']), maxDepth: 4 })) {
    onFile?.(file);
    yield* messagesFromClaudeCodeFile(file, projectsDir);
  }
}

/** Default Claude Code data dir, honoring CLAUDE_CONFIG_DIR. */
export function claudeCodeDefaultDir(): string {
  const configDir = process.env.CLAUDE_CONFIG_DIR;
  const base = configDir && configDir.trim() ? configDir : path.join(os.homedir(), '.claude');
  return path.join(base, 'projects');
}

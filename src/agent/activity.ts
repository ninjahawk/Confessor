/**
 * Reconstructs an AI coding agent's activity from its local session logs and
 * builds the forensic picture: files opened, commands run, ways off the
 * machine, and — the headline — sensitive things that entered the agent's
 * context followed by a network sink in the same session.
 *
 * Reuses the same secret detection + redaction as the chat scanner, so raw
 * secret values never reach any output here either.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as readline from 'node:readline';
import { SECRET_RULES } from '../detect/secrets.js';
import { scanText, scrubRange } from '../detect/engine.js';
import { walkFiles, toMs, collapseWs, truncate } from '../util.js';
import { prettifyProjectDir } from '../adapters/claude-code.js';
import {
  classifyPath,
  tidyPath,
  classifyCommand,
  extractHost,
  filesFromCommand,
} from './classify.js';
import type {
  AgentAudit,
  AccessedFile,
  CommandRun,
  NetworkSink,
  ExposurePath,
  FileSensitivity,
} from './types.js';

const SENS_RANK: Record<FileSensitivity, number> = { secret: 3, personal: 2, system: 1, normal: 0 };
const MAX_COMMANDS = 40;
const MAX_SINKS = 40;
const MAX_PATHS_PER_SESSION = 12;

interface ToolEvent {
  name: string;
  input: Record<string, unknown>;
  result: string;
  ts?: number;
}

interface FileAgg {
  path: string;
  sensitivity: FileSensitivity;
  label: string;
  reason: string;
  actions: Set<'read' | 'write' | 'edit'>;
  reads: number;
  writes: number;
  sessions: Set<string>;
  firstTs?: number;
  lastTs?: number;
  secretsInContent: number;
}

/** Redact any secret values inside a short text (command line, snippet). */
function redactSecrets(text: string): string {
  const spans = scanText(text, SECRET_RULES);
  const scrubbed = spans.length ? scrubRange(text, 0, text.length, spans) : text;
  return truncate(collapseWs(scrubbed), 160);
}

function toolInput(part: Record<string, unknown>): Record<string, unknown> {
  const input = part.input;
  return input && typeof input === 'object' ? (input as Record<string, unknown>) : {};
}

function resultText(content: unknown): string {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .map((p) => (typeof p === 'string' ? p : typeof (p as { text?: string })?.text === 'string' ? (p as { text?: string }).text : ''))
      .filter(Boolean)
      .join('\n');
  }
  return '';
}

/** Read one session file into an ordered list of tool events (pairing results to their tool_use by id). */
async function readSession(file: string): Promise<ToolEvent[]> {
  const events: ToolEvent[] = [];
  const pending = new Map<string, ToolEvent>();
  const stream = fs.createReadStream(file, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
  try {
    for await (const line of rl) {
      if (!line || line[0] !== '{') continue;
      let ev: Record<string, unknown>;
      try {
        ev = JSON.parse(line) as Record<string, unknown>;
      } catch {
        continue;
      }
      if (ev.type !== 'user' && ev.type !== 'assistant') continue;
      const ts = toMs(ev.timestamp);
      const message = ev.message as { content?: unknown } | undefined;
      const content = message?.content;
      if (!Array.isArray(content)) continue;
      for (const raw of content) {
        const part = raw as Record<string, unknown>;
        if (part.type === 'tool_use' && typeof part.name === 'string') {
          const te: ToolEvent = { name: part.name, input: toolInput(part), result: '', ts };
          events.push(te);
          if (typeof part.id === 'string') pending.set(part.id, te);
        } else if (part.type === 'tool_result') {
          const id = typeof part.tool_use_id === 'string' ? part.tool_use_id : '';
          const text = resultText(part.content);
          const owner = id ? pending.get(id) : undefined;
          if (owner) owner.result = text;
        }
      }
    }
  } finally {
    rl.close();
    stream.destroy();
  }
  return events;
}

const FILE_TOOLS = new Set(['Read', 'Write', 'Edit', 'NotebookEdit', 'MultiEdit']);

export interface AgentAuditOptions {
  onFile?: (file: string) => void;
}

/**
 * Analyze a Claude Code `projects` directory into an AgentAudit.
 * Returns undefined if there are no sessions to analyze.
 */
export async function auditAgentActivity(
  projectsDir: string,
  opts: AgentAuditOptions = {},
): Promise<AgentAudit | undefined> {
  if (!fs.existsSync(projectsDir)) return undefined;

  const files = new Map<string, FileAgg>();
  const commands: CommandRun[] = [];
  const sinks = new Map<string, NetworkSink>();
  const exposurePaths: ExposurePath[] = [];
  const toolCounts = new Map<string, number>();
  const projects = new Set<string>();

  let sessions = 0;
  let toolCalls = 0;
  let secretsInContext = 0;
  let firstTs: number | undefined;
  let lastTs: number | undefined;

  const bumpTs = (ts?: number): void => {
    if (!ts) return;
    if (!firstTs || ts < firstTs) firstTs = ts;
    if (!lastTs || ts > lastTs) lastTs = ts;
  };

  const touchFile = (
    rawPath: string,
    action: 'read' | 'write' | 'edit',
    sessionId: string,
    ts: number | undefined,
    secretsHere: number,
  ): FileAgg => {
    const disp = tidyPath(rawPath);
    let agg = files.get(disp);
    if (!agg) {
      const cls = classifyPath(rawPath);
      agg = {
        path: disp,
        sensitivity: cls.sensitivity,
        label: cls.label,
        reason: cls.reason,
        actions: new Set(),
        reads: 0,
        writes: 0,
        sessions: new Set(),
        secretsInContent: 0,
      };
      files.set(disp, agg);
    }
    agg.actions.add(action);
    if (action === 'read') agg.reads++;
    else agg.writes++;
    agg.sessions.add(sessionId);
    agg.secretsInContent += secretsHere;
    if (ts) {
      if (!agg.firstTs || ts < agg.firstTs) agg.firstTs = ts;
      if (!agg.lastTs || ts > agg.lastTs) agg.lastTs = ts;
    }
    return agg;
  };

  const addSink = (channel: NetworkSink['channel'], target: string, detail: string, external: boolean, ts?: number): void => {
    const key = `${channel} ${target}`;
    let s = sinks.get(key);
    if (!s) {
      s = { channel, target, detail, count: 0, external, firstTs: ts };
      sinks.set(key, s);
    }
    s.count++;
    if (ts && (!s.firstTs || ts < s.firstTs)) s.firstTs = ts;
  };

  const projDirs = fs.existsSync(projectsDir)
    ? fs.readdirSync(projectsDir, { withFileTypes: true }).filter((d) => d.isDirectory())
    : [];

  for (const file of walkFiles(projectsDir, { exts: new Set(['.jsonl']), maxDepth: 4 })) {
    opts.onFile?.(file);
    const sessionId = path.relative(projectsDir, file);
    const projDir = path.basename(path.dirname(file));
    const sessionTitle = prettifyProjectDir(projDir).split('/').filter(Boolean).pop() ?? projDir;
    projects.add(projDir);

    let events: ToolEvent[];
    try {
      events = await readSession(file);
    } catch {
      continue;
    }
    if (events.length === 0) continue;
    sessions++;

    // Sensitive events seen so far in this session, for exposure-path linking.
    const sensitiveSoFar: Array<{ label: string; detail: string; ts?: number; severity: 'critical' | 'high' }> = [];
    let sessionPaths = 0;

    for (const ev of events) {
      toolCalls++;
      toolCounts.set(ev.name, (toolCounts.get(ev.name) ?? 0) + 1);
      bumpTs(ev.ts);

      // --- secrets that entered context via this tool's result ---
      let secretsHere = 0;
      if (ev.result) {
        const spans = scanText(ev.result, SECRET_RULES);
        // unique by normalized value
        const seen = new Set<string>();
        for (const sp of spans) {
          const norm = sp.rule.normalize ? sp.rule.normalize(sp.value) : sp.value;
          if (seen.has(norm)) continue;
          seen.add(norm);
        }
        secretsHere = seen.size;
        if (secretsHere > 0) {
          secretsInContext += secretsHere;
          const firstRule = spans[0].rule;
          sensitiveSoFar.push({
            label: `${firstRule.title} in a tool result`,
            detail: `A ${firstRule.title.toLowerCase()} was returned into the agent's context`,
            ts: ev.ts,
            severity: 'critical',
          });
        }
      }

      // --- file tools ---
      if (FILE_TOOLS.has(ev.name)) {
        const fp = typeof ev.input.file_path === 'string' ? ev.input.file_path
          : typeof ev.input.path === 'string' ? (ev.input.path as string)
          : typeof ev.input.notebook_path === 'string' ? (ev.input.notebook_path as string)
          : '';
        if (fp) {
          const action = ev.name === 'Read' ? 'read' : ev.name === 'Write' ? 'write' : 'edit';
          const agg = touchFile(fp, action, sessionId, ev.ts, secretsHere);
          if (agg.sensitivity !== 'normal' && sessionPaths < MAX_PATHS_PER_SESSION) {
            sessionPaths++;
            if (action === 'read') {
              sensitiveSoFar.push({
                label: `${agg.label} (${agg.path})`,
                detail: agg.reason,
                ts: ev.ts,
                severity: agg.sensitivity === 'secret' ? 'critical' : 'high',
              });
            }
          }
        }
      }

      // --- bash commands ---
      if (ev.name === 'Bash' && typeof ev.input.command === 'string') {
        const cmd = ev.input.command as string;
        const cls = classifyCommand(cmd);
        if (cls.kind !== 'normal' && commands.length < MAX_COMMANDS) {
          commands.push({ preview: redactSecrets(cmd), kind: cls.kind, reason: cls.reason, count: 1, firstTs: ev.ts, sessionTitle });
        }
        if (cls.kind === 'network') {
          const host = extractHost(cmd);
          const target = host ? host.host : cmd.trim().split(/\s+/)[0];
          addSink('shell', target, redactSecrets(cmd), host ? host.external : true, ev.ts);
          linkExposure(exposurePaths, sensitiveSoFar, `network command (${target})`, redactSecrets(cmd), ev.ts, sessionTitle, host ? host.external : true);
        }
        for (const f of filesFromCommand(cmd)) {
          const cls2 = classifyPath(f);
          if (cls2.sensitivity !== 'normal') {
            const agg = touchFile(f, 'read', sessionId, ev.ts, 0);
            if (sessionPaths < MAX_PATHS_PER_SESSION) {
              sessionPaths++;
              sensitiveSoFar.push({ label: `${agg.label} (${agg.path})`, detail: agg.reason, ts: ev.ts, severity: agg.sensitivity === 'secret' ? 'critical' : 'high' });
            }
          }
        }
      }

      // --- web fetch / search ---
      if (ev.name === 'WebFetch' || ev.name === 'WebSearch') {
        const url = typeof ev.input.url === 'string' ? (ev.input.url as string) : typeof ev.input.query === 'string' ? `search: ${ev.input.query}` : '';
        const host = extractHost(url);
        const target = host ? host.host : ev.name === 'WebSearch' ? 'web search' : 'web';
        addSink('web', target, ev.name === 'WebSearch' ? 'a web search' : `fetched ${target}`, host ? host.external : true, ev.ts);
        linkExposure(exposurePaths, sensitiveSoFar, `web request (${target})`, ev.name === 'WebSearch' ? 'a web search' : `fetched ${target}`, ev.ts, sessionTitle, host ? host.external : true);
      }

      // --- MCP tool calls (data leaving to a server) ---
      if (ev.name.startsWith('mcp__')) {
        const parts = ev.name.split('__');
        const server = parts[1] ?? 'server';
        addSink('mcp', server, `called the "${parts.slice(2).join('/')}" tool on the ${server} server`, true, ev.ts);
        linkExposure(exposurePaths, sensitiveSoFar, `MCP server "${server}"`, `sent to the ${server} MCP server`, ev.ts, sessionTitle, true);
      }
    }
  }

  if (sessions === 0) return undefined;

  const fileList: AccessedFile[] = [...files.values()]
    .map((f) => ({
      path: f.path,
      sensitivity: f.sensitivity,
      label: f.label,
      reason: f.reason,
      actions: [...f.actions],
      reads: f.reads,
      writes: f.writes,
      sessions: f.sessions.size,
      firstTs: f.firstTs,
      lastTs: f.lastTs,
      secretsInContent: f.secretsInContent,
    }))
    .sort((a, b) => SENS_RANK[b.sensitivity] - SENS_RANK[a.sensitivity] || b.secretsInContent - a.secretsInContent || b.reads - a.reads);

  const sensitiveFiles = fileList.filter((f) => f.sensitivity !== 'normal').length;
  const sinkList = [...sinks.values()].sort((a, b) => Number(b.external) - Number(a.external) || b.count - a.count).slice(0, MAX_SINKS);
  const externalSinks = [...sinks.values()].filter((s) => s.external).length;

  // Rank exposure paths: critical first, then smallest gap (tighter = scarier).
  exposurePaths.sort((a, b) => {
    if (a.severity !== b.severity) return a.severity === 'critical' ? -1 : 1;
    return (a.gapSeconds ?? 1e9) - (b.gapSeconds ?? 1e9);
  });
  const topPaths = exposurePaths.slice(0, 25);

  const tools = [...toolCounts.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);

  const audit: AgentAudit = {
    agents: ['Claude Code'],
    sessions,
    projects: projects.size,
    toolCalls,
    tools,
    files: fileList,
    commands: commands.sort((a, b) => rankKind(b.kind) - rankKind(a.kind)),
    sinks: sinkList,
    exposurePaths: topPaths,
    counts: {
      filesTouched: fileList.length,
      sensitiveFiles,
      secretsInContext,
      networkSinks: sinks.size,
      externalSinks,
    },
    firstTs,
    lastTs,
    headline: agentHeadline(topPaths, sensitiveFiles, secretsInContext, externalSinks),
  };
  return audit;
}

function rankKind(k: CommandRun['kind']): number {
  return k === 'network' ? 3 : k === 'destructive' ? 2 : k === 'privileged' ? 1 : 0;
}

/** Link the most recent sensitive event to a sink that just fired. */
function linkExposure(
  out: ExposurePath[],
  sensitiveSoFar: Array<{ label: string; detail: string; ts?: number; severity: 'critical' | 'high' }>,
  sink: string,
  sinkDetail: string,
  sinkTs: number | undefined,
  sessionTitle: string,
  external: boolean,
): void {
  if (!external || sensitiveSoFar.length === 0) return;
  const src = sensitiveSoFar[sensitiveSoFar.length - 1];
  // Avoid pairing a source with a sink that is clearly part of the same instant already recorded.
  const gap = src.ts && sinkTs ? Math.max(0, Math.round((sinkTs - src.ts) / 1000)) : undefined;
  out.push({
    severity: src.severity === 'critical' ? 'critical' : 'high',
    source: src.label,
    sourceDetail: src.detail,
    sourceTs: src.ts,
    sink,
    sinkDetail,
    sinkTs,
    sessionTitle,
    gapSeconds: gap,
  });
}

function agentHeadline(paths: ExposurePath[], sensitiveFiles: number, secrets: number, externalSinks: number): string | undefined {
  if (paths.length > 0) {
    const p = paths[0];
    return `In one session your AI agent opened ${p.source.replace(/\s*\(.*\)$/, '').toLowerCase()}, then reached the network — worth a look at whether anything left.`;
  }
  if (secrets > 0) {
    return `${secrets} secret${secrets === 1 ? '' : 's'} passed through your AI agent's context while it worked.`;
  }
  if (sensitiveFiles > 0) {
    return `Your AI agent opened ${sensitiveFiles} sensitive file${sensitiveFiles === 1 ? '' : 's'} while working on your projects.`;
  }
  if (externalSinks > 0) {
    return `Your AI agent made requests to ${externalSinks} external destination${externalSinks === 1 ? '' : 's'}.`;
  }
  return undefined;
}

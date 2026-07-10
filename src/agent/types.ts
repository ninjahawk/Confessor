/**
 * Data model for the agent-activity forensics: what an AI coding agent
 * (Claude Code today) actually did on your machine — which files it opened,
 * which commands it ran, where it could have sent data, and whether any
 * sensitive read was followed by a way off the machine.
 *
 * This is reconstructed from logs that already exist on disk. No wrapper, no
 * daemon, no network — the same trust story as the rest of the tool.
 */
import type { Severity } from '../types.js';

/** How sensitive a touched path is, and why. */
export type FileSensitivity = 'secret' | 'personal' | 'system' | 'normal';

export interface SensitiveClass {
  sensitivity: FileSensitivity;
  /** e.g. 'SSH private key', 'environment file', 'tax document' */
  label: string;
  /** the matched reason, for the "why flagged" line */
  reason: string;
}

/** A file the agent read, wrote, or edited. */
export interface AccessedFile {
  /** displayed path (may be redacted of a home-dir username) */
  path: string;
  sensitivity: FileSensitivity;
  label: string;
  reason: string;
  /** how the agent touched it */
  actions: Array<'read' | 'write' | 'edit'>;
  reads: number;
  writes: number;
  /** unique sessions this path appeared in */
  sessions: number;
  firstTs?: number;
  lastTs?: number;
  /** secret findings whose value appeared in a tool result tied to this file */
  secretsInContent: number;
}

/** A shell command the agent executed. */
export interface CommandRun {
  /** redacted, single-line preview of the command */
  preview: string;
  /** 'network' commands can move data off the machine */
  kind: 'network' | 'destructive' | 'privileged' | 'normal';
  reason?: string;
  count: number;
  firstTs?: number;
  sessionTitle: string;
}

/** A place data could leave the machine: web fetch, MCP call, or network shell command. */
export interface NetworkSink {
  /** 'web' (WebFetch/WebSearch), 'shell' (curl/scp/…), 'mcp' (tool call to a server) */
  channel: 'web' | 'shell' | 'mcp';
  /** redacted destination — host or tool name */
  target: string;
  detail: string;
  count: number;
  firstTs?: number;
  external: boolean;
}

/**
 * The headline artifact: a sensitive thing entered the agent's context (a
 * secret in a tool result, or a read of a sensitive file), and later in the
 * same session a way off the machine was used. Not proof of exfiltration —
 * a lead worth looking at, which is exactly the question users ask.
 */
export interface ExposurePath {
  severity: Severity;
  /** what sensitive thing was exposed */
  source: string;
  sourceDetail: string;
  sourceTs?: number;
  /** the sink that followed */
  sink: string;
  sinkDetail: string;
  sinkTs?: number;
  sessionTitle: string;
  /** seconds between the read and the sink, when both are dated */
  gapSeconds?: number;
}

export interface AgentTool {
  name: string;
  count: number;
}

export interface AgentAudit {
  /** which agents were analyzed */
  agents: string[];
  sessions: number;
  projects: number;
  toolCalls: number;
  /** distinct tools used, most-used first */
  tools: AgentTool[];
  files: AccessedFile[];
  commands: CommandRun[];
  sinks: NetworkSink[];
  exposurePaths: ExposurePath[];
  counts: {
    filesTouched: number;
    sensitiveFiles: number;
    secretsInContext: number;
    networkSinks: number;
    externalSinks: number;
  };
  firstTs?: number;
  lastTs?: number;
  /** one-line human summary for the hero */
  headline?: string;
}

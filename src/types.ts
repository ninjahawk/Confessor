/** Core data model shared by adapters, the detection engine, and the report. */
import type { AgentAudit } from './agent/types.js';

export type { AgentAudit } from './agent/types.js';

export type Provider = 'claude-code' | 'chatgpt' | 'claude' | 'gemini' | 'generic';

export const PROVIDER_LABELS: Record<Provider, string> = {
  'claude-code': 'Claude Code',
  chatgpt: 'ChatGPT',
  claude: 'Claude.ai',
  gemini: 'Gemini',
  generic: 'Files',
};

export type Role = 'user' | 'assistant' | 'tool' | 'system';

export type Severity = 'critical' | 'high' | 'medium';

export type CategoryId =
  | 'health'
  | 'mental-health'
  | 'legal'
  | 'financial'
  | 'employment'
  | 'relationships'
  | 'identity';

export const CATEGORY_LABELS: Record<CategoryId, string> = {
  health: 'Health',
  'mental-health': 'Mental health',
  legal: 'Legal',
  financial: 'Financial',
  employment: 'Employment',
  relationships: 'Relationships & family',
  identity: 'Identity',
};

/** One message extracted from a chat history source. */
export interface SourceMessage {
  provider: Provider;
  conversationId: string;
  conversationTitle: string;
  role: Role;
  text: string;
  /** ms since epoch, when known */
  timestamp?: number;
  meta?: { project?: string; file?: string };
}

/** Where a finding occurred. */
export interface Occurrence {
  provider: Provider;
  conversationId: string;
  conversationTitle: string;
  timestamp?: number;
  role: Role;
}

/** A deduplicated detection result. Previews are ALWAYS redacted before they land here. */
export interface Finding {
  /** stable id derived from type + normalized value */
  id: string;
  layer: 1 | 2 | 3;
  severity: Severity;
  /** machine type, e.g. 'aws-access-key-id', 'email', 'category:health' */
  type: string;
  /** human-readable, e.g. 'AWS access key ID' */
  title: string;
  /** redacted context preview (never contains the raw secret) */
  preview: string;
  remediation?: string;
  /** total occurrences across all messages */
  count: number;
  firstSeen?: Occurrence;
  /** sample occurrences, capped */
  occurrences: Occurrence[];
  providers: Provider[];
  /** layer 3 only */
  category?: CategoryId;
  /** layer 3 only: redacted example sentences, capped */
  examples?: string[];
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
}

export interface ProviderStats {
  provider: Provider;
  label: string;
  conversations: number;
  messages: number;
  counts: SeverityCounts;
  score: number;
  grade: string;
}

export interface WorstConversation {
  provider: Provider;
  conversationId: string;
  title: string;
  firstTimestamp?: number;
  lastTimestamp?: number;
  counts: SeverityCounts;
  score: number;
}

/** Timeline groups: layer 1 & 2 pseudo-groups plus every category. */
export type TimelineGroup = 'secrets' | 'pii' | CategoryId;

export interface TimelinePoint {
  /** 'YYYY-MM' */
  month: string;
  counts: Partial<Record<TimelineGroup, number>>;
  total: number;
}

export interface ScanResult {
  schemaVersion: 1;
  tool: string;
  version: string;
  generatedAt: string;
  stats: {
    messages: number;
    conversations: number;
    providers: Provider[];
    counts: SeverityCounts;
    score: number;
    grade: string;
  };
  perProvider: ProviderStats[];
  findings: Finding[];
  timeline: TimelinePoint[];
  worstConversations: WorstConversation[];
  /** e.g. "You first introduced yourself by name to ChatGPT on Mar 3, 2023." */
  headline?: string;
  /** Present when Claude Code (or another agent) logs were analyzed. */
  agent?: AgentAudit;
}

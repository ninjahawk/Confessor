import type { Severity } from '../types.js';

/**
 * A detection rule for layers 1 (secrets) and 2 (structured PII).
 * Rules are pure data + small functions so the full set is auditable at a glance.
 */
export interface MatchRule {
  id: string;
  title: string;
  severity: Severity;
  layer: 1 | 2;
  /** Must be constructed with the `g` and `d` flags. */
  pattern: RegExp;
  /** Capture group holding the sensitive value; defaults to the whole match. */
  group?: number;
  /**
   * Cheap lowercase substring gates checked before running the regex.
   * If provided, at least one must appear in the message (lowercased).
   */
  prefilter?: string[];
  /** Required context within ±100 chars of the match (e.g. the word 'ssn'). */
  context?: RegExp;
  /** Final structural/entropy validation. */
  validate?: (value: string, full: string, start: number) => boolean;
  /** Canonical form used for deduplication (defaults to the raw value). */
  normalize?: (value: string) => string;
  /** Redactor — every stored preview passes through this. */
  redact: (value: string) => string;
  /** Dynamic title, e.g. card brand. */
  describe?: (value: string) => string;
  remediation?: string;
  /** Higher priority wins when spans overlap. */
  priority: number;
}

export interface SpanMatch {
  start: number;
  end: number;
  value: string;
  rule: MatchRule;
}

const CONTEXT_WINDOW = 100;

/**
 * Run every rule over the text, resolve overlaps by priority
 * (specific beats generic; layer 1 beats layer 2), return spans sorted by start.
 */
export function scanText(text: string, rules: MatchRule[]): SpanMatch[] {
  if (!text) return [];
  const lower = text.toLowerCase();
  const candidates: SpanMatch[] = [];

  for (const rule of rules) {
    if (rule.prefilter && !rule.prefilter.some((p) => lower.includes(p))) continue;
    rule.pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    let guard = 0;
    while ((m = rule.pattern.exec(text)) !== null) {
      if (++guard > 10000) break; // runaway safety
      if (m[0].length === 0) {
        rule.pattern.lastIndex++;
        continue;
      }
      const g = rule.group ?? 0;
      const value = m[g];
      if (!value) continue;
      let start: number;
      let end: number;
      const idx = m.indices?.[g];
      if (idx) {
        [start, end] = idx;
      } else {
        const rel = g === 0 ? 0 : Math.max(0, m[0].indexOf(value));
        start = m.index + rel;
        end = start + value.length;
      }
      if (rule.context) {
        const ctx = text.slice(Math.max(0, start - CONTEXT_WINDOW), Math.min(text.length, end + CONTEXT_WINDOW));
        if (!rule.context.test(ctx)) continue;
      }
      if (rule.validate && !rule.validate(value, text, start)) continue;
      candidates.push({ start, end, value, rule });
    }
  }

  // Priority sweep: higher priority first; ties → earlier, then longer.
  candidates.sort(
    (a, b) =>
      b.rule.priority - a.rule.priority || a.start - b.start || b.end - b.start - (a.end - a.start),
  );
  const kept: SpanMatch[] = [];
  for (const c of candidates) {
    let overlaps = false;
    for (const k of kept) {
      if (c.start < k.end && k.start < c.end) {
        overlaps = true;
        break;
      }
    }
    if (!overlaps) kept.push(c);
  }
  kept.sort((a, b) => a.start - b.start);
  return kept;
}

/**
 * Return `text[from..to)` with any overlapping match spans replaced by their
 * redacted form. Used to build previews so a preview for finding A can never
 * leak the raw value of finding B sitting next to it.
 */
export function scrubRange(text: string, from: number, to: number, spans: SpanMatch[]): string {
  let out = '';
  let cursor = from;
  for (const s of spans) {
    if (s.end <= from || s.start >= to) continue;
    if (s.start > cursor) out += text.slice(cursor, Math.min(s.start, to));
    // Span may start before the range; either way, emit the redacted form once.
    out += s.rule.redact(s.value);
    cursor = Math.max(cursor, s.end);
    if (cursor >= to) break;
  }
  if (cursor < to) out += text.slice(cursor, to);
  return out;
}

/** Build the redacted context preview for one span. */
export function buildPreview(text: string, span: SpanMatch, allSpans: SpanMatch[], ctx = 48): string {
  const others = allSpans.filter((s) => s !== span);
  const ws = Math.max(0, span.start - ctx);
  const we = Math.min(text.length, span.end + ctx);
  const before = scrubRange(text, ws, span.start, others);
  const after = scrubRange(text, span.end, we, others);
  const core = span.rule.redact(span.value);
  const prefix = ws > 0 ? '…' : '';
  const suffix = we < text.length ? '…' : '';
  let preview = `${prefix}${before}${core}${after}${suffix}`;
  preview = preview.replace(/\s+/g, ' ').trim();
  if (preview.length > 240) preview = preview.slice(0, 239) + '…';
  return preview;
}

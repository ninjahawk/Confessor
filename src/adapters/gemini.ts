/**
 * Gemini adapter (beta): parses Google Takeout "My Activity" for Gemini Apps,
 * either the JSON or the HTML flavor. Takeout only records your prompts (and
 * timestamps), not Gemini's replies — best-effort by design.
 */
import type { SourceMessage } from '../types.js';
import { decodeEntities, toMs } from '../util.js';

interface ActivityItem {
  header?: string;
  title?: string;
  time?: string;
}

const CONVERSATION_ID = 'gemini-activity';
const CONVERSATION_TITLE = 'Gemini Apps activity';

function promptFromTitle(title: string): string | null {
  const stripped = title.replace(/^Prompted\s+/i, '');
  if (stripped === title) return null; // "Used Gemini Apps" etc. carry no content
  return stripped.trim() || null;
}

export function looksLikeGeminiJson(data: unknown): data is ActivityItem[] {
  return (
    Array.isArray(data) &&
    data.length > 0 &&
    typeof data[0] === 'object' &&
    data[0] !== null &&
    'title' in (data[0] as object) &&
    ('header' in (data[0] as object) || 'time' in (data[0] as object))
  );
}

export function* messagesFromGeminiJson(data: ActivityItem[]): Generator<SourceMessage> {
  for (const item of data) {
    if (typeof item.title !== 'string') continue;
    const prompt = promptFromTitle(item.title);
    if (!prompt) continue;
    yield {
      provider: 'gemini',
      conversationId: CONVERSATION_ID,
      conversationTitle: CONVERSATION_TITLE,
      role: 'user',
      text: prompt,
      timestamp: toMs(item.time),
    };
  }
}

function parseLooseDate(s: string): number | undefined {
  const direct = Date.parse(s);
  if (!Number.isNaN(direct)) return direct;
  // Retry without a trailing timezone abbreviation ("… PM EST").
  const noTz = s.replace(/\s+[A-Z]{2,5}$/, '');
  const retry = Date.parse(noTz);
  return Number.isNaN(retry) ? undefined : retry;
}

/** Best-effort extraction from the Takeout MyActivity.html format. */
export function* messagesFromGeminiHtml(html: string): Generator<SourceMessage> {
  const cellRe = /<div[^>]*class="[^"]*content-cell[^"]*mdl-typography--body-1[^"]*"[^>]*>([\s\S]*?)<\/div>/g;
  let m: RegExpExecArray | null;
  while ((m = cellRe.exec(html)) !== null) {
    const inner = m[1];
    if (/mdl-typography--caption/.test(inner)) continue;
    const text = decodeEntities(
      inner
        .replace(/<br\s*\/?>/gi, '\n')
        .replace(/<[^>]+>/g, '')
        .replace(/\r/g, ''),
    )
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
    if (text.length === 0) continue;
    const first = text[0];
    const prompt = promptFromTitle(first);
    if (!prompt) continue;
    // The last line is usually the timestamp.
    const last = text[text.length - 1];
    const ts = last && last !== first ? parseLooseDate(last) : undefined;
    yield {
      provider: 'gemini',
      conversationId: CONVERSATION_ID,
      conversationTitle: CONVERSATION_TITLE,
      role: 'user',
      text: prompt,
      timestamp: ts,
    };
  }
}

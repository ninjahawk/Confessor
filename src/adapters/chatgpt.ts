/**
 * ChatGPT export adapter: parses `conversations.json` from the official
 * data export (Settings → Data controls → Export data).
 */
import type { SourceMessage, Role } from '../types.js';
import { toMs } from '../util.js';

interface GptAuthor {
  role?: string;
}
interface GptContent {
  content_type?: string;
  parts?: unknown[];
  text?: string;
  thoughts?: Array<{ summary?: string; content?: string }>;
  user_profile?: string;
  user_instructions?: string;
}
interface GptMessage {
  author?: GptAuthor;
  content?: GptContent;
  create_time?: number;
}
interface GptNode {
  message?: GptMessage | null;
}
interface GptConversation {
  id?: string;
  conversation_id?: string;
  title?: string;
  create_time?: number;
  mapping?: Record<string, GptNode>;
}

function contentText(c: GptContent | undefined): string {
  if (!c) return '';
  switch (c.content_type) {
    case 'text':
    case 'multimodal_text': {
      const parts = Array.isArray(c.parts) ? c.parts : [];
      return parts
        .map((p) => {
          if (typeof p === 'string') return p;
          if (p && typeof p === 'object' && typeof (p as { text?: unknown }).text === 'string') {
            return (p as { text: string }).text;
          }
          return '';
        })
        .filter(Boolean)
        .join('\n');
    }
    case 'code':
    case 'execution_output':
      return typeof c.text === 'string' ? c.text : '';
    case 'thoughts':
      return (c.thoughts ?? [])
        .map((t) => [t.summary, t.content].filter(Boolean).join('\n'))
        .join('\n');
    case 'user_editable_context':
      // Custom instructions / profile — user-authored and often very personal.
      return [c.user_profile, c.user_instructions].filter((s) => typeof s === 'string').join('\n');
    default: {
      const parts = Array.isArray(c.parts) ? c.parts : [];
      return parts.filter((p): p is string => typeof p === 'string').join('\n');
    }
  }
}

export function looksLikeChatGptExport(data: unknown): data is GptConversation[] {
  return Array.isArray(data) && data.length > 0 && typeof data[0] === 'object' && data[0] !== null && 'mapping' in (data[0] as object);
}

export function* messagesFromChatGpt(data: GptConversation[]): Generator<SourceMessage> {
  let idx = 0;
  for (const conv of data) {
    idx++;
    const conversationId = conv.conversation_id ?? conv.id ?? `chatgpt-${idx}`;
    const conversationTitle = conv.title?.trim() || 'Untitled conversation';
    const fallbackTs = toMs(conv.create_time);
    const nodes = Object.values(conv.mapping ?? {});
    const messages: Array<{ role: Role; text: string; ts?: number }> = [];
    for (const node of nodes) {
      const m = node?.message;
      if (!m) continue;
      const authorRole = m.author?.role;
      let role: Role;
      if (authorRole === 'user') role = 'user';
      else if (authorRole === 'assistant') role = 'assistant';
      else if (authorRole === 'tool') role = 'tool';
      else continue; // system prompts are OpenAI's, not the user's disclosure
      const text = contentText(m.content).trim();
      if (!text) continue;
      messages.push({ role, text, ts: toMs(m.create_time) ?? fallbackTs });
    }
    messages.sort((a, b) => (a.ts ?? 0) - (b.ts ?? 0));
    for (const m of messages) {
      yield {
        provider: 'chatgpt',
        conversationId,
        conversationTitle,
        role: m.role,
        text: m.text,
        timestamp: m.ts,
      };
    }
  }
}

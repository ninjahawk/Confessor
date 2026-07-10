/**
 * Claude.ai export adapter: parses `conversations.json` from the Anthropic
 * data export (Settings → Privacy → Export data).
 */
import type { SourceMessage } from '../types.js';
import { toMs } from '../util.js';

interface ClaudeContentPart {
  type?: string;
  text?: string;
}
interface ClaudeMessage {
  sender?: string;
  text?: string;
  content?: ClaudeContentPart[];
  created_at?: string;
}
interface ClaudeConversation {
  uuid?: string;
  name?: string;
  created_at?: string;
  chat_messages?: ClaudeMessage[];
}

export function looksLikeClaudeExport(data: unknown): data is ClaudeConversation[] {
  return (
    Array.isArray(data) &&
    data.length > 0 &&
    typeof data[0] === 'object' &&
    data[0] !== null &&
    'chat_messages' in (data[0] as object)
  );
}

function messageText(m: ClaudeMessage): string {
  if (Array.isArray(m.content) && m.content.length > 0) {
    const joined = m.content
      .map((p) => (p && p.type === 'text' && typeof p.text === 'string' ? p.text : ''))
      .filter(Boolean)
      .join('\n');
    if (joined.trim()) return joined;
  }
  return typeof m.text === 'string' ? m.text : '';
}

export function* messagesFromClaudeAi(data: ClaudeConversation[]): Generator<SourceMessage> {
  let idx = 0;
  for (const conv of data) {
    idx++;
    const conversationId = conv.uuid ?? `claude-${idx}`;
    const conversationTitle = conv.name?.trim() || 'Untitled conversation';
    const fallbackTs = toMs(conv.created_at);
    for (const m of conv.chat_messages ?? []) {
      const text = messageText(m).trim();
      if (!text) continue;
      yield {
        provider: 'claude',
        conversationId,
        conversationTitle,
        role: m.sender === 'human' ? 'user' : 'assistant',
        text,
        timestamp: toMs(m.created_at) ?? fallbackTs,
      };
    }
  }
}

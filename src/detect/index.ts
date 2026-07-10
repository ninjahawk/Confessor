import { SECRET_RULES } from './secrets.js';
import { PII_RULES } from './pii.js';
import { scanText, type SpanMatch, type MatchRule } from './engine.js';
import { scanCategories, type CategoryHit } from './categories.js';

export { SECRET_RULES } from './secrets.js';
export { PII_RULES } from './pii.js';
export { scanText, scrubRange, buildPreview } from './engine.js';
export type { SpanMatch, MatchRule } from './engine.js';
export { scanCategories } from './categories.js';
export type { CategoryHit } from './categories.js';

export const ALL_RULES: MatchRule[] = [...SECRET_RULES, ...PII_RULES];

export interface MessageDetections {
  spans: SpanMatch[];
  categories: CategoryHit[];
}

/** Run all three layers over one message body. Layer 3 runs only for user-authored text. */
export function detectMessage(text: string, role: 'user' | 'assistant' | 'tool' | 'system'): MessageDetections {
  const spans = scanText(text, ALL_RULES);
  const categories = role === 'user' ? scanCategories(text) : [];
  return { spans, categories };
}

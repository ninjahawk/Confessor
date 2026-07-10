import type { CategoryId } from '../types.js';
import {
  MEDICATIONS,
  MENTAL_MEDS,
  HEALTH_CONDITIONS,
  HEALTH_SELF,
  MENTAL_TERMS,
  MENTAL_SELF,
  LEGAL_TERMS,
  LEGAL_SELF,
  FINANCIAL_TERMS,
  FINANCIAL_SELF,
  EMPLOYMENT_TERMS,
  EMPLOYMENT_SELF,
  RELATIONSHIP_TERMS,
  RELATIONSHIP_SELF,
  IDENTITY_SELF,
} from './lexicons.js';

export interface CategoryHit {
  category: CategoryId;
  /** which phrase/pattern fired, for the report */
  trigger: string;
  sentenceStart: number;
  sentenceEnd: number;
  /** identity hits that captured an actual full name (drives the headline stat) */
  hasName?: boolean;
}

/**
 * First-person markers. Layer 3 requires them in the same sentence unless the
 * trigger phrase is inherently first-person ("my therapist"). This is the main
 * false-positive guard: asking *about* a topic is not disclosing it.
 */
const FIRST_PERSON = /\b(?:i|i'm|i've|i'd|i'll|im|my|me|mine|we|our|us)\b/i;

interface RegexTrigger {
  re: RegExp;
  label: string;
  selfSufficient?: boolean;
  hasName?: boolean;
}

interface CategoryDef {
  id: CategoryId;
  /** phrases sufficient alone */
  self: string[];
  /** phrases that need a first-person marker in the sentence */
  gated: string[];
  regexes?: RegexTrigger[];
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Compile a phrase list into one word-boundary alternation regex. */
function phraseRe(phrases: string[]): RegExp | null {
  if (phrases.length === 0) return null;
  const sorted = [...phrases].sort((a, b) => b.length - a.length);
  return new RegExp(`\\b(?:${sorted.map(escapeRe).join('|')})\\b`, 'i');
}

/** Common capitalized non-name words after "I'm …" ("I'm Getting Started"). */
const NOT_NAMES =
  /^(?:Getting|Going|Just|Not|Really|Sorry|Sure|Still|Also|Actually|Trying|Looking|Working|Making|Thinking|Very|Pretty|Kind|Currently|Now|Almost|Already|Finally|Done|Glad|Happy|New|Using|Running|Building|Writing|Testing|Doing|Having|Being|Feeling|Seeing|Asking|Wondering|Curious|Afraid|Aware|Certain|Confident|Familiar|Interested|Learning|Starting|Beginning|Assuming|Guessing|Hoping|Planning|Excited|Good|Fine|Okay|Only|Quite|Rather|Slightly|Somewhat|Totally|Definitely|Probably|Mostly|Mainly|Simply|Merely|Deeply|Honestly|Genuinely|The|That|This|Then|There|Here)$/;

const MONEY_RE = /\$\s?\d{1,3}(?:,\d{3})+(?:\.\d{2})?|\$\d{4,7}\b|\b\d{2,3}k\b/i;
const MONEY_CONTEXT = /\b(?:salar|income|debt|owe|sav(?:e|ing)|balance|rent|mortgage|loan|paycheck|bonus|net worth|401k|retirement|pay|earn|make|making|spent|budget)/i;

const CATEGORY_DEFS: CategoryDef[] = [
  {
    id: 'health',
    self: HEALTH_SELF,
    gated: [...HEALTH_CONDITIONS, ...MEDICATIONS],
  },
  {
    id: 'mental-health',
    self: MENTAL_SELF,
    gated: [...MENTAL_TERMS, ...MENTAL_MEDS],
  },
  {
    id: 'legal',
    self: LEGAL_SELF,
    gated: LEGAL_TERMS,
  },
  {
    id: 'financial',
    self: FINANCIAL_SELF,
    gated: FINANCIAL_TERMS,
  },
  {
    id: 'employment',
    self: EMPLOYMENT_SELF,
    gated: EMPLOYMENT_TERMS,
  },
  {
    id: 'relationships',
    self: RELATIONSHIP_SELF,
    gated: RELATIONSHIP_TERMS,
  },
  {
    id: 'identity',
    self: IDENTITY_SELF,
    gated: [],
    regexes: [
      {
        re: /\b[Mm]y (?:full |real |legal )?name(?:'s| is)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)/,
        label: 'my name is …',
        selfSufficient: true,
        hasName: true,
      },
      {
        re: /\bI(?:'m| am)\s+([A-Z][a-z]{2,})\s+([A-Z][a-z]{2,})\b/,
        label: 'self-introduction',
        selfSufficient: true,
        hasName: true,
      },
      {
        re: /\bI work (?:at|for)\s+([A-Z][\w&.'-]{2,30})/,
        label: 'employer disclosure',
        selfSufficient: true,
      },
      {
        re: /\bI live (?:in|at|on|near)\s+([A-Z][A-Za-z .,'-]{2,40})/,
        label: 'location disclosure',
        selfSufficient: true,
      },
      {
        re: /\bI(?:'m| am)\s+(\d{2})\s+years old\b/,
        label: 'age disclosure',
        selfSufficient: true,
      },
    ],
  },
];

interface CompiledCategory {
  id: CategoryId;
  selfRe: RegExp | null;
  gatedRe: RegExp | null;
  regexes: RegexTrigger[];
}

const COMPILED: CompiledCategory[] = CATEGORY_DEFS.map((d) => ({
  id: d.id,
  selfRe: phraseRe(d.self),
  gatedRe: phraseRe(d.gated),
  regexes: d.regexes ?? [],
}));

/** Cheap prefilter: don't sentence-split messages that can't possibly hit. */
const ANY_HINT = /\b(?:my|i|me|our|we)\b/i;

const SENTENCE_RE = /[^.!?\n\r]+[.!?]?/g;

/**
 * Layer 3: scan a user message for sensitive disclosure categories.
 * At most one hit per category per sentence.
 */
export function scanCategories(text: string): CategoryHit[] {
  if (!text || text.length < 8) return [];
  if (!ANY_HINT.test(text)) return [];
  const hits: CategoryHit[] = [];

  SENTENCE_RE.lastIndex = 0;
  let sm: RegExpExecArray | null;
  while ((sm = SENTENCE_RE.exec(text)) !== null) {
    const sentence = sm[0];
    if (sentence.trim().length < 8) continue;
    const sStart = sm.index;
    const sEnd = sm.index + sentence.length;
    // Very long "sentences" are usually pasted code/data — match on a window.
    const probe = sentence.length > 1200 ? sentence.slice(0, 1200) : sentence;
    const hasFp = FIRST_PERSON.test(probe);

    for (const cat of COMPILED) {
      let trigger: string | null = null;
      let hasName = false;

      // Regex triggers first: the name-capturing identity patterns must win
      // over plain phrase matches so `hasName` (→ headline stat) is recorded.
      for (const rt of cat.regexes) {
        if (!rt.selfSufficient && !hasFp) continue;
        const m = probe.match(rt.re);
        if (m) {
          if (rt.hasName && m[1] && NOT_NAMES.test(m[1].split(/\s+/)[0] ?? '')) continue;
          trigger = rt.label;
          hasName = Boolean(rt.hasName);
          break;
        }
      }
      if (!trigger && cat.selfRe) {
        const m = probe.match(cat.selfRe);
        if (m) trigger = m[0].toLowerCase();
      }
      if (!trigger && hasFp && cat.gatedRe) {
        const m = probe.match(cat.gatedRe);
        if (m) trigger = m[0].toLowerCase();
      }
      // Financial extra: money amounts + finance context + first person.
      if (!trigger && cat.id === 'financial' && hasFp && MONEY_RE.test(probe) && MONEY_CONTEXT.test(probe)) {
        trigger = 'money amount in context';
      }

      if (trigger) {
        hits.push({ category: cat.id, trigger, sentenceStart: sStart, sentenceEnd: sEnd, hasName });
      }
    }
  }
  return hits;
}

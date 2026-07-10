import * as fs from 'node:fs';
import * as path from 'node:path';

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/** Number of distinct character classes (lower/upper/digit/other) present. */
export function charClasses(s: string): number {
  let n = 0;
  if (/[a-z]/.test(s)) n++;
  if (/[A-Z]/.test(s)) n++;
  if (/\d/.test(s)) n++;
  if (/[^a-zA-Z0-9]/.test(s)) n++;
  return n;
}

/** FNV-1a 32-bit hash, hex encoded. Used for stable finding ids — not cryptographic. */
export function fnv1a(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, '0');
}

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Collapse all whitespace runs (incl. newlines) into single spaces. */
export function collapseWs(s: string): string {
  return s.replace(/\s+/g, ' ').trim();
}

export function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + '…';
}

const NUM_FMT = new Intl.NumberFormat('en-US');
export function comma(n: number): string {
  return NUM_FMT.format(n);
}

const DATE_FMT = new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
export function formatDate(ts?: number): string {
  if (!ts || !Number.isFinite(ts)) return 'unknown date';
  try {
    return DATE_FMT.format(new Date(ts));
  } catch {
    return 'unknown date';
  }
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** 'YYYY-MM' key for a timestamp, or undefined when unknown. */
export function monthKey(ts?: number): string | undefined {
  if (!ts || !Number.isFinite(ts)) return undefined;
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return undefined;
  const y = d.getUTCFullYear();
  if (y < 2000 || y > 2100) return undefined;
  return `${y}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
}

/** 'YYYY-MM' → 'Mar 2024' */
export function formatMonth(key: string): string {
  const [y, m] = key.split('-');
  const mi = Number(m) - 1;
  return `${MONTHS[mi] ?? m} ${y}`;
}

/** Months between two 'YYYY-MM' keys inclusive, in order. */
export function monthRange(from: string, to: string): string[] {
  const out: string[] = [];
  let [y, m] = from.split('-').map(Number);
  const [ey, em] = to.split('-').map(Number);
  while (y < ey || (y === ey && m <= em)) {
    out.push(`${y}-${String(m).padStart(2, '0')}`);
    m++;
    if (m > 12) {
      m = 1;
      y++;
    }
    if (out.length > 600) break; // safety valve
  }
  return out;
}

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'venv']);

/** Recursively walk files under a root. Skips symlinks and junk dirs. Deterministic order. */
export function* walkFiles(root: string, opts?: { exts?: Set<string>; maxDepth?: number }): Generator<string> {
  const maxDepth = opts?.maxDepth ?? 16;
  function* walk(dir: string, depth: number): Generator<string> {
    if (depth > maxDepth) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        yield* walk(full, depth + 1);
      } else if (e.isFile()) {
        if (opts?.exts && !opts.exts.has(path.extname(e.name).toLowerCase())) continue;
        yield full;
      }
    }
  }
  yield* walk(root, 0);
}

/** Decode a minimal set of HTML entities (for the Gemini Takeout HTML adapter). */
export function decodeEntities(s: string): string {
  const named: Record<string, string> = {
    amp: '&',
    lt: '<',
    gt: '>',
    quot: '"',
    apos: "'",
    nbsp: ' ',
    mdash: '—',
    ndash: '–',
    hellip: '…',
    rsquo: '’',
    lsquo: '‘',
    rdquo: '”',
    ldquo: '“',
  };
  return s.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (whole, ent: string) => {
    if (ent.startsWith('#x') || ent.startsWith('#X')) {
      const code = parseInt(ent.slice(2), 16);
      return Number.isFinite(code) ? String.fromCodePoint(code) : whole;
    }
    if (ent.startsWith('#')) {
      const code = parseInt(ent.slice(1), 10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : whole;
    }
    return named[ent] ?? whole;
  });
}

/** Parse an ISO or unix-ish timestamp into ms since epoch. */
export function toMs(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    // Heuristic: seconds vs milliseconds.
    return value > 1e12 ? value : value * 1000;
  }
  if (typeof value === 'string' && value) {
    const t = Date.parse(value);
    return Number.isNaN(t) ? undefined : t;
  }
  return undefined;
}

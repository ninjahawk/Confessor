import type { SeverityCounts, Severity } from './types.js';

/** Simple weighted count, as promised in the report: no ML, no magic. */
export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 10,
  high: 3,
  medium: 1,
};

export function computeScore(c: SeverityCounts): number {
  return c.critical * SEVERITY_WEIGHTS.critical + c.high * SEVERITY_WEIGHTS.high + c.medium * SEVERITY_WEIGHTS.medium;
}

export function grade(score: number): string {
  if (score === 0) return 'A+';
  if (score < 10) return 'A';
  if (score < 25) return 'B';
  if (score < 60) return 'C';
  if (score < 120) return 'D';
  return 'F';
}

export function gradeColor(g: string): string {
  switch (g) {
    case 'A+':
    case 'A':
      return '#34c759';
    case 'B':
      return '#92c73a';
    case 'C':
      return '#ff9500';
    case 'D':
      return '#ff6b22';
    default:
      return '#ff3b30';
  }
}

export const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2 };

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#ff3b30',
  high: '#ff9500',
  medium: '#007aff',
};

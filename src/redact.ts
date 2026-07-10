/**
 * Redaction helpers. THE core promise of this tool: the report and all output
 * previews never reprint a secret or identifier in full. Every detection rule
 * routes its matched value through one of these before anything is stored.
 */

/** Keep first/last `keep` chars, mask the middle. Short values are fully masked. */
export function redactMiddle(v: string, keep = 4): string {
  if (v.length <= keep * 2) return '•'.repeat(Math.max(v.length, 4));
  const stars = Math.min(v.length - keep * 2, 12);
  return v.slice(0, keep) + '•'.repeat(stars) + v.slice(-keep);
}

export function maskDigits(s: string): string {
  return s.replace(/\d/g, '•');
}

export function redactEmail(v: string): string {
  const at = v.indexOf('@');
  if (at <= 0) return redactMiddle(v);
  const local = v.slice(0, at);
  const domain = v.slice(at + 1);
  return `${local[0]}•••@${domain}`;
}

export function redactCard(v: string): string {
  const d = v.replace(/\D/g, '');
  return `•••• •••• •••• ${d.slice(-4)}`;
}

export function redactSsn(v: string): string {
  const d = v.replace(/\D/g, '');
  return `•••-••-${d.slice(-4)}`;
}

export function redactIban(v: string): string {
  const s = v.replace(/\s/g, '');
  return `${s.slice(0, 2)}•• ···· ${s.slice(-4)}`;
}

export function redactPhone(v: string): string {
  const d = v.replace(/\D/g, '');
  return `•••-•••-${d.slice(-4)}`;
}

export function redactIp(v: string): string {
  const parts = v.split('.');
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.•.•`;
  // IPv6: keep the first group only.
  const g = v.split(':');
  return `${g[0]}:••••::••`;
}

export function redactUrlCreds(v: string): string {
  return v.replace(/(:\/\/[^:@/]+:)[^@]+(@)/, '$1••••••$2');
}

export function redactJwt(v: string): string {
  const segs = v.split('.').length;
  return `${v.slice(0, 10)}… [JWT REDACTED — ${segs} segments, ${v.length} chars]`;
}

export function redactPrivateKey(v: string): string {
  const header = v.match(/-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----/)?.[0] ?? '-----BEGIN PRIVATE KEY-----';
  return `${header} … [KEY MATERIAL REDACTED — ${v.length} chars]`;
}

export function redactFixed(label: string): (v: string) => string {
  return () => `[${label} — REDACTED]`;
}

/** Mask a street address' house number: '742 Evergreen Terrace' → '••• Evergreen Terrace'. */
export function redactAddress(v: string): string {
  return v.replace(/^\d+/, (m) => '•'.repeat(m.length));
}

/** Keep only the year of a date of birth. */
export function redactDob(v: string): string {
  const year = v.match(/\b(19|20)\d{2}\b/)?.[0];
  return year ? `••/••/${year}` : '••/••/••••';
}

export function redactIdNumber(v: string): string {
  if (v.length <= 3) return '•'.repeat(v.length);
  return `${v[0]}${'•'.repeat(v.length - 3)}${v.slice(-2)}`;
}

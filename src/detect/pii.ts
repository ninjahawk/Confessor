import type { MatchRule } from './engine.js';
import {
  luhnValid,
  cardBrand,
  ibanValid,
  ssnPlausible,
  isPublicIpv4,
  isPublicIpv6,
} from './validators.js';
import {
  redactCard,
  redactSsn,
  redactIban,
  redactEmail,
  redactPhone,
  redactIp,
  redactAddress,
  redactDob,
  redactIdNumber,
} from '../redact.js';

const r = (pattern: string, flags = ''): RegExp => new RegExp(pattern, `gd${flags}`);

/** Domains/TLDs that indicate a non-personal or fictional email. */
const EMAIL_SKIP_DOMAINS = /(?:^|\.)(?:example\.(?:com|org|net)|test\.com|email\.com|domain\.com|localhost)$/i;
const EMAIL_FILE_EXT_TLDS = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico', 'bmp',
  'md', 'txt', 'json', 'yml', 'yaml', 'toml', 'lock', 'map', 'log',
  'js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'css', 'scss', 'html', 'htm',
  'py', 'rb', 'rs', 'go', 'java', 'cs', 'php', 'sh', 'ps1',
  'woff', 'woff2', 'ttf', 'otf', 'eot', 'mp4', 'mp3', 'wav', 'pdf', 'zip', 'gz',
]);
const EMAIL_SKIP_LOCAL = /^(?:noreply|no-reply|donotreply|do-not-reply|notifications?|support|info|admin|hello|contact|sales|team)$/i;

function digitsOf(s: string): string {
  return s.replace(/\D/g, '');
}

function notAdjacentDigit(full: string, start: number, end: number): boolean {
  const before = start > 0 ? full[start - 1] : '';
  const after = end < full.length ? full[end] : '';
  return !/[\d]/.test(before) && !/[\d]/.test(after);
}

/**
 * Layer 2: structured PII. Regex + hard validators (Luhn, IBAN mod-97, SSN
 * structure) and context gates for the ambiguous ones. Severity HIGH.
 */
export const PII_RULES: MatchRule[] = [
  {
    id: 'credit-card',
    title: 'Payment card number',
    severity: 'high',
    layer: 2,
    pattern: r('(?<![\\d-])(?:\\d[ -]?){12,18}\\d(?![\\d-])'),
    validate: (v, full, start) => {
      const d = digitsOf(v);
      if (d.length < 13 || d.length > 19) return false;
      if (!notAdjacentDigit(full, start, start + v.length)) return false;
      if (/^(\d)\1+$/.test(d)) return false;
      return luhnValid(d) && cardBrand(d) !== null;
    },
    normalize: (v) => digitsOf(v),
    describe: (v) => {
      const brand = cardBrand(digitsOf(v));
      return brand ? `Payment card number (${brand})` : 'Payment card number';
    },
    priority: 30,
    redact: redactCard,
    remediation: 'If this card is still active, consider asking your bank to reissue it.',
  },
  {
    id: 'iban',
    title: 'IBAN (bank account)',
    severity: 'high',
    layer: 2,
    pattern: r('\\b[A-Z]{2}\\d{2}(?: ?[A-Z0-9]){11,30}\\b'),
    validate: (v) => ibanValid(v),
    normalize: (v) => v.replace(/\s/g, '').toUpperCase(),
    priority: 29,
    redact: redactIban,
    remediation: 'IBANs alone rarely enable fraud, but combined with your name they can — be aware it was shared.',
  },
  {
    id: 'ssn',
    title: 'US Social Security number',
    severity: 'high',
    layer: 2,
    pattern: r('\\b\\d{3}[- ]\\d{2}[- ]\\d{4}\\b'),
    prefilter: ['ssn', 'social sec', 'social-sec', 'social_sec'],
    context: /\b(?:ssn|social\s+security|social\s+sec)\b/i,
    validate: (v) => ssnPlausible(digitsOf(v)),
    normalize: (v) => digitsOf(v),
    priority: 28,
    redact: redactSsn,
    remediation: 'Consider a credit freeze at the three US bureaus if this SSN is yours and was shared with a third party.',
  },
  {
    id: 'ssn-bare',
    title: 'US Social Security number',
    severity: 'high',
    layer: 2,
    pattern: r('\\b\\d{9}\\b'),
    prefilter: ['ssn', 'social sec', 'social-sec', 'social_sec'],
    context: /\b(?:ssn|social\s+security|social\s+sec)\b/i,
    validate: (v, full, start) => ssnPlausible(v) && notAdjacentDigit(full, start, start + v.length),
    normalize: (v) => v,
    priority: 27,
    redact: redactSsn,
    remediation: 'Consider a credit freeze at the three US bureaus if this SSN is yours and was shared with a third party.',
  },
  {
    id: 'email',
    title: 'Email address',
    severity: 'high',
    layer: 2,
    pattern: r('\\b[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]*\\.[A-Za-z]{2,24}\\b'),
    prefilter: ['@'],
    validate: (v) => {
      const [local, domain] = v.split('@');
      if (!local || !domain) return false;
      const tld = domain.split('.').pop()?.toLowerCase() ?? '';
      if (EMAIL_FILE_EXT_TLDS.has(tld)) return false;
      if (EMAIL_SKIP_DOMAINS.test(domain)) return false;
      if (EMAIL_SKIP_LOCAL.test(local)) return false;
      if (/^\d/.test(domain)) return false; // img@2x.png style artifacts
      return true;
    },
    normalize: (v) => v.toLowerCase(),
    priority: 26,
    redact: redactEmail,
    remediation: 'Email addresses tie conversations to your identity; know which accounts are now linked to your chat history.',
  },
  {
    id: 'dob',
    title: 'Date of birth',
    severity: 'high',
    layer: 2,
    pattern: r(
      '\\b(?:born(?:\\s+on)?|date\\s+of\\s+birth|birth\\s*date|dob|birthday(?:\\s+is)?)\\b[^.!?\\n]{0,40}?((?:\\d{1,2}[/.-]\\d{1,2}[/.-](?:19|20)?\\d{2})|(?:(?:19|20)\\d{2}[/.-]\\d{1,2}[/.-]\\d{1,2})|(?:(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\\.?\\s+\\d{1,2}(?:st|nd|rd|th)?,?\\s+(?:19|20)\\d{2}))',
      'i',
    ),
    group: 1,
    prefilter: ['born', 'birth', 'dob'],
    priority: 25,
    redact: redactDob,
    remediation: 'Date of birth is a core identity-verification datum; combined with name it enables impersonation.',
  },
  {
    id: 'passport-or-license',
    title: 'Passport / driver’s license number',
    severity: 'high',
    layer: 2,
    pattern: r(
      "\\b(?:passport|driver'?s?\\s+licen[cs]e|driving\\s+licen[cs]e|dl)\\s*(?:number|no\\.?|#|:)?\\s*(?:is\\s+)?[\"']?([A-Z0-9][A-Z0-9-]{5,14})\\b",
      'i',
    ),
    group: 1,
    prefilter: ['passport', 'licen', 'dl'],
    validate: (v) => /\d/.test(v) && !/^(?:number|expire[ds]?|renewal|invalid|office|photo)$/i.test(v),
    normalize: (v) => v.toUpperCase(),
    priority: 24,
    redact: redactIdNumber,
    remediation: 'Government ID numbers enable identity fraud; monitor for misuse and avoid re-sharing.',
  },
  {
    id: 'phone-us',
    title: 'Phone number',
    severity: 'high',
    layer: 2,
    pattern: r('(?<![\\d.-])(?:\\+1[ .-]?)?\\(?([2-9]\\d{2})\\)?[ .-]\\d{3}[ .-]\\d{4}(?![\\d-])'),
    validate: (v) => {
      const d = digitsOf(v);
      return d.length === 10 || (d.length === 11 && d.startsWith('1'));
    },
    normalize: (v) => digitsOf(v).slice(-10),
    priority: 22,
    redact: redactPhone,
    remediation: 'Phone numbers are durable identifiers used for account recovery and SIM-swap attacks.',
  },
  {
    id: 'phone-intl',
    title: 'Phone number (international)',
    severity: 'high',
    layer: 2,
    pattern: r('(?<![\\d,.])\\+[1-9]\\d{0,2}[ .-]?\\d{2,4}[ .-]?\\d{2,4}[ .-]?\\d{2,4}(?![\\d-])'),
    prefilter: ['+'],
    validate: (v) => {
      const d = digitsOf(v);
      return d.length >= 8 && d.length <= 15;
    },
    normalize: (v) => digitsOf(v).slice(-10),
    priority: 22,
    redact: redactPhone,
    remediation: 'Phone numbers are durable identifiers used for account recovery and SIM-swap attacks.',
  },
  {
    id: 'phone-context',
    title: 'Phone number',
    severity: 'high',
    layer: 2,
    pattern: r('(?<![\\d.-])[1-9]\\d{6,10}(?![\\d-])'),
    prefilter: ['phone', 'mobile', 'cell', 'whatsapp', 'call me', 'text me'],
    context: /\b(?:phone|mobile|cell|whatsapp|call\s+me|text\s+me|tel)\b/i,
    normalize: (v) => digitsOf(v).slice(-10),
    priority: 21,
    redact: redactPhone,
    remediation: 'Phone numbers are durable identifiers used for account recovery and SIM-swap attacks.',
  },
  {
    id: 'street-address',
    title: 'Street address',
    severity: 'high',
    layer: 2,
    pattern: r(
      "\\b\\d{1,6}\\s+(?:[A-Z][A-Za-z'.-]*\\s+){1,4}(?:Street|Avenue|Boulevard|Drive|Lane|Road|Court|Circle|Place|Terrace|Trail|Parkway|Highway|Crescent|Square|Way|St|Ave|Blvd|Dr|Ln|Rd|Ct|Cir|Pl|Ter|Trl|Pkwy|Hwy)\\.?(?=[\\s,.!?;:)]|$)",
    ),
    validate: (v) => !/^(?:19|20)\d{2}\s/.test(v), // "2024 Report Ave" style false hits
    priority: 20,
    redact: redactAddress,
    remediation: 'Home addresses tied to chat accounts are a doxxing risk; avoid re-sharing.',
  },
  {
    id: 'ipv4',
    title: 'Public IP address',
    severity: 'high',
    layer: 2,
    pattern: r('(?<!\\d\\.)(?<!\\d)(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?!\\.?\\d)'),
    validate: (v, full, start) => {
      if (!isPublicIpv4(v)) return false;
      const before = full.slice(Math.max(0, start - 10), start);
      if (/(?:version|\bv)\s*$/i.test(before)) return false; // v1.2.3.4
      return true;
    },
    priority: 18,
    redact: redactIp,
    remediation: 'Public IPs reveal your approximate location and network; rotate via your ISP or VPN if concerned.',
  },
  {
    id: 'ipv6',
    title: 'Public IPv6 address',
    severity: 'high',
    layer: 2,
    pattern: r('\\b(?:[A-Fa-f0-9]{1,4}:){2,7}(?::|[A-Fa-f0-9]{1,4})(?:::)?(?:[A-Fa-f0-9]{1,4})?\\b'),
    prefilter: [':'],
    validate: (v) => {
      // Require a 3–4 char hex group or '::' so MAC addresses don't match.
      if (!/[A-Fa-f0-9]{3,4}/.test(v) && !v.includes('::')) return false;
      return isPublicIpv6(v);
    },
    normalize: (v) => v.toLowerCase(),
    priority: 17,
    redact: redactIp,
    remediation: 'Public IPs reveal your approximate location and network.',
  },
];

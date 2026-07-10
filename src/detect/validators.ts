/** Checksum and structural validators used to keep Layer 2 precision high. */

export function luhnValid(digits: string): boolean {
  if (!/^\d+$/.test(digits)) return false;
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

/** Card brand from IIN prefix; null when the prefix isn't a known consumer brand. */
export function cardBrand(digits: string): string | null {
  if (/^4\d{12}(\d{3})?(\d{3})?$/.test(digits)) return 'Visa';
  if (/^(5[1-5]\d{14}|2(2[2-9]\d|[3-6]\d{2}|7[01]\d|720)\d{12})$/.test(digits)) return 'Mastercard';
  if (/^3[47]\d{13}$/.test(digits)) return 'American Express';
  if (/^(6011|65\d{2}|64[4-9]\d)\d{12}$/.test(digits)) return 'Discover';
  if (/^35(2[89]|[3-8]\d)\d{12}$/.test(digits)) return 'JCB';
  if (/^3(0[0-5]|[68]\d)\d{11}$/.test(digits)) return 'Diners Club';
  return null;
}

/** Official IBAN lengths for common countries; unknown countries fall back to 15–34 + checksum. */
const IBAN_LENGTHS: Record<string, number> = {
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22, BR: 29,
  CH: 21, CR: 22, CY: 28, CZ: 24, DE: 22, DK: 18, DO: 28, EE: 20, EG: 29, ES: 24,
  FI: 18, FO: 18, FR: 27, GB: 22, GE: 22, GI: 23, GL: 18, GR: 27, GT: 28, HR: 21,
  HU: 28, IE: 22, IL: 23, IS: 26, IT: 27, JO: 30, KW: 30, KZ: 20, LB: 28, LI: 21,
  LT: 20, LU: 20, LV: 21, MC: 27, MD: 24, ME: 22, MK: 19, MT: 31, MU: 30, NL: 18,
  NO: 15, PK: 24, PL: 28, PT: 25, QA: 29, RO: 24, RS: 22, SA: 24, SE: 24, SI: 19,
  SK: 24, SM: 27, TN: 24, TR: 26, UA: 29, XK: 20,
};

export function ibanValid(iban: string): boolean {
  const s = iban.replace(/\s/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s)) return false;
  const cc = s.slice(0, 2);
  const expected = IBAN_LENGTHS[cc];
  if (expected !== undefined) {
    if (s.length !== expected) return false;
  } else if (s.length < 15 || s.length > 34) {
    return false;
  }
  // Mod-97: move first 4 chars to the end, letters → 10..35, big-number mod via chunks.
  const rearranged = s.slice(4) + s.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    const val = code >= 65 ? String(code - 55) : ch;
    for (const digit of val) {
      remainder = (remainder * 10 + (digit.charCodeAt(0) - 48)) % 97;
    }
  }
  return remainder === 1;
}

/** SSN structural rules: area 001–899 excluding 666, group ≠ 00, serial ≠ 0000. */
export function ssnPlausible(digits: string): boolean {
  if (digits.length !== 9) return false;
  const area = Number(digits.slice(0, 3));
  const group = Number(digits.slice(3, 5));
  const serial = Number(digits.slice(5));
  if (area === 0 || area === 666 || area >= 900) return false;
  if (group === 0 || serial === 0) return false;
  return true;
}

export function base64UrlToString(seg: string): string | null {
  try {
    return Buffer.from(seg, 'base64url').toString('utf8');
  } catch {
    return null;
  }
}

/** True when the candidate decodes like a real JWT (header JSON with an `alg`). */
export function jwtLooksValid(candidate: string): boolean {
  const segs = candidate.split('.');
  if (segs.length !== 3) return false;
  const header = base64UrlToString(segs[0]);
  if (!header) return false;
  try {
    const parsed = JSON.parse(header) as Record<string, unknown>;
    return typeof parsed === 'object' && parsed !== null && 'alg' in parsed;
  } catch {
    return false;
  }
}

/** Public, routable IPv4 — filters private/reserved/documentation/CGNAT ranges. */
export function isPublicIpv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return false;
  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0 && parts[2] === 2) return false; // TEST-NET-1
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && parts[2] === 100) return false; // TEST-NET-2
  if (a === 203 && b === 0 && parts[2] === 113) return false; // TEST-NET-3
  if (a >= 224) return false; // multicast + reserved + broadcast
  return true;
}

/** Structural IPv6 validation without the banned `node:net` module. */
export function isValidIpv6(s: string): boolean {
  if (s.includes(':::')) return false;
  const doubleColon = s.includes('::');
  if (doubleColon && s.indexOf('::') !== s.lastIndexOf('::')) return false;
  const groups = s.split(':').filter((g) => g.length > 0);
  if (groups.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) return false;
  if (doubleColon) return groups.length >= 2 && groups.length <= 7;
  return groups.length === 8;
}

/** Interesting IPv6 = valid, not loopback/link-local/ULA/multicast/documentation. */
export function isPublicIpv6(s: string): boolean {
  if (!isValidIpv6(s)) return false;
  const lower = s.toLowerCase();
  if (lower === '::' || lower === '::1') return false;
  if (lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd')) return false;
  if (lower.startsWith('ff')) return false;
  if (lower.startsWith('2001:db8')) return false;
  return true;
}

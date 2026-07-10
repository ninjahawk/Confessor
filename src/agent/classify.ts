/**
 * Classifiers for agent activity. All pattern-based and explainable — every
 * flag points at the one rule that matched, same discipline as the detection
 * engine.
 */
import type { SensitiveClass } from './types.js';

interface PathRule {
  re: RegExp;
  sensitivity: SensitiveClass['sensitivity'];
  label: string;
  reason: string;
}

/**
 * Sensitive path rules, most-specific first. Matched against a normalized
 * (forward-slash, lowercased) path. These are files an agent almost never has
 * a legitimate reason to open while doing a coding task — the whole point is
 * to surface the ones it opened anyway.
 */
const PATH_RULES: PathRule[] = [
  // ---- credentials & keys (secret) ----
  { re: /(^|\/)\.ssh\/(id_[a-z0-9]+|.*_rsa|.*_ed25519|identity)$/, sensitivity: 'secret', label: 'SSH private key', reason: 'a private key that grants server and Git access' },
  { re: /(^|\/)\.ssh\//, sensitivity: 'secret', label: 'SSH directory', reason: 'your SSH keys and known hosts live here' },
  { re: /(^|\/)\.aws\/(credentials|config)$/, sensitivity: 'secret', label: 'AWS credentials', reason: 'your Amazon cloud access keys' },
  { re: /(^|\/)\.(env)(\.[a-z0-9_.-]+)?$/, sensitivity: 'secret', label: 'Environment file', reason: 'app secrets and API keys are conventionally kept here' },
  { re: /(^|\/)\.git-credentials$/, sensitivity: 'secret', label: 'Git credentials', reason: 'saved usernames and tokens for Git remotes' },
  { re: /(^|\/)\.netrc$/, sensitivity: 'secret', label: 'netrc file', reason: 'plaintext logins for FTP/HTTP tools' },
  { re: /(^|\/)\.npmrc$/, sensitivity: 'secret', label: 'npm config', reason: 'may hold your npm publish token' },
  { re: /(^|\/)\.pypirc$/, sensitivity: 'secret', label: 'PyPI config', reason: 'may hold your PyPI upload token' },
  { re: /(^|\/)\.docker\/config\.json$/, sensitivity: 'secret', label: 'Docker config', reason: 'registry login credentials' },
  { re: /(^|\/)\.kube\/config$/, sensitivity: 'secret', label: 'Kubernetes config', reason: 'cluster admin credentials' },
  { re: /(^|\/)(id_rsa|id_ed25519|id_ecdsa|id_dsa)(\.pub)?$/, sensitivity: 'secret', label: 'Private key', reason: 'an SSH private key' },
  { re: /\.(pem|key|pfx|p12|keystore|jks)$/, sensitivity: 'secret', label: 'Key / certificate file', reason: 'private key or certificate material' },
  { re: /(^|\/)(service-account|serviceaccount|gcp-key|google-credentials)[^/]*\.json$/, sensitivity: 'secret', label: 'Cloud service account key', reason: 'a Google Cloud service-account key' },
  { re: /(^|\/)wallet\.dat$/, sensitivity: 'secret', label: 'Crypto wallet', reason: 'a cryptocurrency wallet file' },
  { re: /(^|\/)(secrets?|credentials?)\.(json|ya?ml|txt|env)$/, sensitivity: 'secret', label: 'Secrets file', reason: 'a file explicitly named for secrets' },

  // ---- OS / browser credential stores (secret) ----
  { re: /(^|\/)login data$/, sensitivity: 'secret', label: 'Browser saved passwords', reason: "Chrome's saved-password database" },
  { re: /(^|\/)cookies(\.sqlite)?$/, sensitivity: 'secret', label: 'Browser cookies', reason: 'session cookies that can impersonate you' },
  { re: /(^|\/)(keychain|login\.keychain-db)$/, sensitivity: 'secret', label: 'macOS Keychain', reason: 'the system password vault' },
  { re: /(^|\/)local state$/, sensitivity: 'secret', label: 'Browser Local State', reason: 'holds the key that decrypts saved passwords' },

  // ---- shell history (secret-ish) ----
  { re: /(^|\/)\.(bash|zsh|python|node_repl|psql)_history$/, sensitivity: 'secret', label: 'Shell history', reason: 'past commands, often with secrets typed inline' },

  // ---- system files (system) ----
  { re: /^\/etc\/(shadow|passwd|sudoers)$/, sensitivity: 'system', label: 'System account file', reason: 'OS user and password data' },

  // ---- personal documents by name (personal) ----
  { re: /(tax|w-?2|1099|1040|irs)[^/]*\.(pdf|csv|xlsx?|docx?)$/, sensitivity: 'personal', label: 'Tax document', reason: 'a file that looks like tax paperwork' },
  { re: /(ssn|social.?security|passport|driver.?licen[cs]e|birth.?certificate)/, sensitivity: 'personal', label: 'Identity document', reason: 'the path names a government ID' },
  { re: /(bank|statement|invoice|payslip|payroll|salary)[^/]*\.(pdf|csv|xlsx?)$/, sensitivity: 'personal', label: 'Financial document', reason: 'a file that looks like a financial record' },
  { re: /(medical|health|diagnos|prescription|patient)[^/]*\.(pdf|csv|docx?|txt)$/, sensitivity: 'personal', label: 'Medical document', reason: 'a file that looks like a health record' },
  { re: /(resume|cv|passport|scan[^/]*id)[^/]*\.(pdf|docx?|jpe?g|png)$/, sensitivity: 'personal', label: 'Personal document', reason: 'a personal document' },
];

export function classifyPath(rawPath: string): SensitiveClass {
  const norm = rawPath.replace(/\\/g, '/').toLowerCase();
  for (const r of PATH_RULES) {
    if (r.re.test(norm)) {
      return { sensitivity: r.sensitivity, label: r.label, reason: r.reason };
    }
  }
  return { sensitivity: 'normal', label: 'File', reason: '' };
}

/** Replace a home-directory username in a path with ~, so the report doesn't dox the user. */
export function tidyPath(rawPath: string): string {
  return rawPath
    .replace(/\\/g, '/')
    .replace(/^([A-Za-z]:)?\/?(Users|home)\/[^/]+/i, '~')
    .replace(/^\/root/, '~');
}

export type CommandKind = 'network' | 'destructive' | 'privileged' | 'normal';

interface CommandRule {
  re: RegExp;
  kind: CommandKind;
  reason: string;
}

const NETWORK_CMDS: CommandRule[] = [
  { re: /\bcurl\b/, kind: 'network', reason: 'curl can send file contents to any URL' },
  { re: /\bwget\b/, kind: 'network', reason: 'wget transfers data over the network' },
  { re: /\b(nc|netcat|ncat)\b/, kind: 'network', reason: 'netcat opens raw network connections' },
  { re: /\bscp\b/, kind: 'network', reason: 'scp copies files to a remote host' },
  { re: /\brsync\b.*::|\brsync\b.*@/, kind: 'network', reason: 'rsync is syncing to a remote host' },
  { re: /\b(ftp|sftp|telnet)\b/, kind: 'network', reason: 'a legacy network transfer tool' },
  { re: /\bInvoke-(WebRequest|RestMethod)\b/i, kind: 'network', reason: 'PowerShell web request' },
  { re: /\bnpm\s+publish\b/, kind: 'network', reason: 'publishes a package to the npm registry' },
  { re: /\bgit\s+push\b/, kind: 'network', reason: 'pushes commits to a remote repository' },
  { re: /\|\s*(curl|nc|wget)\b/, kind: 'network', reason: 'piping data into a network command' },
];

const DESTRUCTIVE_CMDS: CommandRule[] = [
  { re: /\brm\s+-rf?\b/, kind: 'destructive', reason: 'recursive delete' },
  { re: /\b(mkfs|dd\s+if=)/, kind: 'destructive', reason: 'can wipe a disk' },
  { re: />\s*\/dev\/sd/, kind: 'destructive', reason: 'writes directly to a disk device' },
];

const PRIVILEGED_CMDS: CommandRule[] = [
  { re: /\bsudo\b/, kind: 'privileged', reason: 'runs with administrator rights' },
  { re: /\bchmod\s+777\b/, kind: 'privileged', reason: 'makes a file world-writable' },
];

export function classifyCommand(cmd: string): { kind: CommandKind; reason?: string } {
  for (const list of [NETWORK_CMDS, DESTRUCTIVE_CMDS, PRIVILEGED_CMDS]) {
    for (const r of list) {
      if (r.re.test(cmd)) return { kind: r.kind, reason: r.reason };
    }
  }
  return { kind: 'normal' };
}

/** Pull the first host out of a command or URL, for a redacted sink target. */
export function extractHost(text: string): { host: string; external: boolean } | null {
  const m = text.match(/https?:\/\/([^/\s"'`)]+)/i) || text.match(/\bscp\s+[^@\s]+@([^:\s]+)/i) || text.match(/@([a-z0-9.-]+\.[a-z]{2,})/i);
  if (!m) return null;
  const host = m[1].replace(/:\d+$/, '').toLowerCase();
  const external = !/^(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|.*\.local)$/.test(host);
  return { host, external };
}

/** Files referenced by a shell command (cat/less/cp/etc.), best-effort. */
export function filesFromCommand(cmd: string): string[] {
  const out: string[] = [];
  const re = /\b(?:cat|less|more|head|tail|cp|mv|scp|type|Get-Content|nano|vim|vi|open|xxd|base64|strings|grep)\s+((?:[^\s|;&<>]+\s*)+)/gi;
  let m: RegExpExecArray | null;
  let guard = 0;
  while ((m = re.exec(cmd)) !== null && guard++ < 50) {
    for (const tok of m[1].split(/\s+/)) {
      if (tok && !tok.startsWith('-') && /[\/.]/.test(tok)) out.push(tok.replace(/["'`]/g, ''));
    }
  }
  return out;
}

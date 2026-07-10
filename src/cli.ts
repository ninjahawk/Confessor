#!/usr/bin/env node
/**
 * confessor — find out what you've told AI.
 * 100% local. Zero network calls. Zero dependencies.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { audit, toolVersion } from './index.js';
import { renderReport } from './report/html.js';
import { openInBrowser } from './open.js';
import { claudeCodeDefaultDir } from './adapters/index.js';
import type { ScanResult, Severity } from './types.js';
import { PROVIDER_LABELS } from './types.js';
import { comma } from './util.js';

const useColor = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR;
const c = {
  red: (s: string) => (useColor ? `\x1b[31m${s}\x1b[0m` : s),
  yellow: (s: string) => (useColor ? `\x1b[33m${s}\x1b[0m` : s),
  blue: (s: string) => (useColor ? `\x1b[34m${s}\x1b[0m` : s),
  green: (s: string) => (useColor ? `\x1b[32m${s}\x1b[0m` : s),
  bold: (s: string) => (useColor ? `\x1b[1m${s}\x1b[0m` : s),
  dim: (s: string) => (useColor ? `\x1b[2m${s}\x1b[0m` : s),
};

const HELP = `
confessor — see what your AI coding agent actually did on your computer.

Reconstructs Claude Code's activity from its local logs (files opened, secrets
that entered its context, network calls, and sensitive-read-then-network-call
exposure paths), and scans your AI chat history for secrets, personal
identifiers, and sensitive disclosures. 100% local: zero network calls, zero
dependencies, and the report is a single offline HTML file.

USAGE
  confessor                      auto-detect Claude Code logs, analyze, open report
  confessor scan <path...>       also scan export zips, folders, or files
  confessor <path...>            same thing, 'scan' is optional

WHAT CAN BE SCANNED
  ~/.claude/projects             Claude Code session logs (auto-detected)
  chatgpt-export.zip             ChatGPT: Settings → Data controls → Export data
  claude-export/                 Claude.ai: Settings → Privacy → Export data
  Takeout/                       Gemini: takeout.google.com → My Activity (beta)
  notes/ file.md dump.json       any .txt .md .json .jsonl .log .csv

OPTIONS
  --json             print machine-readable JSON to stdout (no HTML, no browser)
  --out <file>       report path (default: ./confessor-report.html)
  --no-open          write the report but don't open the browser
  --fail-on <sev>    exit 2 if findings at/above severity: critical|high|medium
  --quiet            no progress output
  -v, --version      print version
  -h, --help         this help

EXIT CODES
  0 scan completed   1 error / nothing to scan   2 --fail-on threshold hit

Everything runs offline — verify with a firewall, or read the source:
https://github.com/ninjahawk/Confessor
`;

interface CliOptions {
  paths: string[];
  json: boolean;
  out: string;
  open: boolean;
  quiet: boolean;
  failOn?: Severity;
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    paths: [],
    json: false,
    out: 'confessor-report.html',
    open: true,
    quiet: false,
  };
  const rest = [...argv];
  while (rest.length > 0) {
    const a = rest.shift() as string;
    switch (a) {
      case '-h':
      case '--help':
        process.stdout.write(HELP);
        process.exit(0);
        break;
      case '-v':
      case '--version':
        process.stdout.write(toolVersion() + '\n');
        process.exit(0);
        break;
      case '--json':
        opts.json = true;
        break;
      case '--no-open':
        opts.open = false;
        break;
      case '--quiet':
        opts.quiet = true;
        break;
      case '--out': {
        const v = rest.shift();
        if (!v) fail("--out needs a file path");
        opts.out = v as string;
        break;
      }
      case '--fail-on': {
        const v = rest.shift();
        if (v !== 'critical' && v !== 'high' && v !== 'medium') {
          fail('--fail-on must be critical, high, or medium');
        }
        opts.failOn = v as Severity;
        break;
      }
      case 'scan':
        break; // optional subcommand
      default:
        if (a.startsWith('-')) fail(`unknown option: ${a} (try --help)`);
        opts.paths.push(a);
    }
  }
  return opts;
}

function fail(msg: string): never {
  process.stderr.write(c.red(`error: ${msg}`) + '\n');
  process.exit(1);
}

function guidance(): string {
  const auto = claudeCodeDefaultDir();
  return `
${c.bold('Nothing to scan yet.')} No Claude Code logs at ${auto}.

Point confessor at an AI data export instead:

  ${c.bold('ChatGPT')}   chatgpt.com → Settings → Data controls → Export data
             ${c.dim('→ confessor scan ~/Downloads/chatgpt-export.zip')}
  ${c.bold('Claude')}    claude.ai → Settings → Privacy → Export data
             ${c.dim('→ confessor scan ~/Downloads/claude-export.zip')}
  ${c.bold('Gemini')}    takeout.google.com → select "My Activity" (beta)
             ${c.dim('→ confessor scan ~/Downloads/Takeout')}
  ${c.bold('Anything')}  ${c.dim('→ confessor scan ./some-folder-of-notes')}
`;
}

function severityMeets(counts: ScanResult['stats']['counts'], threshold: Severity): boolean {
  if (threshold === 'critical') return counts.critical > 0;
  if (threshold === 'high') return counts.critical + counts.high > 0;
  return counts.critical + counts.high + counts.medium > 0;
}

function printSummary(result: ScanResult, reportPath: string | null, opened: boolean): void {
  const s = result.stats;
  const providers = s.providers.map((p) => PROVIDER_LABELS[p]).join(' · ');
  const lines: string[] = [];
  lines.push('');
  lines.push(`  ${c.bold('CONFESSOR')} ${c.dim('v' + result.version)} — what your AI has seen`);
  lines.push('');
  lines.push(`  ${c.bold(comma(s.messages))} messages · ${c.bold(comma(s.conversations))} conversations · ${providers}`);
  lines.push('');
  lines.push(`  ${c.red('●')} ${c.bold(String(comma(s.counts.critical)).padStart(6))}  ${c.red('CRITICAL')}  secrets & credentials`);
  lines.push(`  ${c.yellow('●')} ${c.bold(String(comma(s.counts.high)).padStart(6))}  ${c.yellow('HIGH')}      personal identifiers`);
  lines.push(`  ${c.blue('●')} ${c.bold(String(comma(s.counts.medium)).padStart(6))}  ${c.blue('MEDIUM')}    sensitive disclosures`);
  lines.push('');
  lines.push(`  Exposure score ${c.bold(comma(s.score))} · grade ${c.bold(s.grade)}`);
  if (result.headline) {
    lines.push('');
    lines.push(`  ${c.dim(result.headline)}`);
  }
  if (result.agent) {
    const a = result.agent;
    lines.push('');
    lines.push(`  ${c.bold('AGENT ACTIVITY')} ${c.dim('(Claude Code)')}`);
    lines.push(`  ${c.bold(String(comma(a.counts.sensitiveFiles)))} sensitive files opened · ${c.bold(String(comma(a.counts.secretsInContext)))} secrets in context · ${c.bold(String(comma(a.counts.externalSinks)))} external destinations`);
    if (a.exposurePaths.length > 0) {
      lines.push(`  ${c.red('⚠')} ${c.bold(comma(a.exposurePaths.length) + ' exposure path' + (a.exposurePaths.length === 1 ? '' : 's'))} — sensitive data read, then a network call in the same session.`);
    }
  }
  if (s.counts.critical > 0) {
    lines.push('');
    lines.push(`  ${c.red('⚠')} ${c.bold(comma(s.counts.critical) + ' credential' + (s.counts.critical === 1 ? '' : 's'))} should be rotated — how-to is in the report.`);
  }
  if (reportPath) {
    lines.push('');
    lines.push(`  Report → ${c.bold(reportPath)}${opened ? c.dim('  (opening in browser)') : ''}`);
  }
  lines.push('');
  lines.push(`  ${c.green('●')} ${c.dim('100% local · zero network calls · github.com/ninjahawk/Confessor')}`);
  lines.push('');
  process.stdout.write(lines.join('\n') + '\n');
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));

  if (opts.paths.length === 0 && !fs.existsSync(claudeCodeDefaultDir())) {
    process.stderr.write(guidance());
    process.exit(1);
  }

  const showProgress = !opts.quiet && process.stderr.isTTY;
  let files = 0;
  let lastDraw = 0;
  const progress = (count: number): void => {
    if (!showProgress) return;
    const now = Date.now();
    if (now - lastDraw < 120) return;
    lastDraw = now;
    process.stderr.write(`\r  scanning… ${comma(files)} files · ${comma(count)} messages `);
  };

  let result: ScanResult;
  try {
    result = await audit(opts.paths.length > 0 ? opts.paths : undefined, {
      onFile: () => {
        files++;
      },
      warn: (m) => {
        if (!opts.quiet) process.stderr.write(`\r${c.yellow('warn:')} ${m}\n`);
      },
      onMessageCount: progress,
    });
  } catch (err) {
    if (showProgress) process.stderr.write('\r\x1b[2K');
    fail((err as Error).message);
  }
  if (showProgress) process.stderr.write('\r\x1b[2K');

  if (opts.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    const outPath = path.resolve(opts.out);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, renderReport(result), 'utf8');
    const opened = opts.open ? openInBrowser(outPath) : false;
    printSummary(result, outPath, opened);
  }

  if (opts.failOn && severityMeets(result.stats.counts, opts.failOn)) {
    process.exit(2);
  }
}

main().catch((err: Error) => {
  fail(err.message);
});

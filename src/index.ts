/**
 * Programmatic API:
 *
 *   import { audit, renderReport } from 'confessor';
 *   const result = await audit(['./chatgpt-export.zip']);
 *   fs.writeFileSync('report.html', renderReport(result));
 */
import * as fs from 'node:fs';
import { Auditor } from './audit.js';
import { messagesFromPath, claudeCodeDefaultDir, type ScanCallbacks } from './adapters/index.js';
import type { ScanResult } from './types.js';

export { renderReport } from './report/html.js';
export { Auditor } from './audit.js';
export { messagesFromPath, claudeCodeDefaultDir } from './adapters/index.js';
export { SECRET_RULES, PII_RULES, scanText, scanCategories, detectMessage } from './detect/index.js';
export * from './types.js';

export function toolVersion(): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      version?: string;
    };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

export interface AuditOptions extends ScanCallbacks {
  onMessageCount?: (count: number) => void;
}

/**
 * Scan the given paths (or auto-detect local Claude Code logs when omitted)
 * and return the aggregated result. Purely local; throws if nothing scannable
 * is found.
 */
export async function audit(paths?: string[], opts: AuditOptions = {}): Promise<ScanResult> {
  let targets = paths ?? [];
  if (targets.length === 0) {
    const auto = claudeCodeDefaultDir();
    if (!fs.existsSync(auto)) {
      throw new Error(
        `no Claude Code logs found at ${auto} — pass a path: confessor scan <export.zip | folder>`,
      );
    }
    targets = [auto];
  }
  const auditor = new Auditor();
  for (const target of targets) {
    for await (const msg of messagesFromPath(target, opts)) {
      auditor.addMessage(msg);
      opts.onMessageCount?.(auditor.messageCount);
    }
  }
  if (auditor.messageCount === 0) {
    throw new Error('no messages found in the given paths — nothing to scan');
  }
  return auditor.finish(toolVersion());
}

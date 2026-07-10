import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Repo root, resolved from the compiled test location (build/test/helpers). */
export const REPO_ROOT = path.resolve(fileURLToPath(new URL('.', import.meta.url)), '..', '..', '..');

export const FIXTURES = path.join(REPO_ROOT, 'test', 'fixtures');

export const FIXTURE_PATHS = {
  claudeCodeHome: path.join(FIXTURES, 'claude-code-home'),
  claudeCodeJsonl: path.join(FIXTURES, 'claude-code-home', 'projects', 'C--Users-demo-app', 'session-0001.jsonl'),
  chatgptDir: path.join(FIXTURES, 'chatgpt'),
  chatgptJson: path.join(FIXTURES, 'chatgpt', 'conversations.json'),
  claudeAiDir: path.join(FIXTURES, 'claude-ai'),
  claudeAiJson: path.join(FIXTURES, 'claude-ai', 'conversations.json'),
  geminiHtml: path.join(FIXTURES, 'gemini', 'MyActivity.html'),
  genericDir: path.join(FIXTURES, 'generic'),
};

export const ALL_FIXTURE_INPUTS = [
  FIXTURE_PATHS.claudeCodeHome,
  FIXTURE_PATHS.chatgptDir,
  FIXTURE_PATHS.claudeAiDir,
  FIXTURE_PATHS.geminiHtml,
  FIXTURE_PATHS.genericDir,
];

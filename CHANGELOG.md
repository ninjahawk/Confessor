# Changelog

## Unreleased

### Added — AI agent forensics (the new headline)

- Reconstructs what a Claude Code agent did from its local `~/.claude/projects`
  session logs: every file read/written/edited, every command run, every
  outbound network path (WebFetch/WebSearch, network shell commands, MCP calls).
- **Exposure paths**: flags a sensitive file read or a secret in a tool result
  followed by an external network sink in the same session, with the time gap —
  the "data in, a way out right after" pattern.
- Path classifier for files an agent rarely has a task reason to open: `.env`,
  `~/.ssh` keys, `.aws/credentials`, browser password/cookie stores, shell
  history, and tax/medical/financial/identity documents by name.
- Runs the secret detection engine over tool *results* to count secrets that
  actually entered the model's context window.
- New report section "What your AI agent did on this computer" and a matching
  CLI summary block; the report leads with the agent finding when Claude Code
  logs are present.

### Changed

- Report redesigned around a light, Apple-style aesthetic: system fonts, white
  cards, iOS segmented-control filters, plain language for non-technical
  readers ("passwords & keys" rather than "credentials").

## 1.0.0 — 2026-07-09

Initial release: 100% local scanner for ChatGPT, Claude.ai, Claude Code, and
Gemini history. Three-layer detection (30 secret rules, 13 PII rules, 7
disclosure lexicons), structural redaction, single self-contained offline HTML
report. Zero runtime dependencies and zero network calls, both enforced in CI.
60 tests over planted-secret fixtures.

# Changelog

## 1.0.0 — 2026-07-09

Initial release.

- Scans ChatGPT exports (zip or unpacked), Claude.ai exports, local Claude
  Code session logs (auto-detected at `~/.claude/projects`), Gemini Takeout
  (beta), and generic text files (`.txt .md .json .jsonl .log .csv`).
- Three-layer detection engine: 30 secret/credential rules, 13 structured PII
  rules, 7 sensitive-disclosure lexicons — with prefilter gates, context
  windows, and validators (Luhn, entropy, structure) to keep false positives
  down.
- Structural redaction: full sensitive values are never written to any output.
- Single self-contained offline HTML report: per-source exposure grades,
  filterable findings table with remediation, disclosure categories, monthly
  timeline, heaviest conversations, per-provider cleanup instructions, and a
  shareable redacted score card.
- `--json` output and `--fail-on <severity>` exit codes for CI use.
- Zero runtime dependencies (including a from-scratch zip reader on
  `node:zlib`) and zero network calls, both enforced by a static check in CI.
- 60 tests over planted-secret fixtures for every supported provider.

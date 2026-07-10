# Security Policy

Confessor's entire job is handling your most sensitive data, so the bar here
is deliberately strict.

## Threat model

The tool assumes the scanned content contains live credentials and personal
data. Its promises:

1. **Nothing leaves the machine.** No code in `src/` may perform or import
   anything network-capable. Enforced by `scripts/no-network-check.mjs` in CI
   and in `prepublishOnly`.
2. **No full sensitive values in any output.** The HTML report, the `--json`
   output, and terminal output only ever contain redacted previews. Every
   detection rule routes its match through a redactor before storage, and
   previews are scrubbed against all other findings in the same message.
3. **Zero runtime dependencies.** There is no supply chain beyond this repo
   and Node itself.

## What counts as a vulnerability

Report it if you find any of these — each one breaks a core guarantee:

- Any network activity, however indirect, during scan or report generation.
- Any full (unredacted) secret or identifier appearing in the report, JSON
  output, terminal output, or any temp file.
- A crafted export file that causes path traversal, resource exhaustion
  (zip bombs are explicitly in scope for the zip reader), or code execution.
- XSS in the generated report: scanned content is attacker-controlled by
  definition (e.g. a chat log containing `<script>` — there is a fixture for
  exactly this), so any script execution from scanned content in the report
  is a vulnerability.

## Reporting

Please use GitHub's private vulnerability reporting
(Security → Report a vulnerability on this repo) rather than a public issue,
so a fix can ship before details are public. You can expect an initial
response within a few days.

## Supported versions

| Version | Supported |
|---|---|
| 1.x | ✅ |

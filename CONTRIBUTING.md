# Contributing

Thanks for helping. The codebase is small on purpose (~3,800 lines of
TypeScript, zero runtime dependencies) — please keep it that way.

## Setup

```bash
git clone https://github.com/ninjahawk/Confessor
cd Confessor
npm install        # devDependencies only (typescript + @types/node)
npm test           # builds src + tests, runs the 60-test suite
npm run check:no-network
```

Node ≥ 18.17. Tests use the built-in `node:test` runner — no test framework
to learn.

## The two hard rules

CI enforces both; PRs that break them cannot merge:

1. **No runtime dependencies.** If a feature needs a package, it needs a
   from-scratch implementation instead (that's how the zip reader happened).
2. **No network-capable code in `src/`.** `scripts/no-network-check.mjs` scans
   for banned imports and calls.

## Adding a detection rule

Most contributions are new secret patterns or false-positive fixes. A rule is
plain data in `src/detect/secrets.ts` or `src/detect/pii.ts`:

```ts
{
  id: 'acme-api-key',
  title: 'Acme API key',
  severity: 'critical',
  layer: 1,
  prefilter: ['acme_'],            // cheap gate before the regex runs
  pattern: /\bacme_[a-z0-9]{32}\b/gd,
  validate: (v) => entropyOk(v),   // optional: kill look-alikes
  redact: (v) => redactMiddle(v),  // REQUIRED — never store the full value
  remediation: 'Rotate at dashboard.acme.dev → API keys.',
  priority: 50,
}
```

With every rule, please include:

- A **planted fake value** in the relevant fixture under `test/fixtures/`
  (never real credentials, even revoked ones — fixture data is public).
- A positive test (it's found) and a negative test (similar-looking prose is
  not) in `test/`. The existing suites show the pattern.
- The redaction suite automatically asserts your rule redacts its own match —
  no extra work, but it will fail if `redact` is missing or weak.

For false positives: the fix is usually a `context` requirement or a
`validate` function, not a more clever regex.

## Report changes

`src/report/html.ts` renders the whole report as one self-contained file.
Inline CSS, inline vanilla JS, inline SVG — no external resources of any
kind, so it renders with the network unplugged. The "report never leaks"
test runs against the rendered output, so redaction regressions fail fast.

## Style

Match what's there: small pure functions, rules as data, comments only where
the code can't say it. If a diff makes the tool bigger without making it
detect better, it's probably not the right diff.

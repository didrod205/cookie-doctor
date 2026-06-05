# Contributing to cookie-doctor

Thanks for your interest! Most contributions are a new security rule — small and
data-driven.

## Getting started

```bash
git clone https://github.com/didrod205/cookie-doctor.git
cd cookie-doctor
npm install
npm test            # vitest
npm run typecheck   # tsc --noEmit
npm run build       # tsup → dist/
node dist/cli.js scan examples/weak.cookie.txt
```

## Project layout

```
src/
  parse.ts       # Set-Cookie → structured Cookie (attrs, prefix, lifetime)
  checks.ts      # the security rule set (the prefix-spec moat lives here)
  extract.ts     # pull Set-Cookie from raw / curl -I / nginx / JSON
  analyze.ts     # orchestrator + report builder
  score.ts       # weighted score + grade
  config.ts      # pure defaults/merge      load-config.ts # fs loading
  loader.ts      # read files / stdin
  report/        # console / json / markdown
  cli.ts         # cac CLI
tests/           # vitest specs (incl. integration over examples/)
examples/        # weak / strong cookies + a header dump
```

## Adding a rule

Add a check to `src/checks.ts` returning a `Finding` (stable `rule`, severity,
`attribute`, and a `fix`), then register it in `checkCookie`. Add a positive and a
negative test in `tests/checks.test.ts`.

## Quality bar

- [ ] Values reflect the cookie spec / documented browser behaviour (cite it). A
      wrong rule trains people to ignore the linter — and "the browser drops it"
      claims (`__Host-`, `SameSite=None`) must be exactly right.
- [ ] `strong.cookie.txt` stays 100/100 — no false positives on a hardened cookie.
- [ ] `npm run typecheck && npm test && npm run build` all pass.
- [ ] Regenerated `examples/sample-report.*` if output changed.

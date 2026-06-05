<div align="center">

# 🍪 cookie-doctor

### Lint your `Set-Cookie` headers for security — locally, no website.

[![npm version](https://img.shields.io/npm/v/cookie-doctor.svg?color=success)](https://www.npmjs.com/package/cookie-doctor)
[![bundle size](https://img.shields.io/bundlephobia/minzip/cookie-doctor?label=core%20gzip)](https://bundlephobia.com/package/cookie-doctor)
[![CI](https://github.com/didrod205/cookie-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/didrod205/cookie-doctor/actions/workflows/ci.yml)
[![types](https://img.shields.io/npm/types/cookie-doctor.svg)](https://www.npmjs.com/package/cookie-doctor)
[![license](https://img.shields.io/npm/l/cookie-doctor.svg)](./LICENSE)

**[🌐 Try the browser playground →](https://didrod205.github.io/cookie-doctor/)** &nbsp;·&nbsp; paste a `Set-Cookie`, see its security holes. Nothing is uploaded — it all runs client-side.

</div>

You set a session cookie and shipped it. But it went out without `HttpOnly` (so any
XSS can steal it), without `Secure` (so it rides plain HTTP), with `SameSite=None`
but no `Secure` (so the browser **rejects it entirely**), or with a `__Host-` prefix
whose strict rules it quietly violates — and now logins mysteriously don't stick.
You find out from a pentest, a console warning, or a 3 a.m. incident.

**cookie-doctor lints a `Set-Cookie` for these problems locally and
deterministically** — from a string, a `curl -I` response, or a config file. It
knows the `__Host-`/`__Secure-` prefix rules and the `SameSite=None`↔`Secure`
interaction, the exact spec people get wrong.

```bash
npx cookie-doctor scan -c "sid=abc; SameSite=None"
```

```
sid  46/100 (F)
  ✗ SameSite=None without Secure — the browser rejects the cookie   [SameSite]
  ✗ No HttpOnly — this looks like a session cookie, JS can read it  [HttpOnly]
  ✗ No Secure — sent over plaintext HTTP                            [Secure]
```

---

## Why cookie-doctor?

- 🧨 **It catches the "silently dropped" bugs.** `__Host-` without `Secure`, with a
  `Domain`, or without `Path=/`; `SameSite=None` without `Secure` — the browser
  rejects these cookies outright, so your session just *doesn't work*. cookie-doctor
  flags them as **validity** errors, not style nits.
- 🎯 **Severity that knows what a session cookie is.** A missing `HttpOnly` on
  `sid`/`auth`/a JWT-valued cookie is an **error**; on `theme=dark` it's a gentle
  warning. No noise.
- 🔒 **Local & deterministic.** No website, no API key, runs offline and in CI.
  Same cookie → same result. Fail the PR that ships an insecure session cookie.
- 🧩 **Reads it from anywhere.** A raw `Set-Cookie`, a `curl -I` dump, an nginx
  `add_header`, an Apache `Header set`, or `vercel.json`.

Why not paste it into an LLM? The `__Host-`/`__Secure-` rules and the
`SameSite=None`/`Secure` interaction are exact spec a chatbot gets subtly wrong —
and you want this gating session config on **every** PR, not once.

## Install

```bash
# run it now
npx cookie-doctor scan -c "<your Set-Cookie>"

# or add it
npm install -g cookie-doctor      # global CLI
npm install -D cookie-doctor      # CI dependency
```

Node ≥ 18. The core is dependency-free and browser-safe.

## Quick start

```bash
cookie-doctor scan -c "__Host-sid=abc; Secure; HttpOnly; SameSite=Lax; Path=/"
curl -sI https://example.com | cookie-doctor scan       # straight from a response
cookie-doctor scan headers.txt _headers vercel.json     # from configs
cookie-doctor scan -c "<cookie>" --min-score 80          # CI gate
cookie-doctor scan headers.txt --md cookies.md           # Markdown report
cookie-doctor init                                       # write a config
```

See [`examples/sample-report.md`](./examples/sample-report.md), and
[`examples/strong.cookie.txt`](./examples/strong.cookie.txt) for a cookie that
scores 100.

## What it checks

| Group | Examples |
| ----- | -------- |
| **Will be dropped by the browser** | `__Host-`/`__Secure-` prefix rules (Secure required, no Domain, `Path=/`), `SameSite=None` without `Secure`, invalid `SameSite`, oversized (> 4 KB) |
| **XSS / theft** | missing `HttpOnly` (error on session/token cookies) |
| **CSRF** | missing `SameSite` |
| **Transport** | missing `Secure` |
| **Scope** | `Domain` shared with subdomains, legacy leading-dot `Domain` |
| **Lifetime** | long-lived auth cookies (configurable threshold) |

Each finding is a weighted error / warning / info; the cookie rolls up to a 0–100
score and an A–F grade you can gate in CI.

## Real scenarios

**1. Gate session-cookie security in CI.** A PR that adds an auth cookie without
`HttpOnly`/`Secure`, or breaks a `__Host-` rule, fails the build:

```yaml
# .github/workflows/ci.yml
- run: curl -sI http://localhost:3000/login | npx cookie-doctor scan --min-score 90
```

**2. Audit what your framework actually sends.** Pipe a real response through it —
`express-session`, NextAuth, a reverse proxy — and see the attributes you *thought*
were set.

**3. Triage a security finding.** A scanner said "insecure cookie" — `cookie-doctor`
tells you *which* attribute and *why*, with the exact fix.

## Configuration

`cookie-doctor init` writes `cookie-doctor.config.json`:

```jsonc
{
  "ignore": [],                                  // rule ids to skip
  "sessionNames": ["session", "sid", "auth", "token", "jwt", "..."],
  "maxAgeDays": 30,                              // warn above this lifetime
  "minScore": 0                                  // CI gate threshold
}
```

## Library API

```ts
import { analyzeSetCookie, DEFAULT_CONFIG } from "cookie-doctor";

const report = analyzeSetCookie("inline", "sid=abc; Secure", DEFAULT_CONFIG, Date.now());
for (const f of report.findings) console.log(f.severity, f.rule, f.attribute);
```

Also exported: `parseSetCookie`, `checkCookie`, `extractCookies`, `lifetimeSeconds`,
and types. The core has zero runtime dependencies.

## Roadmap

- 🤖 **Optional `--ai` layer (bring-your-own key)** to explain a cookie's risk in
  context / suggest a hardened header. The core stays 100% offline and deterministic.
- `Partitioned` (CHIPS) attribute awareness.
- Read cookies from a saved `.har` or a browser cookie export.
- ✅ **A browser playground** — paste a `Set-Cookie`, see the audit, nothing uploaded.
  [Live here](https://didrod205.github.io/cookie-doctor/).

## 💖 Sponsor

cookie-doctor is free and MIT-licensed, built and maintained in spare time. If it
caught an insecure cookie before your users did, please consider supporting it:

- ⭐ **Star this repo** — the simplest free way to help others find it.
- 🍋 **[Sponsor via Lemon Squeezy](https://elab-studio.lemonsqueezy.com/checkout/buy/5d059b89-51d0-456b-b33a-ed56994f7010)** — one-time or recurring.

## License

[MIT](./LICENSE) © cookie-doctor contributors

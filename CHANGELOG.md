# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-06-05

Docs/metadata release — the published library and CLI (`dist/`) are unchanged
from 0.1.0.

### Added

- A **browser playground** — paste a Set-Cookie and see its security holes, entirely
  client-side (the same pure analysis core, incl. the prefix rules; nothing uploaded).
  Live at <https://didrod205.github.io/cookie-doctor/>. README now links it.
- Internal: the playground source (`web/`, built to `docs/` for GitHub Pages). Not
  part of the npm package.

## [0.1.0] - 2026-06-05

Initial public release.

### Added

- **Set-Cookie security linting**: missing `HttpOnly` / `Secure` / `SameSite`,
  `SameSite=None` without `Secure`, invalid `SameSite`, over-broad `Domain`
  (and legacy leading-dot), long-lived cookies, and oversized (> 4 KB) cookies.
- **Cookie-prefix rules** (`__Host-` / `__Secure-`): Secure required, no `Domain`,
  `Path=/` — the violations that make the browser silently reject a cookie, flagged
  as "validity" errors.
- **Session-aware severity**: a missing `HttpOnly`/`Secure` is an error on
  session/auth/JWT-valued cookies and a warning on benign ones (configurable
  `sessionNames`).
- **Extraction** from a raw `Set-Cookie`, an HTTP response (`curl -I`), nginx
  `add_header`, Apache `Header set`, and JSON configs (vercel.json).
- `scan` / `report` / `init` CLI with `--cookie`, stdin, JSON/Markdown export, and a
  CI score gate. Zero-dependency, browser-safe core; library API + types.

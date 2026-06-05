/**
 * The Set-Cookie security rule set. The deterministic moat is the cookie-prefix
 * spec (`__Host-`/`__Secure-`) and the `SameSite=None` ↔ `Secure` interaction:
 * get these wrong and the browser *silently drops the cookie*, so they're
 * "validity" errors, not style nits.
 */

import { getAttr, hasAttr, lifetimeSeconds } from "./parse.js";
import type { Config, Cookie, Finding } from "./types.js";

const JWT_RE = /^eyJ[A-Za-z0-9_-]+\./;

/** Heuristic: does this cookie look like a session/auth credential? */
export function isSession(cookie: Cookie, config: Config): boolean {
  const name = cookie.name.toLowerCase();
  if (config.sessionNames.some((s) => name.includes(s.toLowerCase()))) return true;
  return JWT_RE.test(cookie.value) || cookie.value.length >= 40;
}

/** Cookie-prefix rules — violations make the browser reject the cookie outright. */
export function checkValidity(cookie: Cookie, _config: Config): Finding[] {
  const out: Finding[] = [];
  const secure = hasAttr(cookie, "secure");
  const samesite = (getAttr(cookie, "samesite") ?? "").toLowerCase();

  if (cookie.prefix === "__Host-" || cookie.prefix === "__Secure-") {
    if (!secure) {
      out.push({
        rule: "prefix-needs-secure",
        category: "validity",
        severity: "error",
        attribute: "Secure",
        title: `${cookie.prefix} prefix without Secure`,
        message: `A \`${cookie.prefix}\` cookie must be Secure, or the browser rejects it (it never gets set).`,
        fix: "Add `Secure`.",
      });
    }
  }
  if (cookie.prefix === "__Host-") {
    if (hasAttr(cookie, "domain")) {
      out.push({
        rule: "host-prefix-domain",
        category: "validity",
        severity: "error",
        attribute: "Domain",
        title: "__Host- prefix with a Domain attribute",
        message: "A `__Host-` cookie must NOT set Domain — with it, the browser rejects the cookie.",
        fix: "Remove the Domain attribute (the cookie becomes host-only, which is the point of __Host-).",
      });
    }
    if (getAttr(cookie, "path") !== "/") {
      out.push({
        rule: "host-prefix-path",
        category: "validity",
        severity: "error",
        attribute: "Path",
        title: "__Host- prefix without Path=/",
        message: "A `__Host-` cookie must set `Path=/` exactly — otherwise the browser rejects it.",
        fix: "Set `Path=/`.",
      });
    }
  }

  if (samesite === "none" && !secure) {
    out.push({
      rule: "samesite-none-insecure",
      category: "validity",
      severity: "error",
      attribute: "SameSite",
      title: "SameSite=None without Secure",
      message: "`SameSite=None` requires `Secure` — without it, modern browsers reject the cookie.",
      fix: "Add `Secure` (or drop SameSite=None if the cookie isn't used cross-site).",
    });
  }
  if (samesite && !["strict", "lax", "none"].includes(samesite)) {
    out.push({
      rule: "samesite-invalid",
      category: "validity",
      severity: "warning",
      attribute: "SameSite",
      title: `Invalid SameSite value "${getAttr(cookie, "samesite")}"`,
      message: "SameSite must be Strict, Lax, or None; an unknown value is treated as the default.",
      fix: "Use SameSite=Strict, Lax, or None.",
    });
  }

  if (cookie.bytes > 4096) {
    out.push({
      rule: "oversized",
      category: "validity",
      severity: "warning",
      title: `Cookie is ${cookie.bytes} bytes (> 4096)`,
      message: "Browsers cap a cookie at ~4 KB; a larger one may be truncated or dropped.",
      fix: "Store a reference (an opaque id) in the cookie and keep the data server-side.",
    });
  }
  return out;
}

export function checkXss(cookie: Cookie, config: Config): Finding[] {
  if (hasAttr(cookie, "httponly")) return [];
  const sensitive = isSession(cookie, config);
  return [
    {
      rule: "no-httponly",
      category: "xss",
      severity: sensitive ? "error" : "warning",
      attribute: "HttpOnly",
      title: "No HttpOnly",
      message: sensitive
        ? "This looks like a session/token cookie, but JavaScript (and any XSS) can read it."
        : "JavaScript can read this cookie; if no client code needs it, add HttpOnly.",
      fix: "Add `HttpOnly` unless client-side JS genuinely needs to read the cookie.",
    },
  ];
}

export function checkTransport(cookie: Cookie, config: Config): Finding[] {
  if (hasAttr(cookie, "secure")) return [];
  const sensitive = isSession(cookie, config);
  return [
    {
      rule: "no-secure",
      category: "transport",
      severity: sensitive ? "error" : "warning",
      attribute: "Secure",
      title: "No Secure",
      message: "Without Secure, the cookie is sent over plaintext HTTP and can be sniffed or MITM'd.",
      fix: "Add `Secure` (and consider the `__Host-` prefix for session cookies).",
    },
  ];
}

export function checkCsrf(cookie: Cookie, _config: Config): Finding[] {
  if (hasAttr(cookie, "samesite")) return [];
  return [
    {
      rule: "no-samesite",
      category: "csrf",
      severity: "warning",
      attribute: "SameSite",
      title: "No SameSite",
      message: "Relying on the browser's default (Lax). Set it explicitly — Strict or Lax defends against CSRF.",
      fix: "Add `SameSite=Lax` (or `Strict` for sensitive actions).",
    },
  ];
}

export function checkScope(cookie: Cookie, config: Config): Finding[] {
  const out: Finding[] = [];
  const domain = getAttr(cookie, "domain");
  if (domain) {
    out.push({
      rule: "broad-domain",
      category: "scope",
      severity: isSession(cookie, config) ? "warning" : "info",
      attribute: "Domain",
      title: `Domain=${domain} shares the cookie with subdomains`,
      message: "Setting Domain sends the cookie to every subdomain — including any that's less trusted or attacker-controlled.",
      fix: "Omit Domain for a host-only cookie (the default and most secure).",
    });
    if (domain.startsWith(".")) {
      out.push({
        rule: "leading-dot-domain",
        category: "scope",
        severity: "info",
        attribute: "Domain",
        title: "Leading-dot Domain is legacy",
        message: "A leading dot (`.example.com`) is ignored by modern browsers; the scope already includes subdomains.",
        fix: "Drop the leading dot for clarity.",
      });
    }
  }
  return out;
}

export function checkLifetime(cookie: Cookie, config: Config, now: number): Finding[] {
  const life = lifetimeSeconds(cookie, now);
  if (life === null || life <= 0) return [];
  const maxSec = config.maxAgeDays * 86400;
  if (life > maxSec) {
    const days = Math.round(life / 86400);
    return [
      {
        rule: "long-lived",
        category: "lifetime",
        severity: "warning",
        attribute: "Max-Age",
        title: `Lives ~${days} days`,
        message: "A long-lived auth cookie widens the blast radius if it's ever stolen (and browsers cap at ~400 days anyway).",
        fix: `Shorten the lifetime (≤ ${config.maxAgeDays} days) and refresh sessions instead.`,
      },
    ];
  }
  return [];
}

export function checkCookie(cookie: Cookie, config: Config, now: number): Finding[] {
  return [
    ...checkValidity(cookie, config),
    ...checkXss(cookie, config),
    ...checkTransport(cookie, config),
    ...checkCsrf(cookie, config),
    ...checkScope(cookie, config),
    ...checkLifetime(cookie, config, now),
  ];
}

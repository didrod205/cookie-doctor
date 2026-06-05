/**
 * Parse a `Set-Cookie` header value into a structured {@link Cookie}. The grammar
 * is `name=value` followed by `;`-separated attributes; attribute names are
 * case-insensitive, and flag attributes (Secure, HttpOnly, Partitioned) carry no
 * value. Cookie-name prefixes (`__Host-`, `__Secure-`) are case-sensitive.
 */

import type { Cookie } from "./types.js";

export function parseSetCookie(raw: string, label?: string): Cookie {
  const trimmed = raw.replace(/^set-cookie:\s*/i, "").trim();
  const segments = trimmed.split(";");
  const first = (segments[0] ?? "").trim();

  const eq = first.indexOf("=");
  const name = eq >= 0 ? first.slice(0, eq).trim() : first;
  const value = eq >= 0 ? first.slice(eq + 1).trim() : "";

  const attributes = new Map<string, string>();
  for (const seg of segments.slice(1)) {
    const part = seg.trim();
    if (!part) continue;
    const i = part.indexOf("=");
    const key = (i >= 0 ? part.slice(0, i) : part).trim().toLowerCase();
    const val = i >= 0 ? part.slice(i + 1).trim() : "";
    if (key && !attributes.has(key)) attributes.set(key, val);
  }

  const prefix = name.startsWith("__Host-")
    ? "__Host-"
    : name.startsWith("__Secure-")
      ? "__Secure-"
      : null;

  return {
    name,
    value,
    attributes,
    prefix,
    bytes: new TextEncoder().encode(trimmed).length,
    raw: trimmed,
    label,
  };
}

export function hasAttr(cookie: Cookie, name: string): boolean {
  return cookie.attributes.has(name.toLowerCase());
}

export function getAttr(cookie: Cookie, name: string): string | undefined {
  return cookie.attributes.get(name.toLowerCase());
}

/**
 * Effective lifetime in seconds: Max-Age wins over Expires (per spec). Returns
 * null for a session cookie (neither set), and a negative number for an
 * already-expired deletion cookie.
 */
export function lifetimeSeconds(cookie: Cookie, now: number): number | null {
  const maxAge = getAttr(cookie, "max-age");
  if (maxAge !== undefined && /^-?\d+$/.test(maxAge)) return Number(maxAge);

  const expires = getAttr(cookie, "expires");
  if (expires) {
    const t = Date.parse(expires);
    if (!Number.isNaN(t)) return Math.round((t - now) / 1000);
  }
  return null;
}

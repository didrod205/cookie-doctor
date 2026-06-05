import { describe, expect, it } from "vitest";
import { parseSetCookie } from "../src/parse.js";
import { checkCookie } from "../src/checks.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import type { Config } from "../src/types.js";

const NOW = 1_700_000_000_000;
const rules = (raw: string, config: Config = DEFAULT_CONFIG) =>
  checkCookie(parseSetCookie(raw), config, NOW).map((f) => f.rule);
const find = (raw: string, rule: string) =>
  checkCookie(parseSetCookie(raw), DEFAULT_CONFIG, NOW).find((f) => f.rule === rule);

describe("__Host- / __Secure- prefix rules (the moat)", () => {
  it("requires Secure on a prefixed cookie", () => {
    expect(rules("__Host-x=1; Path=/")).toContain("prefix-needs-secure");
    expect(rules("__Secure-x=1")).toContain("prefix-needs-secure");
  });
  it("forbids Domain and requires Path=/ on __Host-", () => {
    const r = rules("__Host-x=1; Secure; Domain=example.com; Path=/app");
    expect(r).toContain("host-prefix-domain");
    expect(r).toContain("host-prefix-path");
  });
  it("a correct __Host- cookie passes the prefix checks", () => {
    const r = rules("__Host-x=1; Secure; Path=/");
    expect(r).not.toContain("prefix-needs-secure");
    expect(r).not.toContain("host-prefix-domain");
    expect(r).not.toContain("host-prefix-path");
  });
});

describe("SameSite=None ↔ Secure", () => {
  it("errors on SameSite=None without Secure", () => {
    expect(find("x=1; SameSite=None", "samesite-none-insecure")?.severity).toBe("error");
  });
  it("is fine with SameSite=None and Secure", () => {
    expect(rules("x=1; SameSite=None; Secure")).not.toContain("samesite-none-insecure");
  });
  it("flags an invalid SameSite value", () => {
    expect(rules("x=1; SameSite=Strictt; Secure")).toContain("samesite-invalid");
  });
});

describe("HttpOnly / Secure severity by session-ness", () => {
  it("errors for a session-named cookie, warns for a benign one", () => {
    expect(find("sid=abc; Secure; SameSite=Lax", "no-httponly")?.severity).toBe("error");
    expect(find("theme=dark; Secure; SameSite=Lax", "no-httponly")?.severity).toBe("warning");
  });
  it("treats a JWT-valued cookie as sensitive", () => {
    expect(find("x=eyJhbGciOiJIUzI1NiJ9.payload.sig; Secure", "no-httponly")?.severity).toBe("error");
  });
});

describe("scope, csrf, lifetime", () => {
  it("flags a Domain attribute and a leading dot", () => {
    const r = rules("sid=a; Secure; HttpOnly; SameSite=Lax; Domain=.example.com");
    expect(r).toContain("broad-domain");
    expect(r).toContain("leading-dot-domain");
  });
  it("warns when SameSite is absent", () => {
    expect(rules("x=1; Secure")).toContain("no-samesite");
  });
  it("flags a long-lived cookie", () => {
    expect(rules("x=1; Secure; HttpOnly; SameSite=Lax; Max-Age=31536000")).toContain("long-lived");
    expect(rules("x=1; Secure; HttpOnly; SameSite=Lax; Max-Age=600")).not.toContain("long-lived");
  });
  it("oversized cookies are flagged", () => {
    expect(rules(`x=${"a".repeat(5000)}; Secure`)).toContain("oversized");
  });
});

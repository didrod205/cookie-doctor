import { describe, expect, it } from "vitest";
import { parseSetCookie, hasAttr, getAttr, lifetimeSeconds } from "../src/parse.js";

describe("parseSetCookie", () => {
  it("parses name, value and attributes", () => {
    const c = parseSetCookie("sid=abc123; Path=/; HttpOnly; SameSite=Lax");
    expect(c.name).toBe("sid");
    expect(c.value).toBe("abc123");
    expect(getAttr(c, "path")).toBe("/");
    expect(getAttr(c, "samesite")).toBe("Lax");
    expect(hasAttr(c, "httponly")).toBe(true);
    expect(hasAttr(c, "secure")).toBe(false);
  });

  it("strips a leading 'Set-Cookie:' and is attribute-case-insensitive", () => {
    const c = parseSetCookie("Set-Cookie: a=b; SECURE; httponly");
    expect(c.name).toBe("a");
    expect(hasAttr(c, "secure")).toBe(true);
    expect(hasAttr(c, "HttpOnly")).toBe(true);
  });

  it("detects __Host- and __Secure- prefixes (case-sensitive)", () => {
    expect(parseSetCookie("__Host-x=1").prefix).toBe("__Host-");
    expect(parseSetCookie("__Secure-x=1").prefix).toBe("__Secure-");
    expect(parseSetCookie("__host-x=1").prefix).toBeNull();
    expect(parseSetCookie("x=1").prefix).toBeNull();
  });

  it("handles a value containing '='", () => {
    expect(parseSetCookie("t=ab=cd==; Secure").value).toBe("ab=cd==");
  });
});

describe("lifetimeSeconds", () => {
  const NOW = 1_700_000_000_000; // fixed epoch ms
  it("reads Max-Age (seconds), which wins over Expires", () => {
    expect(lifetimeSeconds(parseSetCookie("a=b; Max-Age=3600"), NOW)).toBe(3600);
  });
  it("computes seconds-until-Expires", () => {
    const future = new Date(NOW + 7200_000).toUTCString();
    expect(lifetimeSeconds(parseSetCookie(`a=b; Expires=${future}`), NOW)).toBe(7200);
  });
  it("returns null for a session cookie", () => {
    expect(lifetimeSeconds(parseSetCookie("a=b"), NOW)).toBeNull();
  });
});

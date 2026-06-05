import { describe, expect, it } from "vitest";
import { extractCookies } from "../src/extract.js";

describe("extractCookies", () => {
  it("pulls Set-Cookie lines from an HTTP response dump", () => {
    const dump = "HTTP/2 200\ncontent-type: text/html\nset-cookie: a=1; Path=/\nset-cookie: b=2; Secure\n";
    const r = extractCookies(dump);
    expect(r.map((x) => x.cookie)).toEqual(["a=1; Path=/", "b=2; Secure"]);
    expect(r[0]!.label).toBe("header");
  });

  it("pulls from an nginx add_header directive", () => {
    const conf = `add_header Set-Cookie "sid=x; HttpOnly; Secure";`;
    expect(extractCookies(conf)[0]!.cookie).toBe("sid=x; HttpOnly; Secure");
  });

  it("pulls from a vercel.json-style config", () => {
    const json = JSON.stringify({
      headers: [{ source: "/(.*)", headers: [{ key: "Set-Cookie", value: "sid=x; Secure" }] }],
    });
    expect(extractCookies(json)[0]!.cookie).toBe("sid=x; Secure");
  });

  it("treats bare lines as one cookie each", () => {
    const r = extractCookies("sid=a; Secure\ncsrf=b; HttpOnly");
    expect(r).toHaveLength(2);
    expect(r[1]!.cookie).toBe("csrf=b; HttpOnly");
  });

  it("returns nothing for empty input", () => {
    expect(extractCookies("   ")).toHaveLength(0);
  });
});

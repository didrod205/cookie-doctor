import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { analyzeSetCookie, buildReport } from "../src/analyze.js";
import { loadFromContent } from "../src/loader.js";
import { parseSetCookie } from "../src/parse.js";
import { analyzeCookie } from "../src/analyze.js";
import { DEFAULT_CONFIG, parseConfig, mergeConfig } from "../src/config.js";

const NOW = 1_700_000_000_000;
const META = { version: "test", generatedAt: "2026-06-05T00:00:00Z" };
const read = (f: string) => readFileSync(resolve("examples", f), "utf8");

function analyzeContent(content: string) {
  return loadFromContent(content, "t").map((i) =>
    analyzeCookie(i.source, parseSetCookie(i.cookie, i.source), DEFAULT_CONFIG, NOW),
  );
}

describe("analyze (integration over examples)", () => {
  it("gives a hardened __Host- cookie a perfect score", () => {
    const r = analyzeSetCookie("s", read("strong.cookie.txt").trim(), DEFAULT_CONFIG, NOW);
    expect(r.grade).toBe("A");
    expect(r.findings).toHaveLength(0);
  });

  it("fails the weak cookies and catches every prefix violation", () => {
    const reports = analyzeContent(read("weak.cookie.txt"));
    expect(reports.length).toBe(4);
    const hostToken = reports.find((c) => c.name === "__Host-token")!;
    const ids = new Set(hostToken.findings.map((f) => f.rule));
    expect(ids.has("prefix-needs-secure")).toBe(true);
    expect(ids.has("host-prefix-domain")).toBe(true);
    expect(ids.has("host-prefix-path")).toBe(true);
    expect(hostToken.grade).toBe("F");
  });

  it("respects the ignore list", () => {
    const cfg = { ...DEFAULT_CONFIG, ignore: ["no-httponly"] };
    const r = analyzeSetCookie("t", "sid=a", cfg, NOW);
    expect(r.findings.some((f) => f.rule === "no-httponly")).toBe(false);
  });

  it("buildReport aggregates cookies", () => {
    const report = buildReport(analyzeContent(read("weak.cookie.txt")), META);
    expect(report.tool).toBe("cookie-doctor");
    expect(report.summary.cookies).toBe(4);
    expect(report.summary.errors).toBeGreaterThan(0);
  });
});

describe("config", () => {
  it("parses and merges over defaults", () => {
    const cfg = parseConfig(JSON.stringify({ minScore: 80, maxAgeDays: 7 }));
    expect(cfg.minScore).toBe(80);
    expect(cfg.maxAgeDays).toBe(7);
    expect(cfg.sessionNames).toEqual(DEFAULT_CONFIG.sessionNames);
  });
  it("throws on invalid JSON, ignores undefined overrides", () => {
    expect(() => parseConfig("{ bad")).toThrow(/invalid config/);
    expect(mergeConfig(DEFAULT_CONFIG, { minScore: undefined as unknown as number }).minScore).toBe(0);
  });
});

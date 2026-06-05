/** Orchestrator: parse + lint Set-Cookie values and assemble reports. */

import { checkCookie } from "./checks.js";
import { parseSetCookie } from "./parse.js";
import { gradeFor, scoreFindings } from "./score.js";
import type { Config, Cookie, CookieReport, Finding, Report } from "./types.js";

const SEVERITY_ORDER: Record<string, number> = { error: 0, warning: 1, info: 2, pass: 3 };

/** Analyze a single parsed cookie (pure; `now` in epoch milliseconds). */
export function analyzeCookie(source: string, cookie: Cookie, config: Config, now: number): CookieReport {
  const ignore = new Set(config.ignore);
  const findings: Finding[] = checkCookie(cookie, config, now)
    .filter((f) => !ignore.has(f.rule))
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));

  const counts = { error: 0, warning: 0, info: 0 };
  for (const f of findings) {
    if (f.severity === "error") counts.error++;
    else if (f.severity === "warning") counts.warning++;
    else if (f.severity === "info") counts.info++;
  }
  const score = scoreFindings(findings);
  return { source, name: cookie.name, score, grade: gradeFor(score), counts, findings };
}

/** Convenience: parse a Set-Cookie string and analyze it. */
export function analyzeSetCookie(source: string, raw: string, config: Config, now: number): CookieReport {
  return analyzeCookie(source, parseSetCookie(raw, source), config, now);
}

export function buildReport(
  cookies: CookieReport[],
  meta: { version: string; generatedAt: string },
): Report {
  const errors = cookies.reduce((s, c) => s + c.counts.error, 0);
  const warnings = cookies.reduce((s, c) => s + c.counts.warning, 0);
  const infos = cookies.reduce((s, c) => s + c.counts.info, 0);
  const score = cookies.length
    ? Math.round(cookies.reduce((s, c) => s + c.score, 0) / cookies.length)
    : 100;

  return {
    tool: "cookie-doctor",
    version: meta.version,
    generatedAt: meta.generatedAt,
    summary: { cookies: cookies.length, score, grade: gradeFor(score), errors, warnings, infos },
    cookies,
  };
}

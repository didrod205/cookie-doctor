/**
 * cookie-doctor playground — lint Set-Cookie headers entirely in the browser.
 * Reuses the library's pure analysis core (parse + the prefix-spec rules). Your
 * cookies never leave the page — a local-first alternative to scanning a live URL
 * with an online header checker.
 */

import { analyzeSetCookie } from "../src/analyze.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import { extractCookies } from "../src/extract.js";
import { CATEGORY_LABELS, type CookieReport, type Severity } from "../src/types.js";

const SAMPLE = `set-cookie: sid=a1b2c3d4e5
set-cookie: __Host-token=xyz; Path=/app; Domain=example.com
set-cookie: auth=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig; SameSite=None; Max-Age=31536000
set-cookie: __Host-session=ok; Path=/; Secure; HttpOnly; SameSite=Lax`;

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

const ICON: Record<Severity, string> = { error: "✗", warning: "⚠", info: "ℹ", pass: "✓" };

function gradeClass(grade: string): string {
  if (grade === "A" || grade === "B") return "grade-A";
  if (grade === "C" || grade === "D") return "grade-C";
  return "grade-F";
}

function findingRows(report: CookieReport): string {
  if (report.findings.length === 0) return `<div class="ok">✓ Secure — nothing to fix.</div>`;
  return report.findings
    .map(
      (f) => `<div class="finding sev-${f.severity}">
        <span class="finding-icon">${ICON[f.severity]}</span>
        <div class="finding-body">
          <div class="finding-title">${esc(f.title)}
            <span class="cat-tag">${esc(CATEGORY_LABELS[f.category])}</span>
            ${f.attribute ? `<span class="dir-tag">${esc(f.attribute)}</span>` : ""}
          </div>
          <div class="finding-msg">${esc(f.message)}</div>
          ${f.fix ? `<div class="finding-fix">→ ${esc(f.fix)}</div>` : ""}
        </div>
      </div>`,
    )
    .join("");
}

function renderReport(report: CookieReport): string {
  return `<div class="pane">
    <h2><code class="cookie-name">${esc(report.name)}</code>
      <span class="score-badge ${gradeClass(report.grade)}">${report.score}/100 (${report.grade})</span></h2>
    ${findingRows(report)}
  </div>`;
}

function render(): void {
  const value = $<HTMLTextAreaElement>("input").value;
  const out = $("output");
  if (!value.trim()) {
    out.classList.add("hidden");
    return;
  }
  const now = Date.now();
  const reports = extractCookies(value).map((e) => analyzeSetCookie(e.label, e.cookie, DEFAULT_CONFIG, now));
  out.classList.remove("hidden");
  out.innerHTML =
    reports.map(renderReport).join("") ||
    `<div class="pane muted">No Set-Cookie detected — paste a cookie or a curl -I response.</div>`;
}

function init(): void {
  $<HTMLTextAreaElement>("input").addEventListener("input", render);
  $("sample").addEventListener("click", () => {
    $<HTMLTextAreaElement>("input").value = SAMPLE;
    render();
  });
  $("clear").addEventListener("click", () => {
    $<HTMLTextAreaElement>("input").value = "";
    render();
  });
}

init();

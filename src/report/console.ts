/** Colored console output for `scan`. */

import pc from "picocolors";
import type { Report, Severity } from "../types.js";

const MARK: Record<Severity, string> = { error: "✗", warning: "⚠", info: "ℹ", pass: "✓" };

function color(severity: Severity, text: string): string {
  if (severity === "error") return pc.red(text);
  if (severity === "warning") return pc.yellow(text);
  if (severity === "info") return pc.blue(text);
  return pc.green(text);
}

function gradeColor(grade: string): (s: string) => string {
  if (grade === "A" || grade === "B") return pc.green;
  if (grade === "C" || grade === "D") return pc.yellow;
  return pc.red;
}

export function printReport(report: Report, quiet = false): void {
  for (const c of report.cookies) {
    const g = gradeColor(c.grade);
    console.log(`\n${pc.bold(c.name)}  ${g(`${c.score}/100 (${c.grade})`)} ${pc.dim(`· ${c.source}`)}`);
    if (quiet) continue;
    if (c.findings.length === 0) {
      console.log(`  ${pc.green("✓ no issues found")}`);
      continue;
    }
    for (const f of c.findings) {
      const attr = f.attribute ? pc.dim(`[${f.attribute}]`) : "";
      console.log(`  ${color(f.severity, MARK[f.severity])} ${f.title} ${attr} ${pc.dim(f.rule)}`);
      if (f.fix) console.log(`      ${pc.dim("→ " + f.fix.split("\n")[0])}`);
    }
  }

  const s = report.summary;
  const g = gradeColor(s.grade);
  console.log(
    `\n${pc.bold("Overall")}  ${g(`${s.score}/100 (${s.grade})`)} ` +
      pc.dim(`· ${s.cookies} cookie(s), ${s.errors} error(s), ${s.warnings} warning(s), ${s.infos} info(s)`),
  );
}

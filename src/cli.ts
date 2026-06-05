#!/usr/bin/env node
/** cookie-doctor command-line interface. */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { cac } from "cac";
import pc from "picocolors";
import pkg from "../package.json";
import { analyzeCookie, buildReport } from "./analyze.js";
import { DEFAULT_CONFIG } from "./config.js";
import { loadConfig } from "./load-config.js";
import { loadFromContent, loadInputs, readStdin, type InputCookie } from "./loader.js";
import { parseSetCookie } from "./parse.js";
import { printReport } from "./report/console.js";
import { toJSON } from "./report/json.js";
import { toMarkdown } from "./report/markdown.js";
import type { Config, CookieReport, Report } from "./types.js";

const cli = cac("cookie-doctor");

function fail(message: string): never {
  console.error(`${pc.red("cookie-doctor:")} ${message}`);
  process.exit(2);
}

interface ScanOptions {
  cookie?: string;
  config?: string;
  ignore?: string;
  json?: string;
  md?: string;
  minScore?: string;
  quiet?: boolean;
}

cli
  .command("scan [...files]", "Lint Set-Cookie values from a string, files, or stdin")
  .option("-c, --cookie <set-cookie>", "Lint this Set-Cookie value directly")
  .option("--config <file>", "Path to a config file")
  .option("--ignore <rules>", "Comma-separated rule ids to ignore")
  .option("--json <file>", "Write a JSON report to this path")
  .option("--md <file>", "Write a Markdown report to this path")
  .option("--min-score <n>", "CI gate: exit non-zero if the overall score is below this")
  .option("--quiet", "Show only per-cookie summary lines")
  .example('  cookie-doctor scan -c "sid=abc; HttpOnly"')
  .example("  curl -sI https://example.com | cookie-doctor scan")
  .example("  cookie-doctor scan headers.txt --min-score 80")
  .action((files: string[], options: ScanOptions) => {
    try {
      const config: Config = loadConfig(options.config);
      if (options.ignore) {
        config.ignore = [...config.ignore, ...options.ignore.split(",").map((s) => s.trim()).filter(Boolean)];
      }

      const inputs: InputCookie[] = [];
      if (options.cookie) inputs.push({ source: "cookie", cookie: options.cookie });
      if (files && files.length > 0) inputs.push(...loadInputs(files));
      if (inputs.length === 0) {
        if (process.stdin.isTTY) fail("provide a --cookie string, a file, or pipe a response via stdin.");
        inputs.push(...loadFromContent(readStdin(), "<stdin>"));
      }
      if (inputs.length === 0) fail("no Set-Cookie value found in the input.");

      const now = Date.now();
      const cookies: CookieReport[] = inputs.map((i) =>
        analyzeCookie(i.source, parseSetCookie(i.cookie, i.source), config, now),
      );

      const report = buildReport(cookies, {
        version: pkg.version,
        generatedAt: new Date().toISOString(),
      });

      printReport(report, Boolean(options.quiet));

      if (options.json) {
        writeFileSync(resolve(options.json), toJSON(report));
        console.log(pc.dim(`\nWrote JSON report → ${options.json}`));
      }
      if (options.md) {
        writeFileSync(resolve(options.md), toMarkdown(report));
        console.log(pc.dim(`Wrote Markdown report → ${options.md}`));
      }

      const minScore = options.minScore !== undefined ? Number(options.minScore) : config.minScore;
      if (report.summary.score < minScore) {
        console.error(`\n${pc.red("cookie-doctor:")} score ${report.summary.score} is below the minimum ${minScore}.`);
        process.exit(1);
      }
    } catch (e) {
      fail((e as Error).message);
    }
  });

cli
  .command("report <input>", "Render a saved JSON report as Markdown")
  .option("--md <file>", "Write Markdown to this path instead of stdout")
  .action((input: string, options: { md?: string }) => {
    try {
      const report = JSON.parse(readFileSync(resolve(input), "utf8")) as Report;
      const md = toMarkdown(report);
      if (options.md) {
        writeFileSync(resolve(options.md), md);
        console.log(`Wrote ${options.md}`);
      } else {
        process.stdout.write(md);
      }
    } catch (e) {
      fail((e as Error).message);
    }
  });

cli
  .command("init", "Write a cookie-doctor.config.json with the defaults")
  .option("--force", "Overwrite an existing config")
  .action((options: { force?: boolean }) => {
    const file = resolve("cookie-doctor.config.json");
    if (existsSync(file) && !options.force) {
      console.error(`${pc.red("cookie-doctor:")} cookie-doctor.config.json already exists (use --force).`);
      process.exit(1);
    }
    writeFileSync(file, JSON.stringify(DEFAULT_CONFIG, null, 2) + "\n");
    console.log("Created cookie-doctor.config.json");
  });

cli.help();
cli.version(pkg.version);
cli.parse();

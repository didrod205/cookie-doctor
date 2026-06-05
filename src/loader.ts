/** Read Set-Cookie values from files (or stdin) and extract them. */

import { readFileSync, statSync } from "node:fs";
import { relative, resolve } from "node:path";
import { extractCookies } from "./extract.js";

export interface InputCookie {
  source: string;
  cookie: string;
}

function label(source: string, kind: string, index: number, total: number): string {
  const parts = [source];
  if (kind !== "cookie") parts.push(`(${kind})`);
  if (total > 1) parts.push(`#${index + 1}`);
  return parts.join(" ");
}

export function loadFromContent(content: string, source: string): InputCookie[] {
  const extracted = extractCookies(content, "cookie");
  return extracted.map((e, i) => ({
    source: label(source, e.label, i, extracted.length),
    cookie: e.cookie,
  }));
}

export function loadInputs(targets: string[]): InputCookie[] {
  const out: InputCookie[] = [];
  const cwd = process.cwd();
  for (const target of targets) {
    const abs = resolve(target);
    try {
      if (!statSync(abs).isFile()) continue;
    } catch {
      throw new Error(`path not found: ${target}`);
    }
    const rel = abs.startsWith(cwd) ? relative(cwd, abs) || abs : abs;
    out.push(...loadFromContent(readFileSync(abs, "utf8"), rel));
  }
  return out;
}

export function readStdin(): string {
  try {
    return readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

/**
 * Pull `Set-Cookie` values out of whatever you paste: a raw cookie string,
 * an HTTP response (`curl -I` output, header dumps), an nginx `add_header` /
 * Apache `Header set` directive, or a JSON config (e.g. vercel.json).
 */

export interface Extracted {
  cookie: string;
  label: string;
}

const DIRECTIVE_RE = /(?:add_header|Header\s+set)\s+Set-Cookie\s+(?:"([^"]*)"|'([^']*)')/gi;
const HEADER_RE = /^[ \t]*set-cookie[ \t]*:[ \t]*(.+)$/gim;

function dedupe(items: Extracted[]): Extracted[] {
  const seen = new Set<string>();
  return items.filter((i) => {
    if (!i.cookie.trim()) return false;
    if (seen.has(i.cookie)) return false;
    seen.add(i.cookie);
    return true;
  });
}

function fromJson(content: string): Extracted[] {
  let data: unknown;
  try {
    data = JSON.parse(content);
  } catch {
    return [];
  }
  const out: Extracted[] = [];
  const push = (v: unknown) => {
    if (typeof v === "string") out.push({ cookie: v, label: "json" });
    else if (Array.isArray(v)) for (const x of v) if (typeof x === "string") out.push({ cookie: x, label: "json" });
  };
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) return node.forEach(walk);
    if (node && typeof node === "object") {
      const obj = node as Record<string, unknown>;
      const key = typeof obj.key === "string" ? obj.key.toLowerCase() : "";
      if (key === "set-cookie") push(obj.value);
      for (const [k, v] of Object.entries(obj)) {
        if (k.toLowerCase() === "set-cookie") push(v);
        else if (v && typeof v === "object") walk(v);
      }
    }
  };
  walk(data);
  return out;
}

export function extractCookies(content: string, label = "cookie"): Extracted[] {
  // 1. nginx / Apache directives.
  const directives: Extracted[] = [];
  let dm: RegExpExecArray | null;
  DIRECTIVE_RE.lastIndex = 0;
  while ((dm = DIRECTIVE_RE.exec(content)) !== null) {
    directives.push({ cookie: (dm[1] ?? dm[2])!, label: "header" });
  }
  if (directives.length) return dedupe(directives);

  // 2. JSON config.
  const json = fromJson(content);
  if (json.length) return dedupe(json);

  // 3. HTTP `Set-Cookie:` header lines (curl -I, response dumps).
  const headers: Extracted[] = [];
  let hm: RegExpExecArray | null;
  HEADER_RE.lastIndex = 0;
  while ((hm = HEADER_RE.exec(content)) !== null) {
    headers.push({ cookie: hm[1]!.trim(), label: "header" });
  }
  if (headers.length) return dedupe(headers);

  // 4. Raw — one cookie per non-empty line.
  const raw = content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && l.includes("="))
    .map((l) => ({ cookie: l, label }));
  return dedupe(raw);
}

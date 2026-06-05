/** Core types for cookie-doctor. */

export type Severity = "error" | "warning" | "info" | "pass";

export type Category = "validity" | "xss" | "csrf" | "transport" | "scope" | "lifetime";

export const CATEGORIES: Category[] = ["validity", "xss", "csrf", "transport", "scope", "lifetime"];

export const CATEGORY_LABELS: Record<Category, string> = {
  validity: "Will be dropped by the browser",
  xss: "XSS / theft",
  csrf: "CSRF",
  transport: "Transport security",
  scope: "Scope",
  lifetime: "Lifetime",
};

export interface Finding {
  rule: string;
  category: Category;
  severity: Severity;
  /** The cookie attribute this is about, when applicable. */
  attribute?: string;
  title: string;
  message: string;
  fix?: string;
}

/** A parsed Set-Cookie. Attribute keys are lowercased; flag attrs map to "". */
export interface Cookie {
  name: string;
  value: string;
  attributes: Map<string, string>;
  /** "__Host-" or "__Secure-" when the name carries a cookie prefix. */
  prefix: "__Host-" | "__Secure-" | null;
  /** Total serialized byte length (for the 4 KB limit check). */
  bytes: number;
  raw: string;
  /** Where this cookie came from (file, header, json, …). */
  label?: string;
}

export interface CookieReport {
  source: string;
  name: string;
  score: number;
  grade: string;
  counts: { error: number; warning: number; info: number };
  findings: Finding[];
}

export interface Report {
  tool: "cookie-doctor";
  version: string;
  generatedAt: string;
  summary: {
    cookies: number;
    score: number;
    grade: string;
    errors: number;
    warnings: number;
    infos: number;
  };
  cookies: CookieReport[];
}

export interface Config {
  /** Rule ids to ignore. */
  ignore: string[];
  /** Cookie-name substrings treated as session/auth (stricter HttpOnly/Secure). */
  sessionNames: string[];
  /** Warn when a cookie lives longer than this many days. */
  maxAgeDays: number;
  /** CI gate: minimum overall score. */
  minScore: number;
}

/**
 * cookie-doctor — lint Set-Cookie headers for security, locally and
 * deterministically. Flags missing HttpOnly/Secure/SameSite, the
 * SameSite=None↔Secure interaction, over-broad Domain, and the __Host-/__Secure-
 * prefix rules that make browsers silently drop a cookie. No website, no API key.
 *
 * ```ts
 * import { analyzeSetCookie, DEFAULT_CONFIG } from "cookie-doctor";
 * const report = analyzeSetCookie("inline", "sid=abc; Secure", DEFAULT_CONFIG, Date.now());
 * ```
 */

export { analyzeCookie, analyzeSetCookie, buildReport } from "./analyze.js";
export { parseSetCookie, hasAttr, getAttr, lifetimeSeconds } from "./parse.js";
export { extractCookies, type Extracted } from "./extract.js";
export {
  checkCookie,
  checkValidity,
  checkXss,
  checkTransport,
  checkCsrf,
  checkScope,
  checkLifetime,
  isSession,
} from "./checks.js";
export { scoreFindings, gradeFor } from "./score.js";
export { DEFAULT_CONFIG, CONFIG_FILENAMES, parseConfig, mergeConfig } from "./config.js";
export {
  CATEGORIES,
  CATEGORY_LABELS,
  type Category,
  type Config,
  type Cookie,
  type CookieReport,
  type Finding,
  type Report,
  type Severity,
} from "./types.js";

/**
 * Security primitives shared by the CDP session, browser manager and MCP tools.
 *
 * The defaults are intentionally conservative: secrets are redacted, only
 * loopback Chrome endpoints are accepted, and page automation requires the
 * "interactive" permission tier. No unsafe environment flag is needed for
 * ordinary navigation/click/type/scroll operations.
 */

export const PERMISSIONS = Object.freeze(['read-only', 'interactive', 'full-debug']);
const PERMISSION_LEVEL = Object.freeze({ 'read-only': 0, interactive: 1, 'full-debug': 2 });

const SECRET_HEADER = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token|x-amz-security-token|x-goog-api-key|x-goog-auth-user|x-access-token)$/i;
const SECRET_FIELD = /^(password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?id|private[_-]?key|token|authorization|cookie|set-cookie)$/i;
const SECRET_QUERY = /^(password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?id|token|auth|authorization|signature|sig|key|code)$/i;
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);
const HTTP_PROTOCOLS = new Set(['http:', 'https:']);

export class PermissionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PermissionError';
    this.code = 'EPERM';
  }
}

export function normalizePermission(value = process.env.DEVTOOLS_PERMISSION ?? process.env.CDP_PERMISSION) {
  if (value != null && String(value).trim() !== '') {
    const normalized = String(value).trim().toLowerCase();
    if (PERMISSIONS.includes(normalized)) return normalized;
    throw new PermissionError(`Invalid permission "${value}". Use read-only, interactive or full-debug.`);
  }
  // Backwards compatibility with the v0.1 flag.
  if (process.env.ALLOW_UNSAFE_CDP === '1') return 'full-debug';
  return 'interactive';
}

export function permissionLevel(permission) {
  return PERMISSION_LEVEL[permission] ?? -1;
}

export function permissionAtLeast(actual, required) {
  return permissionLevel(actual) >= permissionLevel(required);
}

export function assertPermission(actual, required, action = 'this operation') {
  if (!permissionAtLeast(actual, required)) {
    throw new PermissionError(
      `${action} requires the "${required}" permission tier; current tier is "${actual}". ` +
      'Set DEVTOOLS_PERMISSION=interactive (or full-debug) in the MCP environment.'
    );
  }
}

export function allowSensitiveData(permission, confirmSensitive = false, env = process.env) {
  return confirmSensitive === true && permission === 'full-debug' && env.DEVTOOLS_ALLOW_SENSITIVE === '1';
}

export function assertSensitiveAllowed(permission, confirmSensitive, action = 'sensitive data export') {
  if (!allowSensitiveData(permission, confirmSensitive)) {
    throw new PermissionError(
      `${action} is disabled by default. It requires DEVTOOLS_PERMISSION=full-debug, ` +
      'DEVTOOLS_ALLOW_SENSITIVE=1 and confirmSensitive=true.'
    );
  }
}

export function normalizePageUrl(raw, { allowAboutBlank = false } = {}) {
  if (typeof raw !== 'string') throw new Error('URL must be a string');
  const trimmed = raw.trim();
  if (!trimmed) throw new Error('URL must not be empty');
  if (trimmed.length > 8192) throw new Error('URL is too long (maximum 8192 characters)');
  if (allowAboutBlank && trimmed === 'about:blank') return trimmed;
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error('Invalid URL. Include a scheme, for example https://example.com/path');
  }
  if (!HTTP_PROTOCOLS.has(parsed.protocol)) {
    throw new Error('Only HTTP and HTTPS URLs are supported');
  }
  if (!parsed.hostname) throw new Error('URL has no hostname');
  if (parsed.username || parsed.password) {
    throw new Error('URLs containing embedded credentials are not accepted; use the site login form instead');
  }
  return parsed.href;
}

export function localHost(hostname) {
  return LOOPBACK_HOSTS.has(hostname);
}

export function normalizeEndpoint(endpoint = 'http://127.0.0.1:9222') {
  if (typeof endpoint !== 'string' || !endpoint.trim()) throw new Error('CDP_ENDPOINT must be a URL');
  let parsed;
  try {
    parsed = new URL(endpoint.trim());
  } catch {
    throw new Error('CDP_ENDPOINT is not a valid URL');
  }
  if (!isAllowedEndpoint(parsed.href)) {
    throw new Error('CDP endpoint must be a loopback HTTP endpoint (127.0.0.1 / localhost / ::1), or set CDP_ALLOW_REMOTE=1 explicitly');
  }
  return parsed.origin;
}

export function isAllowedEndpoint(endpoint) {
  try {
    const parsed = new URL(endpoint);
    if (parsed.protocol !== 'http:' || parsed.username || parsed.password) return false;
    if (localHost(parsed.hostname)) return true;
    return process.env.CDP_ALLOW_REMOTE === '1';
  } catch {
    return false;
  }
}

export function isAllowedWebSocket(raw, endpoint) {
  try {
    const ws = new URL(raw);
    const base = new URL(endpoint);
    if (ws.protocol !== 'ws:' || ws.port !== base.port) return false;
    if (localHost(ws.hostname) && localHost(base.hostname)) return true;
    return ws.hostname === base.hostname;
  } catch {
    return false;
  }
}

export function redactText(text, max = 8000) {
  if (text == null) return '';
  return String(text)
    .slice(0, max)
    .replace(/\bBearer\s+[^\s"']+/gi, 'Bearer [REDACTED]')
    .replace(/\b(Basic)\s+[A-Za-z0-9+/=]+/gi, '$1 [REDACTED]')
    .replace(/(["']?(?:password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?id|private[_-]?key|token|authorization)["']?\s*[:=]\s*["']?)[^"'\s,}\]]+/gi, '$1[REDACTED]')
    .replace(/([?&](?:password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?id|token|auth|authorization|signature|sig|key|code)=)[^&\s"']+/gi, '$1[REDACTED]');
}

function redactHeaderValue(value, includeSensitive) {
  if (Array.isArray(value)) return value.map(v => redactHeaderValue(v, includeSensitive));
  if (value == null) return value;
  return redactText(String(value), 2000);
}

export function redactHeaders(headers = {}, { includeSensitive = false } = {}) {
  if (!headers || typeof headers !== 'object') return {};
  return Object.fromEntries(Object.entries(headers).map(([key, value]) => [
    key,
    !includeSensitive && SECRET_HEADER.test(key) ? '[REDACTED]' : redactHeaderValue(value, includeSensitive)
  ]));
}

export function redactUrl(raw = '', { includeSensitive = false } = {}) {
  if (raw == null) return '';
  try {
    const url = new URL(String(raw));
    url.hash = '';
    if (url.username) url.username = '[REDACTED]';
    if (url.password) url.password = '[REDACTED]';
    if (!includeSensitive) {
      for (const key of [...url.searchParams.keys()]) {
        if (SECRET_QUERY.test(key)) url.searchParams.set(key, '[REDACTED]');
      }
    }
    return url.href.slice(0, 2000);
  } catch {
    return redactText(raw, 2000);
  }
}

export function redactJsonish(raw, { includeSensitive = false } = {}, depth = 0) {
  if (depth > 8) return '[max depth]';
  if (typeof raw === 'string') return includeSensitive ? raw.slice(0, 20000) : redactText(raw, 20000);
  if (!raw || typeof raw !== 'object') return raw;
  if (Array.isArray(raw)) return raw.slice(0, 200).map(item => redactJsonish(item, { includeSensitive }, depth + 1));
  return Object.fromEntries(Object.entries(raw).map(([key, value]) => [
    key,
    !includeSensitive && SECRET_FIELD.test(key) ? '[REDACTED]' : redactJsonish(value, { includeSensitive }, depth + 1)
  ]));
}

export function safeResponseBody(raw, maxChars = 12000, { includeSensitive = false } = {}) {
  if (!raw || typeof raw !== 'object') {
    return { binary: false, body: '', truncated: false, originalChars: 0 };
  }
  if (raw.base64Encoded) {
    const size = String(raw.body ?? '').length;
    return { binary: true, body: '[binary/base64 omitted]', sizeHint: size, truncated: false, originalChars: size };
  }
  const text = String(raw.body ?? '');
  let sanitized;
  if (includeSensitive) {
    sanitized = text;
  } else {
    try {
      sanitized = JSON.stringify(redactJsonish(JSON.parse(text)));
    } catch {
      sanitized = redactText(text, maxChars);
    }
  }
  return {
    binary: false,
    body: sanitized.slice(0, maxChars),
    truncated: sanitized.length > maxChars,
    originalChars: text.length
  };
}

export function compactJson(value, maxChars = 40000) {
  let text;
  try {
    text = JSON.stringify(value);
  } catch {
    text = JSON.stringify({ error: 'Value is not JSON-serializable', preview: String(value).slice(0, maxChars) });
  }
  if (text == null) text = 'null';
  if (text.length <= maxChars) return text;
  return JSON.stringify({ truncated: true, originalChars: text.length, preview: text.slice(0, Math.max(0, maxChars - 160)) });
}

export function estimateBytes(value) {
  if (value == null) return 4;
  if (typeof value === 'string') return Math.min(value.length * 2, 16_000_000);
  try { return Math.min(JSON.stringify(value).length, 16_000_000); }
  catch { return 16_000_000; }
}

export function boundedInt(value, min, max, fallback) {
  return Number.isInteger(value) ? Math.max(min, Math.min(max, value)) : fallback;
}

export function looksTextual(mimeType = '') {
  return /(?:json|text|javascript|ecmascript|xml|html|x-www-form-urlencoded|graphql)/i.test(String(mimeType));
}

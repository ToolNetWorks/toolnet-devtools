import { assertPermission, normalizePageUrl, redactUrl } from '../security.mjs';
import { enumStr, flag, num, shape, str, tabIdSchema } from './registry.mjs';

/**
 * Authorized security probing over captured browser data.
 *
 * Two rule-based checks:
 * - secrets: passive credential-exposure scan (tokens in URLs, secret-looking
 *   localStorage/sessionStorage keys, JWT-shaped values). Values are never
 *   returned, only their location, so nothing is "stolen" — the operator is
 *   told where credentials leak.
 * - auth_gate: paywall/auth-bypass detection. Checks whether gated-content
 *   markers are served without a login form while the document returned 200.
 *
 * Use only on targets you own or are explicitly authorized to test.
 */

const SECRET_QUERY = /^(password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?id|sessionid|session|token|auth|auth_token|authorization|signature|sig|key|jwt|bearer|csrf|xsrf)$/i;
const JWT_SHAPE = /^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/;
const REDIRECT_PARAMS = /^(url|redirect|redirect_uri|redirect_url|next|return|returnurl|return_to|target|dest|destination|continue|goto|link|r|u)$/i;
const SENSITIVE_PATH = /\/(?:admin|wp-admin|phpmyadmin|pma|\.env|\.git|backup|backups|dump|debug)(?:\/|$)/i;
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Passive scan for credential exposure in captured requests and web storage. Values stay redacted. */
export function scanCredentialExposure({ requests = [], storages = [] } = {}) {
  const findings = [];
  const seen = new Set();
  const push = finding => {
    const key = `${finding.type}|${finding.key}|${finding.url ?? finding.store}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(finding);
  };

  for (const request of requests.slice(-2000)) {
    let parsed = null;
    try { parsed = new URL(String(request.url ?? '')); } catch { continue; }
    if (!/^https?:$/.test(parsed.protocol)) continue;
    for (const [key, value] of parsed.searchParams.entries()) {
      if (!SECRET_QUERY.test(key)) continue;
      if (!value) continue;
      push({
        type: 'url-query-param',
        severity: key === 'password' || key === 'passwd' || key === 'pwd' ? 'critical' : 'high',
        key,
        url: redactUrl(parsed.href),
        valueChars: String(value).length,
        value: '[REDACTED]',
        remediation: 'Send credentials in headers/body, not URL query parameters.'
      });
    }
  }

  for (const storage of storages) {
    const store = storage?.type === 'session' ? 'sessionStorage' : 'localStorage';
    for (const entry of (storage?.entries ?? [])) {
      const key = String(entry?.key ?? '');
      const value = String(entry?.value ?? '');
      if (!key) continue;
      const keyLooksSecret = SECRET_QUERY.test(key);
      const jwtShaped = JWT_SHAPE.test(value.trim());
      if (!keyLooksSecret && !jwtShaped) continue;
      push({
        type: jwtShaped && !keyLooksSecret ? 'storage-jwt' : 'storage-secret',
        severity: 'high',
        store,
        key,
        valueChars: value.length,
        value: '[REDACTED]',
        remediation: 'Prefer httpOnly cookies for session credentials instead of web storage.'
      });
    }
  }

  const counts = findings.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] ?? 0) + 1;
    return acc;
  }, {});
  return {
    findings: findings.slice(0, 200),
    totals: { scannedRequests: requests.length, scannedStorageEntries: storages.reduce((sum, s) => sum + (s?.entries?.length ?? 0), 0), findings: findings.length, counts },
    exposed: findings.length > 0
  };
}

/** Decide whether gated content markers are served without authentication. */
export function evaluateAuthGate({ documentStatus = null, hasPasswordField = false, pageText = '', authenticatedMarkers = [] } = {}) {
  const text = String(pageText ?? '').toLowerCase();
  const markers = (Array.isArray(authenticatedMarkers) ? authenticatedMarkers : []).map(m => String(m));
  const markersFound = markers.filter(marker => marker && text.includes(marker.toLowerCase()));
  const loginLike = Boolean(hasPasswordField) || /sign in|log in|please login|create account|subscribe now/i.test(text);
  const gateBypassed = documentStatus === 200 && markersFound.length > 0 && !hasPasswordField;
  return {
    documentStatus,
    hasPasswordField,
    loginLike,
    markersFound,
    gateBypassed,
    severity: gateBypassed ? 'high' : 'none',
    remediation: gateBypassed ? 'Gate the content server-side: return 401/403 or do not render member-only markers before authentication.' : null
  };
}

/**
 * Passive attack-surface scan over captured traffic and a DOM probe:
 * mixed content, insecure/third-party credential forms, open-redirect
 * parameters, sensitive paths served with 200, third-party script origins
 * and dangerous inline-JS sinks. Rule-based findings only.
 */
export function scanAttackSurface({ requests = [], pageUrl = '', dom = null } = {}) {
  const findings = [];
  const push = finding => findings.push(finding);
  let origin = null;
  let securePage = false;
  try {
    const parsed = new URL(String(pageUrl || ''));
    origin = parsed.origin;
    securePage = parsed.protocol === 'https:';
  } catch { /* keep null */ }

  const seenRedirectKeys = new Set();
  for (const request of requests.slice(-2000)) {
    let parsed = null;
    try { parsed = new URL(String(request.url ?? '')); } catch { continue; }
    if (!/^https?:$/.test(parsed.protocol)) continue;
    if (securePage && parsed.protocol === 'http:' && !/^(localhost|127\.0\.0\.1)$/.test(parsed.hostname)) {
      push({ type: 'mixed-content', severity: 'medium', url: redactUrl(parsed.href), remediation: 'Serve all subresources over HTTPS.' });
    }
    if (parsed.searchParams.size) {
      for (const [key, value] of parsed.searchParams.entries()) {
        if (!REDIRECT_PARAMS.test(key) || !value || seenRedirectKeys.has(`${key}|${parsed.pathname}`)) continue;
        seenRedirectKeys.add(`${key}|${parsed.pathname}`);
        push({
          type: 'open-redirect-param', severity: 'medium', param: key, url: redactUrl(parsed.href),
          remediation: 'Validate redirect targets against an allowlist server-side.'
        });
      }
    }
    if (SENSITIVE_PATH.test(parsed.pathname) && !request.failed && request.status === 200) {
      push({
        type: 'sensitive-path-exposed', severity: 'medium', path: parsed.pathname, url: redactUrl(parsed.href),
        remediation: 'Restrict admin/config paths with authentication or remove them from production.'
      });
    }
  }

  if (dom && typeof dom === 'object') {
    for (const form of (dom.forms ?? []).slice(0, 30)) {
      const fields = form.fields ?? [];
      if (!fields.some(f => f?.type === 'password')) continue;
      const method = String(form.method || 'GET').toUpperCase();
      let actionUrl = null;
      try { actionUrl = new URL(String(form.action || ''), origin ?? undefined); } catch { /* ignore */ }
      if (method === 'GET') {
        push({ type: 'credential-form-get', severity: 'medium', action: redactUrl(actionUrl?.href ?? String(form.action ?? '')), remediation: 'Submit credential forms with POST so secrets stay out of URLs.' });
      }
      if (actionUrl && actionUrl.protocol === 'http:') {
        push({ type: 'credential-form-insecure', severity: 'high', action: redactUrl(actionUrl.href), remediation: 'Post credential forms to HTTPS endpoints.' });
      }
      if (origin && actionUrl && actionUrl.origin !== origin) {
        push({ type: 'credential-form-third-party', severity: 'high', action: redactUrl(actionUrl.href), pageOrigin: origin, remediation: 'Credential forms should post to the same origin unless the third party is intentional.' });
      }
    }
    const scriptOrigins = new Map();
    for (const src of (dom.scripts ?? []).slice(0, 100)) {
      try {
        const parsed = new URL(String(src), origin ?? undefined);
        if (origin && parsed.origin !== origin) {
          scriptOrigins.set(parsed.origin, (scriptOrigins.get(parsed.origin) ?? 0) + 1);
        }
      } catch { /* ignore */ }
    }
    if (origin && scriptOrigins.size) {
      push({
        type: 'third-party-scripts', severity: 'low', pageOrigin: origin,
        origins: [...scriptOrigins].sort((a, b) => b[1] - a[1]).map(([o, count]) => ({ origin: o, count })),
        remediation: 'Audit third-party script origins; each one is part of the trust boundary.'
      });
    }
    for (const link of (dom.links ?? []).slice(0, 200)) {
      try {
        const parsed = new URL(String(link), origin ?? undefined);
        for (const [key, value] of parsed.searchParams.entries()) {
          if (!REDIRECT_PARAMS.test(key) || !value || seenRedirectKeys.has(`${key}|${parsed.pathname}`)) continue;
          seenRedirectKeys.add(`${key}|${parsed.pathname}`);
          push({ type: 'open-redirect-param', severity: 'medium', param: key, url: redactUrl(parsed.href), source: 'link', remediation: 'Validate redirect targets against an allowlist server-side.' });
        }
      } catch { /* ignore */ }
    }
    const dangerous = dom.dangerous ?? {};
    if ((dangerous.eval ?? 0) > 0 || (dangerous.newFunction ?? 0) > 0) {
      push({ type: 'dangerous-js-eval', severity: 'medium', counts: { eval: dangerous.eval ?? 0, newFunction: dangerous.newFunction ?? 0 }, remediation: 'Avoid eval/new Function on untrusted input; it enables DOM XSS chains.' });
    }
    if ((dangerous.innerHtml ?? 0) > 0 || (dangerous.documentWrite ?? 0) > 0) {
      push({ type: 'dangerous-js-dom-sink', severity: 'low', counts: { innerHtml: dangerous.innerHtml ?? 0, documentWrite: dangerous.documentWrite ?? 0 }, remediation: 'Prefer textContent or sanitization when writing untrusted data into the DOM.' });
    }
  }

  findings.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
  const counts = findings.reduce((acc, finding) => { acc[finding.severity] = (acc[finding.severity] ?? 0) + 1; return acc; }, {});
  return {
    findings: findings.slice(0, 200),
    totals: { scannedRequests: requests.length, findings: findings.length, counts },
    risky: findings.some(finding => finding.severity === 'critical' || finding.severity === 'high')
  };
}

const PAGE_TEXT_EXPRESSION = `(() => String(document.body?.innerText ?? '').slice(0, 20000))()`;
const PASSWORD_FIELD_EXPRESSION = `(() => Boolean(document.querySelector('input[type=password]')))()`;
const SURFACE_PROBE = `(() => {
  const attr = (el, n) => String(el.getAttribute(n) || '');
  const forms = Array.from(document.forms).slice(0, 30).map(f => ({
    action: attr(f, 'action'), method: (attr(f, 'method') || 'GET').toUpperCase(),
    fields: Array.from(f.querySelectorAll('input,select,textarea')).slice(0, 40).map(el => ({ tag: el.tagName.toLowerCase(), type: attr(el, 'type'), name: attr(el, 'name') }))
  }));
  const scripts = Array.from(document.querySelectorAll('script[src]')).slice(0, 100).map(el => attr(el, 'src'));
  const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 200).map(a => a.href);
  const inline = Array.from(document.querySelectorAll('script:not([src])')).slice(0, 60).map(el => el.textContent || '').join('\\n');
  return {
    forms, scripts, links,
    dangerous: {
      eval: (inline.match(/\\beval\\s*\\(/g) || []).length,
      newFunction: (inline.match(/\\bnew\\s+Function\\s*\\(/g) || []).length,
      innerHtml: (inline.match(/\\.innerHTML\\s*=/g) || []).length,
      documentWrite: (inline.match(/document\\.write\\s*\\(/g) || []).length,
      locationAssign: (inline.match(/location\\.(?:href|assign|replace)\\s*=/g) || []).length
    }
  };
})()`;

function findDocumentStatus(session, pageUrl) {
  const requests = session.requestLog?.items?.length ? session.requestLog.items : [...(session.requests?.values() ?? [])];
  const match = requests
    .filter(r => r.resourceType === 'Document' && r.url === pageUrl)
    .sort((a, b) => String(b?.responseReceivedAt ?? '').localeCompare(String(a?.responseReceivedAt ?? '')))[0];
  return match ? (match.failed ? 'failed' : (match.status ?? null)) : null;
}

export function registerSecurityProbeTools(registry) {
  registry.add(
    'devtools_security_probe',
    'Authorized security probing: passively scan captured traffic and web storage for exposed credentials (never returns secret values), detect paywall/auth gates that serve member-only content without authentication, and map the attack surface (mixed content, credential-form risks, open-redirect parameters, sensitive paths, third-party scripts, dangerous inline JS). Use only on targets you own or are authorized to test. Navigation requires interactive.',
    shape({
      tabId: tabIdSchema,
      action: enumStr('Check to run', ['secrets', 'auth_gate', 'surface', 'all'], { default: 'all' }),
      url: str('Optional HTTP/HTTPS URL; navigates with capture before loading (requires interactive)', { maxLength: 8192 }),
      authenticatedMarkers: { type: 'array', description: 'Text markers expected only in authenticated/paid content, e.g. ["Premium content", "Welcome back"]', items: { type: 'string' } },
      maxFindings: num('Maximum reported findings (1-200)', { minimum: 1, maximum: 200 }),
      networkIdleWaitMs: num('Continuous quiet window after navigation (0-10000 ms)', { minimum: 0, maximum: 10_000 })
    }),
    'read-only',
    async ({ tabId, action = 'all', url, authenticatedMarkers = [], maxFindings = 100, networkIdleWaitMs = 1000 }, ctx) => {
      if (url) assertPermission(ctx.permission, 'interactive', 'Security-probe navigation');
      let navigation = null;
      if (url) navigation = await ctx.manager.navigateAndCapture(normalizePageUrl(url), { tabId: tabId || null, newTab: !tabId, networkIdleWaitMs });
      const session = await ctx.session(navigation?.sessionId ?? tabId);

      const runSecrets = async () => {
        const requests = session.requestLog?.items?.length ? session.requestLog.items : [...(session.requests?.values() ?? [])];
        const [local, sessionStore] = await Promise.all([
          session.storage('local', 500).catch(() => ({ entries: [] })),
          session.storage('session', 500).catch(() => ({ entries: [] }))
        ]);
        const scan = scanCredentialExposure({ requests, storages: [local, sessionStore] });
        return { ...scan, findings: scan.findings.slice(0, Math.max(1, Math.min(200, maxFindings))) };
      };

      const runAuthGate = async () => {
        const page = await session.pageInfo();
        const [pageText, hasPasswordField] = await Promise.all([
          session.evaluateValue(PAGE_TEXT_EXPRESSION).catch(() => ''),
          session.evaluateValue(PASSWORD_FIELD_EXPRESSION).catch(() => false)
        ]);
        return evaluateAuthGate({
          documentStatus: findDocumentStatus(session, page.url),
          hasPasswordField,
          pageText,
          authenticatedMarkers
        });
      };

      const runSurface = async () => {
        const page = await session.pageInfo();
        const requests = session.requestLog?.items?.length ? session.requestLog.items : [...(session.requests?.values() ?? [])];
        const dom = await session.evaluateValue(SURFACE_PROBE).catch(() => null);
        return scanAttackSurface({ requests, pageUrl: page.url, dom });
      };

      const result = { sessionId: session.tab?.id };
      if (action === 'secrets') return { ...result, action, credentials: await runSecrets() };
      if (action === 'auth_gate') return { ...result, action, authGate: await runAuthGate() };
      if (action === 'surface') return { ...result, action, surface: await runSurface() };
      const [credentials, authGate, surface] = await Promise.all([runSecrets(), runAuthGate(), runSurface()]);
      return { ...result, action, credentials, authGate, surface };
    }
  );
}

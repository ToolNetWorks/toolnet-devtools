import { assertPermission, normalizePageUrl, redactText, redactUrl } from '../security.mjs';
import { flag, num, shape, str, tabIdSchema } from './registry.mjs';

const MAX_DOM_ITEMS = 60;
const MAX_SOURCE_BYTES = 160_000;
const PRIVATE_FIELD = /^(?:password|passwd|pwd|secret|token|auth|authorization|cookie|session|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|jwt)$/i;

const DOM_PROBE = `(() => {
  const take = (nodes, max = 60) => Array.from(nodes).slice(0, max);
  const attribute = (el, name) => String(el.getAttribute(name) || '').slice(0, 500);
  const count = sel => document.querySelectorAll(sel).length;
  return {
    title: document.title.slice(0, 300),
    generator: attribute(document.querySelector('meta[name="generator"]') || document.documentElement, 'content'),
    technologies: {
      next: !!document.querySelector('#__NEXT_DATA__,script[src*="/_next/"]'),
      nuxt: !!document.querySelector('#__nuxt,script[src*="/_nuxt/"]'),
      wordpress: !!document.querySelector('link[href*="/wp-content/"],script[src*="/wp-content/"]'),
      vite: !!document.querySelector('script[type="module"][src*="/assets/"]'),
      angular: !!document.querySelector('[ng-version]')
    },
    counts: {
      forms: count('form'), buttons: count('button'), inputs: count('input'),
      links: count('a[href]'), images: count('img'), scripts: count('script'),
      stylesheets: count('link[rel="stylesheet"]')
    },
    forms: take(document.forms, 20).map(form => ({
      action: attribute(form, 'action'), method: (attribute(form, 'method') || 'GET').toUpperCase(),
      fields: take(form.querySelectorAll('input,select,textarea'), 30).map(el => ({
        tag: el.tagName.toLowerCase(), type: attribute(el, 'type'), name: attribute(el, 'name')
      }))
    })),
    scripts: take(document.querySelectorAll('script[src]')).map(el => ({ src: attribute(el, 'src'), type: attribute(el, 'type') })),
    stylesheets: take(document.querySelectorAll('link[rel="stylesheet"]')).map(el => attribute(el, 'href')),
    routes: take(document.querySelectorAll('a[href]'), 100).map(el => attribute(el, 'href')).filter(Boolean)
  };
})()`;

function cap(value, min, max, fallback) {
  return Number.isInteger(value) ? Math.max(min, Math.min(max, value)) : fallback;
}

function safeUrl(raw) {
  if (typeof raw !== 'string' || !raw) return '';
  try {
    const parsed = new URL(raw);
    if (!['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol)) return '';
    return redactUrl(parsed.href);
  } catch {
    return redactText(raw, 300);
  }
}

function pathTemplate(pathname) {
  return pathname.split('/').map(segment => {
    if (/^\d{3,}$/.test(segment)) return ':id';
    if (/^[0-9a-f]{8}-[0-9a-f-]{20,}$/i.test(segment)) return ':uuid';
    if (/^[a-f0-9]{24,}$/i.test(segment)) return ':hash';
    return segment;
  }).join('/');
}

function makeEndpointKey(raw, method) {
  try {
    const url = new URL(raw);
    if (!['http:', 'https:'].includes(url.protocol)) return null;
    return { key: `${method.toUpperCase()} ${url.origin}${pathTemplate(url.pathname)}`, origin: url.origin, path: pathTemplate(url.pathname) };
  } catch { return null; }
}

function inferJsonShape(body, depth = 0) {
  if (depth >= 3) return 'object';
  if (Array.isArray(body)) return { type: 'array', items: body.length ? inferJsonShape(body[0], depth + 1) : 'unknown' };
  if (body === null) return 'null';
  if (typeof body !== 'object') return typeof body;
  const keys = Object.keys(body).slice(0, 24);
  return Object.fromEntries(keys.map(key => [PRIVATE_FIELD.test(key) ? '[SENSITIVE_FIELD]' : key, PRIVATE_FIELD.test(key) ? '[REDACTED]' : inferJsonShape(body[key], depth + 1)]));
}

function responseShape(request) {
  const body = request?.body?.body;
  if (typeof body !== 'string' || body.length > 120_000) return null;
  try { return inferJsonShape(JSON.parse(body)); } catch { return null; }
}

function scriptSignals(source) {
  const s = String(source || '').slice(0, MAX_SOURCE_BYTES);
  const api = new Set();
  const matches = s.matchAll(/(?:https?:\/\/[^\s"'`<>\\]{5,220}|\/api\/[\w./?&=-]{2,180}|\/graphql\b)/gi);
  for (const match of matches) {
    if (api.size >= 30) break;
    const candidate = match[0].replace(/[),;]+$/, '');
    api.add(safeUrl(candidate) || redactText(candidate, 180));
  }
  return {
    sourceCharactersScanned: s.length,
    truncated: String(source || '').length > s.length,
    indicators: {
      fetch: /\bfetch\s*\(/.test(s),
      axios: /\baxios\b|\.interceptors\.request/.test(s),
      websocket: /\bWebSocket\s*\(/.test(s),
      graphql: /\bgraphql\b/i.test(s),
      react: /\breact-dom\b|__REACT_DEVTOOLS_GLOBAL_HOOK__/.test(s),
      vue: /__VUE__|createApp\s*\(/.test(s)
    },
    urlCandidates: [...api]
  };
}

/** Summarize browser-observed code and network data without exposing credentials or raw page bodies. */
export function buildReverseReport({ page = {}, requests = [], scripts = [], dom = null, analyzedScripts = [], maxItems = 80 } = {}) {
  const max = cap(maxItems, 1, 200, 80);
  const endpoints = new Map();
  const domains = new Map();
  const assets = new Map();
  for (const request of requests.slice(-2000)) {
    const safe = safeUrl(request.url);
    const entry = makeEndpointKey(safe, request.method ?? 'GET');
    if (!entry) continue;
    domains.set(entry.origin, (domains.get(entry.origin) ?? 0) + 1);
    if (['Script', 'Stylesheet', 'Image', 'Font', 'Media'].includes(request.resourceType)) {
      const assetKey = `${request.resourceType}|${safe}`;
      if (!assets.has(assetKey)) assets.set(assetKey, { type: request.resourceType, url: safe, status: request.status ?? null });
      continue;
    }
    const looksApi = ['Fetch', 'XHR', 'WebSocket', 'EventSource'].includes(request.resourceType)
      || /\/api\/|\/graphql(?:\/|$)|\/v\d+\//i.test(entry.path);
    if (!looksApi) continue;
    const existing = endpoints.get(entry.key) ?? {
      method: String(request.method ?? 'GET').toUpperCase(), origin: entry.origin, path: entry.path,
      count: 0, statuses: {}, contentTypes: [], sampleRequestIds: [], responseShape: null
    };
    existing.count++;
    const status = request.failed ? 'failed' : String(request.status ?? 'pending');
    existing.statuses[status] = (existing.statuses[status] ?? 0) + 1;
    if (request.mimeType && !existing.contentTypes.includes(request.mimeType)) existing.contentTypes.push(request.mimeType);
    if (existing.sampleRequestIds.length < 3 && request.id != null) existing.sampleRequestIds.push(String(request.id));
    existing.responseShape ??= responseShape(request);
    endpoints.set(entry.key, existing);
  }
  const domSafe = dom && typeof dom === 'object' ? {
    title: redactText(dom.title ?? '', 300),
    generator: redactText(dom.generator ?? '', 200),
    technologies: dom.technologies ?? {}, counts: dom.counts ?? {},
    forms: (dom.forms ?? []).slice(0, 20).map(form => ({
      method: String(form.method || 'GET').toUpperCase(), action: safeUrl(form.action) || redactText(form.action ?? '', 200),
      fields: (form.fields ?? []).slice(0, 30).map(f => ({ tag: f.tag, type: f.type, name: PRIVATE_FIELD.test(f.name) ? '[SENSITIVE_FIELD]' : redactText(f.name ?? '', 100) }))
    })),
    scripts: (dom.scripts ?? []).slice(0, MAX_DOM_ITEMS).map(x => ({ src: safeUrl(x.src) || redactText(x.src ?? '', 250), type: x.type })),
    stylesheets: (dom.stylesheets ?? []).slice(0, MAX_DOM_ITEMS).map(x => safeUrl(x) || redactText(x, 250)),
    routes: [...new Set((dom.routes ?? []).slice(0, 100).map(x => safeUrl(x) || redactText(x, 150)))].slice(0, 60)
  } : null;
  const scriptInventory = scripts.slice(-Math.min(max, 100)).map(s => ({
    scriptId: s.scriptId, url: safeUrl(s.url), sourceMapURL: safeUrl(s.sourceMapURL),
    isModule: Boolean(s.isModule), lines: s.endLine != null && s.startLine != null ? Math.max(0, s.endLine - s.startLine + 1) : null
  }));
  return {
    page: { url: safeUrl(page.url), title: redactText(page.title ?? '', 300), readyState: page.readyState ?? null },
    totals: { capturedRequests: requests.length, apiPatterns: endpoints.size, origins: domains.size, assets: assets.size, scripts: scripts.length },
    origins: [...domains].sort((a, b) => b[1] - a[1]).slice(0, max).map(([origin, count]) => ({ origin, count })),
    apiEndpoints: [...endpoints.values()].sort((a, b) => b.count - a.count).slice(0, max),
    assets: [...assets.values()].slice(0, max),
    dom: domSafe,
    scriptInventory,
    analyzedScripts: analyzedScripts.slice(0, 15),
    limitations: [
      'Only client-observable resources and traffic captured after CDP attachment are available.',
      'API routes and JSON shapes are inferred, not server-side source code.',
      'Framework hints are heuristics. Cookies, tokens, and raw source are not included.'
    ]
  };
}

export function registerReverseTools(registry) {
  registry.add(
    'devtools_reverse_engineer',
    'Reverse-engineer a website from observable page structure, API patterns, requests, JS/CSS inventory and optional script heuristics. Accepts any HTTP/HTTPS URL or inspects an attached tab. No raw cookies, tokens or server code. Navigation requires interactive; script source heuristics require full-debug.',
    shape({
      url: str('Optional HTTP/HTTPS URL; navigates with capture BEFORE loading the page', { maxLength: 8192 }),
      tabId: tabIdSchema,
      analyzeScripts: flag('Analyze bounded client-side JavaScript sources; requires full-debug'),
      includeDom: flag('Collect structural DOM inventory (default true)'),
      maxItems: num('Maximum reported items per group, 1-200', { minimum: 1, maximum: 200 }),
      maxScripts: num('Maximum analyzed scripts, 1-15', { minimum: 1, maximum: 15 }),
      networkIdleWaitMs: num('Continuous quiet window after navigation (0-10000 ms)', { minimum: 0, maximum: 10_000 })
    }),
    'read-only',
    async ({ url, tabId, analyzeScripts = false, includeDom = true, maxItems = 80, maxScripts = 8, networkIdleWaitMs = 1000 }, ctx) => {
      if (url) assertPermission(ctx.permission, 'interactive', 'Reverse-engineering navigation');
      if (analyzeScripts) assertPermission(ctx.permission, 'full-debug', 'Client JavaScript source inspection');
      const navigation = url ? await ctx.manager.navigateAndCapture(normalizePageUrl(url), {
        tabId: tabId || null, newTab: !tabId, networkIdleWaitMs
      }) : null;
      const session = await ctx.session(navigation?.sessionId ?? tabId);
      const page = await session.pageInfo();
      const dom = includeDom ? await session.evaluateValue(DOM_PROBE).catch(error => ({ error: redactText(error?.message ?? String(error), 200) })) : null;
      const analyzedScripts = [];
      if (analyzeScripts) {
        await session.enableDebugger();
        const candidates = [...session.scripts.values()].filter(s => s.url && /^https?:\/\//.test(s.url));
        for (const script of candidates.slice(0, cap(maxScripts, 1, 15, 8))) {
          try {
            const raw = await session.send('Debugger.getScriptSource', { scriptId: script.scriptId }, 12_000);
            analyzedScripts.push({ url: safeUrl(script.url), sourceMapURL: safeUrl(script.sourceMapURL), ...scriptSignals(raw.scriptSource) });
          } catch (error) {
            analyzedScripts.push({ url: safeUrl(script.url), error: redactText(error?.message ?? String(error), 180) });
          }
        }
      }
      const requests = session.requestLog.items?.length ? session.requestLog.items : [...session.requests.values()];
      return {
        sessionId: session.tab?.id,
        captureReadiness: { ...session.captureReadiness },
        report: buildReverseReport({ page, requests, scripts: [...session.scripts.values()], dom, analyzedScripts, maxItems })
      };
    }
  );
}

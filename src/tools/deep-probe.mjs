import { assertPermission, normalizePageUrl, redactHeaders, redactText, redactUrl } from '../security.mjs';
import { enumStr, num, shape, str, tabIdSchema } from './registry.mjs';

/**
 * Deep reverse-engineering helpers (authorized targets only):
 * - devtools_graphql: discover GraphQL endpoints from captured traffic and
 *   run a bounded introspection query from the page context.
 * - devtools_sourcemap: list scripts with source maps and fetch their
 *   .map metadata (sources inventory, sourcesContent coverage).
 * - devtools_replay: re-send a captured or explicit request from the page
 *   context with overrides (Burp Repeater-lite).
 */

const INTROSPECTION_QUERY = 'query ToolnetIntrospection { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind fields { name } } } }';
const MAX_MAPS = 10;
const MAX_BODY_EXCERPT = 500;

async function evaluateAsync(session, expression, timeoutMs = 20_000) {
  const result = await session.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true, timeout: timeoutMs }, timeoutMs + 2000);
  if (result?.exceptionDetails) {
    throw new Error(result.exceptionDetails.exception?.description ?? result.exceptionDetails.text ?? 'Evaluation failed');
  }
  return result?.result?.value;
}

function capturedRequests(session) {
  return session.requestLog?.items?.length ? session.requestLog.items : [...(session.requests?.values() ?? [])];
}

function graphqlCandidates(session) {
  const endpoints = new Map();
  for (const request of capturedRequests(session).slice(-2000)) {
    let parsed = null;
    try { parsed = new URL(String(request.url ?? '')); } catch { continue; }
    if (!/^https?:$/.test(parsed.protocol)) continue;
    const isGraphqlUrl = /\/graphql(?:\/|$)/i.test(parsed.pathname) || /graphql/i.test(parsed.searchParams.get('query') ?? '');
    let operations = [];
    let isGraphqlBody = false;
    const postData = typeof request.postData === 'string' ? request.postData : '';
    if (postData && ['POST', 'PUT', 'PATCH'].includes(String(request.method ?? '').toUpperCase())) {
      try {
        const body = JSON.parse(postData);
        if (body && typeof body === 'object' && (body.query || body.operationName)) {
          isGraphqlBody = true;
          operations = [body.operationName].filter(Boolean).map(name => String(name).slice(0, 120));
        }
      } catch { /* not JSON */ }
    }
    if (!isGraphqlUrl && !isGraphqlBody) continue;
    const key = parsed.origin + parsed.pathname;
    const entry = endpoints.get(key) ?? { endpoint: redactUrl(parsed.origin + parsed.pathname), origin: parsed.origin, count: 0, methods: new Set(), operations: new Set() };
    entry.count++;
    entry.methods.add(String(request.method ?? 'GET').toUpperCase());
    for (const operation of operations) entry.operations.add(operation);
    endpoints.set(key, entry);
  }
  return [...endpoints.values()].map(entry => ({
    endpoint: entry.endpoint,
    origin: entry.origin,
    count: entry.count,
    methods: [...entry.methods],
    operations: [...entry.operations].slice(0, 40)
  }));
}

function fetchExpression(url, initLiteral) {
  return `(async () => {
    try {
      const started = performance.now();
      const res = await fetch(${JSON.stringify(url)}, ${initLiteral});
      const text = await res.text().catch(() => '');
      return { ok: res.ok, status: res.status, statusText: res.statusText, ms: Math.round(performance.now() - started), headers: Object.fromEntries([...res.headers].slice(0, 40)), bodyChars: text.length, body: text.slice(0, 4000) };
    } catch (error) {
      return { fetchError: String(error && error.message || error).slice(0, 300) };
    }
  })()`;
}

export function registerDeepProbeTools(registry) {
  registry.add(
    'devtools_graphql',
    'Discover GraphQL endpoints from captured traffic and optionally run a bounded introspection query from the page context (authorized targets only). Listing endpoints is read-only; introspection requires interactive.',
    shape({
      tabId: tabIdSchema,
      action: enumStr('Action', ['endpoints', 'introspect'], { default: 'endpoints' }),
      url: str('Optional GraphQL endpoint URL for introspection; defaults to the first discovered endpoint', { maxLength: 8192 })
    }),
    'read-only',
    async ({ tabId, action = 'endpoints', url }, ctx) => {
      const session = await ctx.session(tabId);
      const endpoints = graphqlCandidates(session);
      if (action === 'endpoints') {
        return { sessionId: session.tab?.id, endpoints, totals: { endpoints: endpoints.length } };
      }
      assertPermission(ctx.permission, 'interactive', 'GraphQL introspection');
      const target = url ? normalizePageUrl(url) : endpoints[0]?.endpoint;
      if (!target) throw new Error('No GraphQL endpoint found in captured traffic; provide url');
      const value = await evaluateAsync(session, fetchExpression(target, `{ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ query: ${JSON.stringify(INTROSPECTION_QUERY)} }), credentials: 'include' }`));
      if (!value || value.fetchError) return { sessionId: session.tab?.id, endpoint: redactUrl(target), fetchError: value?.fetchError ?? 'no response' };
      let body = null;
      try { body = JSON.parse(value.body ?? ''); } catch { /* not JSON */ }
      const schema = body?.data?.__schema ?? null;
      if (!schema) {
        return {
          sessionId: session.tab?.id,
          endpoint: redactUrl(target),
          httpStatus: value.status,
          introspectionAvailable: false,
          note: body?.errors ? 'Introspection returned errors (often disabled server-side).' : 'Response was not an introspection payload.'
        };
      }
      const types = (schema.types ?? []).filter(t => t?.name && !String(t.name).startsWith('__'));
      return {
        sessionId: session.tab?.id,
        endpoint: redactUrl(target),
        httpStatus: value.status,
        introspectionAvailable: true,
        schema: {
          queryType: schema.queryType?.name ?? null,
          mutationType: schema.mutationType?.name ?? null,
          subscriptionType: schema.subscriptionType?.name ?? null,
          typeCount: types.length,
          types: types.slice(0, 40).map(t => ({ name: t.name, kind: t.kind, fieldCount: (t.fields ?? []).length }))
        }
      };
    }
  );

  registry.add(
    'devtools_sourcemap',
    'List scripts that expose source maps and fetch bounded .map metadata (sources inventory, sourcesContent coverage) for authorized reverse engineering. Uses the Debugger domain, so it requires full-debug.',
    shape({
      tabId: tabIdSchema,
      action: enumStr('Action', ['list', 'fetch'], { default: 'list' }),
      maxMaps: num('Maximum maps fetched (1-10)', { minimum: 1, maximum: 10 })
    }),
    'full-debug',
    async ({ tabId, action = 'list', maxMaps = 5 }, ctx) => {
      const session = await ctx.session(tabId);
      await session.enableDebugger();
      const withMaps = [...session.scripts.values()].filter(s => s?.url && /^https?:/i.test(s.url) && s.sourceMapURL);
      const limit = Math.max(1, Math.min(10, Number.isInteger(maxMaps) ? maxMaps : 5));
      if (action === 'list') {
        return {
          sessionId: session.tab?.id,
          totals: { scripts: session.scripts.size, withSourceMaps: withMaps.length },
          scripts: withMaps.slice(0, 50).map(s => ({ url: redactUrl(s.url), sourceMapURL: redactUrl(s.sourceMapURL) }))
        };
      }
      const maps = [];
      for (const script of withMaps.slice(0, limit)) {
        const value = await evaluateAsync(session, fetchExpression(script.sourceMapURL, `{ method: 'GET', credentials: 'include' }`)).catch(error => ({ fetchError: String(error?.message ?? error).slice(0, 200) }));
        let parsed = null;
        try { parsed = JSON.parse(value?.body ?? ''); } catch { /* not a map */ }
        maps.push({
          scriptUrl: redactUrl(script.url),
          mapUrl: redactUrl(script.sourceMapURL),
          httpStatus: value?.status ?? null,
          fetchError: value?.fetchError,
          map: parsed ? {
            version: parsed.version ?? null,
            sourcesCount: (parsed.sources ?? []).length,
            sourcesContentCount: (parsed.sourcesContent ?? []).filter(c => typeof c === 'string' && c.length > 0).length,
            file: parsed.file ? redactText(String(parsed.file), 200) : null,
            sources: (parsed.sources ?? []).slice(0, 40).map(s => redactText(String(s), 250)),
            mapChars: value?.bodyChars ?? null
          } : null
        });
      }
      return { sessionId: session.tab?.id, totals: { scripts: session.scripts.size, withSourceMaps: withMaps.length, fetched: maps.length }, maps };
    }
  );

  registry.add(
    'devtools_replay',
    'Re-send a captured request (by requestId) or an explicit HTTP(S) request from the page context with overrides - a Burp Repeater-lite for authorized testing. Sends real traffic to the target, so it requires interactive.',
    shape({
      tabId: tabIdSchema,
      requestId: str('Captured request ID to replay', { maxLength: 200 }),
      url: str('Explicit HTTP(S) URL when no requestId is given', { maxLength: 8192 }),
      method: str('HTTP method override', { maxLength: 10 }),
      headers: { type: 'object', description: 'Header overrides merged over the captured request headers', additionalProperties: true },
      json: { type: 'object', description: 'JSON body to send (sets content-type application/json)', additionalProperties: true },
      body: str('Raw body to send when json is not used', { maxLength: 20_000 }),
      timeoutMs: num('Fetch timeout (2000-60000 ms)', { minimum: 2000, maximum: 60_000 })
    }),
    'interactive',
    async ({ tabId, requestId, url, method, headers = {}, json, body, timeoutMs }, ctx) => {
      assertPermission(ctx.permission, 'interactive', 'Request replay');
      const session = await ctx.session(tabId);
      let targetUrl = url ? normalizePageUrl(url) : null;
      let targetMethod = method;
      let baseBody = null;
      if (requestId) {
        const captured = session.requests?.get(String(requestId));
        if (!captured) throw new Error(`Unknown requestId: ${requestId}`);
        targetUrl ??= String(captured.url ?? '');
        targetMethod ??= String(captured.method ?? 'GET');
        baseBody = typeof captured.postData === 'string' ? captured.postData : null;
      }
      if (!targetUrl) throw new Error('Provide requestId or url');
      targetMethod = String(targetMethod ?? 'GET').toUpperCase();

      // Captured header values are redacted, so the browser's own cookie jar
      // (credentials: 'include') provides auth instead of replayed headers.
      const init = {
        method: targetMethod,
        credentials: 'include',
        headers: { ...headers }
      };
      if (json !== undefined && json !== null) {
        init.headers['content-type'] = 'application/json';
        init.body = JSON.stringify(json);
      } else if (body !== undefined && body !== null) {
        init.body = String(body);
      } else if (baseBody && !['GET', 'HEAD'].includes(targetMethod)) {
        init.body = baseBody;
      }

      const initLiteral = JSON.stringify(init).replace(/^"|"$/g, '') || '{}';
      const value = await evaluateAsync(session, fetchExpression(targetUrl, initLiteral), Number.isInteger(timeoutMs) ? Math.max(2000, Math.min(60_000, timeoutMs)) : 20_000);
      return {
        sessionId: session.tab?.id,
        request: { method: targetMethod, url: redactUrl(targetUrl), headers: redactHeaders(init.headers) },
        response: {
          ok: value?.ok ?? null,
          status: value?.status ?? null,
          statusText: value?.statusText ?? null,
          ms: value?.ms ?? null,
          headers: redactHeaders(value?.headers ?? {}),
          bodyChars: value?.bodyChars ?? null,
          bodyExcerpt: redactText(value?.body ?? '', MAX_BODY_EXCERPT),
          fetchError: value?.fetchError ? redactText(value.fetchError, 300) : undefined
        }
      };
    }
  );
}

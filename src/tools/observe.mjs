import { buildSessionDiagnostics } from '../diagnostics.mjs';
import { looksTextual, redactText } from '../security.mjs';
import { enumStr, flag, num, result, shape, str, tabIdSchema } from './registry.mjs';

function recordsFor(session) {
  return session.requestLog.items?.length ? [...session.requestLog.items] : [...session.requests.values()];
}

function publicRequest(req, { includeBody = false, bodyMatch = null } = {}) {
  return {
    id: req.id,
    sequence: req.sequence,
    url: req.url,
    method: req.method,
    type: req.resourceType,
    status: req.status,
    statusText: req.statusText,
    finished: req.finished,
    failed: req.failed,
    error: req.errorText,
    corsError: req.corsError,
    durationMs: req.durationMs,
    bytes: req.bytes,
    mimeType: req.mimeType,
    protocol: req.protocol,
    initiatorType: req.initiatorType,
    startedAt: req.startedAtIso,
    fromDiskCache: req.fromDiskCache,
    fromServiceWorker: req.fromServiceWorker,
    redirectChain: req.redirectChain?.length ? req.redirectChain : undefined,
    body: includeBody ? (req.body ?? null) : undefined,
    bodySkipped: req.bodySkipped,
    bodyError: req.bodyError,
    bodyMatch: bodyMatch ?? undefined
  };
}

async function ensureBody(session, req, budget) {
  if (req.body?.body) return req.body;
  if (!req.finished || req.failed || budget.used >= budget.max) return null;
  if (!looksTextual(req.mimeType ?? '')) return null;
  budget.used++;
  try { return await session.responseBody(req.id, { maxChars: 60_000 }); }
  catch { return null; }
}

function snippet(text, needle, radius = 100) {
  const index = text.toLowerCase().indexOf(needle.toLowerCase());
  if (index < 0) return null;
  const start = Math.max(0, index - radius);
  return `${start > 0 ? '…' : ''}${text.slice(start, index + needle.length + radius)}${index + needle.length + radius < text.length ? '…' : ''}`;
}

export function registerObserveTools(registry) {
  const { add } = registry;

  add(
    'devtools_console',
    'Read buffered console logs, warnings, errors, exceptions and browser warnings, with filtering, stack traces and sequence cursors for continuous polling.',
    shape({
      tabId: tabIdSchema,
      level: str('Exact level: error, warning, log, info, debug, trace'),
      category: str('Category: console, exception, browser, javascript, network, security etc.'),
      contains: str('Case-insensitive text filter'),
      afterSequence: num('Only entries with a higher sequence number', { minimum: 0 }),
      limit: num('Max 1-200', { minimum: 1, maximum: 200 }),
      includeStack: flag('Include captured stack traces (default true when present)')
    }),
    'read-only',
    async ({ tabId, level, category, contains, afterSequence = 0, limit, includeStack = true }, ctx) => {
      const session = await ctx.session(tabId);
      const needle = String(contains ?? '').toLowerCase();
      const rows = session.console.items.filter(entry =>
        (!level || entry.level === level) &&
        (!category || entry.category === category) &&
        (!needle || JSON.stringify(entry).toLowerCase().includes(needle)) &&
        entry.sequence > afterSequence
      );
      const entries = rows.slice(-Math.max(1, Math.min(200, limit ?? 40))).map(entry => {
        if (includeStack) return entry;
        const { stackTrace, ...rest } = entry;
        return rest;
      });
      return {
        sessionId: session.tab?.id,
        totalMatches: rows.length,
        latestSequence: session.seq,
        entries
      };
    }
  );

  add(
    'devtools_network',
    'List captured HTTP requests: URL, method, resource type, status, failure/CORS, duration, bytes and redirects. Body previews are fetched on demand with includeBodies or bodyContains.',
    shape({
      tabId: tabIdSchema,
      urlContains: str('Case-insensitive URL substring'),
      method: str('GET, POST, etc.'),
      resourceType: str('XHR, Fetch, Document, Script, Image, WebSocket etc.'),
      onlyFailed: flag('HTTP >=400 or failed request only'),
      statusMin: num('Minimum HTTP status', { minimum: 0, maximum: 999 }),
      statusMax: num('Maximum HTTP status', { minimum: 0, maximum: 999 }),
      afterSequence: num('Only requests after this sequence', { minimum: 0 }),
      limit: num('Max 1-500', { minimum: 1, maximum: 500 }),
      includeBodies: flag('Include cached/re-fetched response body previews'),
      bodyContains: str('Search completed response bodies (bounded body fetches)')
    }),
    'read-only',
    async ({ tabId, urlContains, method, resourceType, onlyFailed = false, statusMin, statusMax, afterSequence = 0, limit, includeBodies = false, bodyContains }, ctx) => {
      const session = await ctx.session(tabId);
      const needle = String(urlContains ?? '').toLowerCase();
      const bodyNeedle = String(bodyContains ?? '').toLowerCase();
      const records = recordsFor(session);
      let rows = records.filter(req =>
        (!needle || req.url.toLowerCase().includes(needle) || (req.initiatorUrl ?? '').toLowerCase().includes(needle)) &&
        (!method || req.method?.toLowerCase() === method.toLowerCase()) &&
        (!resourceType || req.resourceType?.toLowerCase() === resourceType.toLowerCase()) &&
        (!onlyFailed || req.failed || (req.status ?? 0) >= 400) &&
        (statusMin == null || (req.status ?? 0) >= statusMin) &&
        (statusMax == null || (req.status ?? 0) <= statusMax) &&
        req.sequence > afterSequence
      );
      const matches = [];
      const budget = { used: 0, max: 25 };
      for (const req of rows) {
        let bodyMatch = null;
        if (bodyNeedle) {
          const body = await ensureBody(session, req, budget);
          if (body?.body) bodyMatch = snippet(body.body, bodyNeedle);
          if (!bodyMatch) continue;
        }
        matches.push({ req, bodyMatch });
      }
      rows = matches;
      const limited = rows.slice(-Math.max(1, Math.min(500, limit ?? 50)));
      const output = [];
      for (const { req, bodyMatch } of limited) {
        const body = includeBodies && !bodyNeedle ? await ensureBody(session, req, budget) : null;
        output.push(publicRequest(req, { includeBody: includeBodies, bodyMatch: bodyMatch ?? (body?.body ? null : undefined) }));
      }
      return {
        sessionId: session.tab?.id,
        totalMatches: rows.length,
        latestSequence: session.seq,
        pendingRequests: session.pendingRequestCount(),
        requests: output
      };
    }
  );

  add(
    'devtools_network_search',
    'Search captured requests across URL, headers and response bodies. Useful for finding a specific API call or response value.',
    shape({
      tabId: tabIdSchema,
      query: str('Case-insensitive search text', { minLength: 1, maxLength: 500 }),
      in: enumStr('Search scope', ['all', 'url', 'headers', 'body'], { default: 'all' }),
      afterSequence: num('Only newer requests', { minimum: 0 }),
      limit: num('Max 1-100', { minimum: 1, maximum: 100 }),
      maxBodies: num('Maximum response bodies to fetch (1-50)', { minimum: 1, maximum: 50 })
    }),
    'read-only',
    async ({ tabId, query, in: scope = 'all', afterSequence = 0, limit, maxBodies = 20 }, ctx) => {
      const session = await ctx.session(tabId);
      const needle = query.toLowerCase();
      const budget = { used: 0, max: Math.max(1, Math.min(50, maxBodies)) };
      const matches = [];
      for (const req of recordsFor(session)) {
        if (req.sequence <= afterSequence) continue;
        let field = null;
        let bodySnippet = null;
        if ((scope === 'all' || scope === 'url') && req.url.toLowerCase().includes(needle)) field = 'url';
        if (!field && (scope === 'all' || scope === 'headers')) {
          if (JSON.stringify({ headers: req.headers, responseHeaders: req.responseHeaders }).toLowerCase().includes(needle)) field = 'headers';
        }
        if (!field && (scope === 'all' || scope === 'body')) {
          const body = await ensureBody(session, req, budget);
          if (body?.body) {
            bodySnippet = snippet(body.body, needle);
            if (bodySnippet) field = 'body';
          }
        }
        if (field) matches.push({ ...publicRequest(req), matchedIn: field, bodyMatch: bodySnippet });
      }
      return {
        sessionId: session.tab?.id,
        query,
        totalMatches: matches.length,
        latestSequence: session.seq,
        matches: matches.slice(-Math.max(1, Math.min(100, limit ?? 30)))
      };
    }
  );

  add(
    'devtools_request',
    'Inspect one captured request: request/response headers, status, protocol, timing, security, redirects and errors. Sensitive headers are redacted unless explicitly enabled.',
    shape({
      tabId: tabIdSchema,
      requestId: str('Network request ID', { minLength: 1 }),
      includeSensitive: flag('Requires full-debug + DEVTOOLS_ALLOW_SENSITIVE=1')
    }, ['requestId']),
    'read-only',
    async ({ tabId, requestId, includeSensitive = false }, ctx) => {
      const session = await ctx.session(tabId);
      const req = session.requests.get(requestId) ?? recordsFor(session).find(item => item.id === requestId);
      if (!req) throw new Error('Request not retained. Reproduce it after attaching, or increase the request buffer.');
      const sensitive = ctx.sensitive(includeSensitive);
      const { body, headersRaw, responseHeadersRaw, postDataRaw, urlRaw, redirectResponseLocationRaw, ...record } = req;
      return {
        sessionId: session.tab?.id,
        ...record,
        ...(sensitive ? { urlRaw, headersRaw, responseHeadersRaw, postDataRaw, redirectResponseLocationRaw } : {}),
        body: body ? { binary: body.binary, truncated: body.truncated, originalChars: body.originalChars, cached: true } : undefined
      };
    }
  );

  add(
    'devtools_request_body',
    'Get a POST/PUT/PATCH request payload on demand. Common secrets are redacted unless explicitly enabled.',
    shape({
      tabId: tabIdSchema,
      requestId: str('Network request ID', { minLength: 1 }),
      maxChars: num('Up to 200000 characters', { minimum: 100, maximum: 200_000 }),
      includeSensitive: flag('Requires full-debug + DEVTOOLS_ALLOW_SENSITIVE=1')
    }, ['requestId']),
    'read-only',
    async ({ tabId, requestId, maxChars = 12_000, includeSensitive = false }, ctx) => {
      const session = await ctx.session(tabId);
      const sensitive = ctx.sensitive(includeSensitive);
      const body = await session.requestBody(requestId, { maxChars, includeSensitive: sensitive });
      return result({ sessionId: session.tab?.id, ...body }, Math.min(220_000, maxChars + 4_000));
    }
  );

  add(
    'devtools_response_body',
    'Get a completed HTTP response body on demand. Binary bodies are summarized rather than exported. Common secrets are redacted unless explicitly enabled.',
    shape({
      tabId: tabIdSchema,
      requestId: str('Network request ID', { minLength: 1 }),
      maxChars: num('Up to 200000 characters', { minimum: 100, maximum: 200_000 }),
      includeSensitive: flag('Requires full-debug + DEVTOOLS_ALLOW_SENSITIVE=1')
    }, ['requestId']),
    'read-only',
    async ({ tabId, requestId, maxChars = 12_000, includeSensitive = false }, ctx) => {
      const session = await ctx.session(tabId);
      const req = session.requests.get(requestId);
      if (!req) throw new Error('Request not found in buffer');
      if (!req.finished || req.failed) throw new Error('Response not available: request unfinished or failed');
      const sensitive = ctx.sensitive(includeSensitive);
      const body = await session.responseBody(requestId, { maxChars, includeSensitive: sensitive });
      return result({ sessionId: session.tab?.id, requestId, url: req.url, mimeType: req.mimeType, ...body }, Math.min(220_000, maxChars + 4_000));
    }
  );

  add(
    'devtools_websocket',
    'Read captured WebSocket connections and frames (sent/received, text/binary previews) with search and sequence cursors.',
    shape({
      tabId: tabIdSchema,
      requestId: str('Optional WebSocket request ID'),
      direction: enumStr('Frame direction', ['sent', 'received']),
      contains: str('Case-insensitive payload filter'),
      afterSequence: num('Only newer frames', { minimum: 0 }),
      limit: num('Max 1-200', { minimum: 1, maximum: 200 }),
      includeConnections: flag('Include handshake/connection metadata')
    }),
    'read-only',
    async ({ tabId, requestId, direction, contains, afterSequence = 0, limit, includeConnections = true }, ctx) => {
      const session = await ctx.session(tabId);
      const needle = String(contains ?? '').toLowerCase();
      const rows = session.frames.items.filter(frame =>
        (!requestId || frame.requestId === requestId) &&
        (!direction || frame.direction === direction) &&
        (!needle || String(frame.payload ?? '').toLowerCase().includes(needle)) &&
        frame.sequence > afterSequence
      );
      return {
        sessionId: session.tab?.id,
        totalMatches: rows.length,
        latestSequence: session.seq,
        connections: includeConnections ? [...session.wsConnections.values()] : undefined,
        frames: rows.slice(-Math.max(1, Math.min(200, limit ?? 50)))
      };
    }
  );

  add(
    'devtools_diagnose',
    'Summarize console errors, exceptions, failed/malformed requests, CORS failures, slow requests, dialogs and pending activity for a fast root-cause overview.',
    shape({
      tabId: tabIdSchema,
      slowMs: num('Slow-request threshold in milliseconds', { minimum: 1, maximum: 120_000 })
    }),
    'read-only',
    async ({ tabId, slowMs = 1500 }, ctx) => {
      const session = await ctx.session(tabId);
      return {
        sessionId: session.tab?.id,
        ...buildSessionDiagnostics(session, {
          slowMs,
          requestLimit: 50,
          consoleLimit: 20,
          websocketLimit: 10,
          includeRequests: true
        })
      };
    }
  );
}

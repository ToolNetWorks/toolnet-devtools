import fsp from 'node:fs/promises';
import path from 'node:path';
import { redactHeaders, redactText, redactUrl, safeResponseBody } from './security.mjs';

const HAR_CREATOR = { name: 'toolnet-devtools-mcp', version: '0.3.0' };
const MAX_EXPORT_BYTES = 64_000_000;

function round(value, digits = 2) {
  if (!Number.isFinite(value)) return 0;
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function headerArray(headers = {}) {
  return Object.entries(headers).map(([name, value]) => ({
    name,
    value: Array.isArray(value) ? value.join(', ') : String(value ?? '')
  }));
}

function queryArray(url) {
  try {
    return [...new URL(url).searchParams.entries()].map(([name, value]) => ({ name, value }));
  } catch {
    return [];
  }
}

function selectHeaders(req, includeSensitive, response = false) {
  if (includeSensitive && response && req.responseHeadersRaw) return req.responseHeadersRaw;
  if (includeSensitive && !response && req.headersRaw) return req.headersRaw;
  return redactHeaders(response ? (req.responseHeaders ?? {}) : (req.headers ?? {}));
}

function selectUrl(req, includeSensitive) {
  return includeSensitive && req.urlRaw ? req.urlRaw : redactUrl(req.url ?? '');
}

function harTimings(req) {
  const timing = req.timing ?? {};
  const dnsStart = Number(timing.dnsStart ?? -1);
  const dnsEnd = Number(timing.dnsEnd ?? -1);
  const connectStart = Number(timing.connectStart ?? -1);
  const connectEnd = Number(timing.connectEnd ?? -1);
  const sendStart = Number(timing.sendStart ?? -1);
  const sendEnd = Number(timing.sendEnd ?? -1);
  const receiveHeadersEnd = Number(timing.receiveHeadersEnd ?? -1);
  const first = [dnsStart, connectStart, sendStart].filter(value => value >= 0).sort((a, b) => a - b)[0] ?? 0;
  const blocked = Math.max(0, first);
  const dns = dnsStart >= 0 && dnsEnd >= dnsStart ? dnsEnd - dnsStart : 0;
  const connect = connectStart >= 0 && connectEnd >= connectStart ? connectEnd - connectStart : 0;
  const ssl = Number(timing.sslStart ?? -1) >= 0 && Number(timing.sslEnd ?? -1) >= Number(timing.sslStart)
    ? Number(timing.sslEnd) - Number(timing.sslStart)
    : -1;
  const send = sendStart >= 0 && sendEnd >= sendStart ? sendEnd - sendStart : 0;
  const wait = receiveHeadersEnd >= 0 && sendEnd >= 0 ? Math.max(0, receiveHeadersEnd - sendEnd) : 0;
  const total = Math.max(req.durationMs ?? 0, receiveHeadersEnd >= 0 ? receiveHeadersEnd : 0);
  const receive = Math.max(0, total - Math.max(0, receiveHeadersEnd));
  return {
    blocked: round(blocked),
    dns: round(dns),
    connect: round(connect),
    ssl: round(ssl),
    send: round(send),
    wait: round(wait),
    receive: round(receive),
    _total: round(total)
  };
}

async function bodyForHar(session, req, { includeBodies, includeSensitive, maxChars }) {
  if (!includeBodies) return null;
  try {
    const body = await session.responseBody(req.id, { maxChars, includeSensitive });
    return body;
  } catch (error) {
    return { error: redactText(error?.message ?? String(error), 300) };
  }
}

/**
 * Build a HAR 1.2 document. Secrets are redacted unless includeSensitive is
 * explicitly enabled by the permission layer. Cookies are intentionally not
 * exported by default.
 */
export async function buildHar(session, {
  includeBodies = false,
  includeSensitive = false,
  maxBodies = 100,
  maxBodyChars = 100_000
} = {}) {
  const records = session.requestLog.items?.length ? [...session.requestLog.items] : [...session.requests.values()];
  const entries = [];
  let bodyCount = 0;
  for (const req of records) {
    const url = selectUrl(req, includeSensitive);
    const requestHeaders = selectHeaders(req, includeSensitive, false);
    const responseHeaders = selectHeaders(req, includeSensitive, true);
    const timings = harTimings(req);
    let body = null;
    if (includeBodies && bodyCount < maxBodies && req.finished && !req.failed) {
      body = await bodyForHar(session, req, { includeBodies, includeSensitive, maxChars: maxBodyChars });
      bodyCount++;
    }
    const content = body?.binary
      ? { size: body.sizeHint ?? 0, mimeType: req.mimeType ?? '', text: '[binary omitted]', _binary: true }
      : {
          size: body?.originalChars ?? req.body?.originalChars ?? req.bytes ?? 0,
          mimeType: req.mimeType ?? '',
          text: includeBodies ? (body?.body ?? req.body?.body ?? '') : '',
          _truncated: includeBodies ? Boolean(body?.truncated ?? req.body?.truncated) : false,
          ...(body?.error ? { _error: body.error } : {})
        };
    const entry = {
      startedDateTime: req.startedAtIso ?? new Date((req.startedAt ?? Date.now() / 1000) * 1000).toISOString(),
      time: timings._total,
      request: {
        method: req.method,
        url,
        httpVersion: req.protocol ?? '',
        cookies: [],
        headers: headerArray(requestHeaders),
        queryString: queryArray(url),
        postData: req.hasPostData ? {
          mimeType: req.requestExtraHeaders?.['content-type'] ?? '',
          text: includeSensitive && req.postDataRaw ? req.postDataRaw : (req.postData ?? '')
        } : undefined,
        headersSize: -1,
        bodySize: req.postData?.length ?? 0
      },
      response: {
        status: req.status ?? 0,
        statusText: req.statusText ?? (req.failed ? 'Failed' : ''),
        httpVersion: req.protocol ?? '',
        cookies: [],
        headers: headerArray(responseHeaders),
        content,
        redirectURL: includeSensitive && req.redirectResponseLocationRaw
          ? req.redirectResponseLocationRaw
          : redactUrl(req.redirectResponse?.location ?? ''),
        headersSize: -1,
        bodySize: req.bytes ?? 0,
        _failed: req.failed === true,
        _error: req.errorText,
        _corsError: req.corsError
      },
      cache: {
        beforeRequest: req.servedFromCache ? { expires: null, lastAccess: null, eTag: '', hitCount: 1, comment: 'served from cache' } : undefined,
        afterRequest: undefined
      },
      timings: {
        blocked: timings.blocked,
        dns: timings.dns,
        connect: timings.connect,
        ssl: timings.ssl,
        send: timings.send,
        wait: timings.wait,
        receive: timings.receive
      },
      serverIPAddress: req.remoteAddress,
      connection: req.remotePort ? String(req.remotePort) : undefined,
      _resourceType: req.resourceType,
      _initiatorType: req.initiatorType,
      _fromDiskCache: req.fromDiskCache,
      _fromServiceWorker: req.fromServiceWorker,
      _sequence: req.sequence,
      _redirectChain: req.redirectChain?.length ? req.redirectChain : undefined
    };
    entries.push(entry);
  }
  return {
    log: {
      version: '1.2',
      creator: HAR_CREATOR,
      browser: { name: 'Chrome', version: session.tab ? 'unknown' : 'unknown' },
      pages: [],
      entries
    }
  };
}

export function buildErrorReport(session, { slowMs = 1500 } = {}) {
  const requests = [...session.requests.values()];
  const failures = requests.filter(req => req.failed || (req.status ?? 0) >= 400);
  const slow = requests.filter(req => (req.durationMs ?? 0) >= slowMs);
  const errors = session.console.items.filter(entry => entry.level === 'error' || entry.category === 'exception');
  const warnings = session.console.items.filter(entry => entry.level === 'warning');
  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    tab: session.tab,
    page: session.pageState,
    permission: session.options?.allowSensitive ? 'full-debug+sensitive' : undefined,
    summary: {
      consoleEntries: session.console.items.length,
      consoleErrors: errors.length,
      consoleWarnings: warnings.length,
      capturedRequests: requests.length,
      failedRequests: failures.length,
      slowRequests: slow.length,
      websocketFrames: session.frames.items.length,
      websocketConnections: session.wsConnections.size,
      pendingRequests: session.pendingRequestCount(),
      paused: session.paused != null
    },
    errors: errors.slice(-30),
    warnings: warnings.slice(-10),
    failedRequests: failures.slice(-30).map(req => ({
      id: req.id,
      sequence: req.sequence,
      url: redactUrl(req.url),
      method: req.method,
      type: req.resourceType,
      status: req.status,
      error: req.errorText,
      corsError: req.corsError,
      durationMs: req.durationMs,
      redirectChain: req.redirectChain
    })),
    slowRequests: slow.slice(-20).map(req => ({
      id: req.id,
      url: redactUrl(req.url),
      method: req.method,
      type: req.resourceType,
      status: req.status,
      durationMs: req.durationMs
    })),
    websocketConnections: [...session.wsConnections.values()],
    dialogs: session.dialogs.items,
    page: session.pageState
  };
}

export function buildJsonExport(session, { includeBodies = false, slowMs = 1500 } = {}) {
  const report = buildErrorReport(session, { slowMs });
  const records = session.requestLog.items?.length ? session.requestLog.items : [...session.requests.values()];
  const requests = records.map(req => ({
    id: req.id,
    sequence: req.sequence,
    url: redactUrl(req.url),
    method: req.method,
    type: req.resourceType,
    status: req.status,
    statusText: req.statusText,
    finished: req.finished,
    failed: req.failed,
    error: req.errorText,
    corsError: req.corsError,
    startedAt: req.startedAtIso,
    durationMs: req.durationMs,
    bytes: req.bytes,
    mimeType: req.mimeType,
    protocol: req.protocol,
    headers: redactHeaders(req.headers),
    responseHeaders: redactHeaders(req.responseHeaders),
    postData: req.postData,
    body: includeBodies ? (req.body ?? null) : undefined,
    redirectChain: req.redirectChain,
    initiatorType: req.initiatorType,
    remoteAddress: req.remoteAddress
  }));
  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    tab: session.tab,
    report,
    console: session.console.items,
    requests,
    websocket: {
      connections: [...session.wsConnections.values()],
      frames: session.frames.items
    },
    dialogs: session.dialogs.items,
    scripts: session.debuggerEnabled ? [...session.scripts.values()] : [],
    trace: session.lastTrace ? {
      finished: session.lastTrace.finished,
      durationMs: session.lastTrace.durationMs,
      storedEvents: session.lastTrace.storedEvents,
      truncated: session.lastTrace.truncated,
      topEvents: session.lastTrace.topEvents
    } : null,
    profile: session.lastProfileSummary ?? null
  };
}

export function buildTraceExport(session) {
  if (!session.lastTrace) throw new Error('No trace available. Run devtools_performance action=trace_start, then trace_stop.');
  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    summary: {
      finished: session.lastTrace.finished,
      durationMs: session.lastTrace.durationMs,
      categories: session.lastTrace.categories,
      receivedEvents: session.lastTrace.receivedEvents,
      storedEvents: session.lastTrace.storedEvents,
      storedBytes: session.lastTrace.storedBytes,
      truncated: session.lastTrace.truncated,
      topEvents: session.lastTrace.topEvents
    },
    traceEvents: session.lastTrace.events
  };
}

export function buildProfileExport(session) {
  if (!session.lastProfile) throw new Error('No CPU profile available. Run devtools_performance action=profile_start, then profile_stop.');
  return { summary: session.lastProfileSummary, profile: session.lastProfile };
}

export function resolveExportPath(requestedPath, format, exportDir) {
  const extension = format === 'har' ? 'har' : format === 'trace' ? 'trace.json' : format === 'profile' ? 'cpuprofile' : 'json';
  const fallback = `toolnet-${format}-${new Date().toISOString().replace(/[:.]/g, '-')}.${extension}`;
  const relative = requestedPath && requestedPath.trim() ? requestedPath.trim() : fallback;
  const root = path.resolve(exportDir);
  const resolved = path.isAbsolute(relative) ? path.resolve(relative) : path.resolve(root, relative);
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) {
    throw new Error(`Export path must stay inside ${root}. Set DEVTOOLS_EXPORT_DIR to a different directory if needed.`);
  }
  return resolved;
}

export async function writeExportFile({ session, format, includeBodies = false, includeSensitive = false, path: requestedPath = null, exportDir }) {
  let document;
  if (format === 'har') {
    document = await buildHar(session, { includeBodies, includeSensitive });
  } else if (format === 'report') {
    document = buildErrorReport(session);
  } else if (format === 'trace') {
    document = buildTraceExport(session);
  } else if (format === 'profile') {
    document = buildProfileExport(session);
  } else if (format === 'json') {
    document = buildJsonExport(session, { includeBodies });
  } else {
    throw new Error('Unsupported export format. Use json, har, report, trace or profile.');
  }
  const text = JSON.stringify(document);
  const bytes = Buffer.byteLength(text);
  if (bytes > MAX_EXPORT_BYTES) throw new Error(`Export is too large (${bytes} bytes; maximum ${MAX_EXPORT_BYTES})`);
  const filePath = resolveExportPath(requestedPath, format, exportDir);
  await fsp.mkdir(path.dirname(filePath), { recursive: true });
  await fsp.writeFile(filePath, text, 'utf8');
  return {
    format,
    path: filePath,
    bytes,
    entries: format === 'har' ? document.log.entries.length : undefined,
    summary: format === 'report' ? document.summary : undefined,
    includeBodies,
    includeSensitive
  };
}

export { safeResponseBody, redactUrl };

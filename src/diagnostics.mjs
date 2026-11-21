/**
 * Shared, bounded DevTools diagnostics.
 *
 * Both devtools_diagnose and the one-call F12 workflow use this module so the
 * agent sees exactly the same summary regardless of how the capture started.
 * Nothing here returns raw headers, cookies, tokens or request bodies.
 */

function publicRequest(req) {
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
    startedAt: req.startedAtIso,
    initiatorType: req.initiatorType,
    fromDiskCache: req.fromDiskCache,
    fromServiceWorker: req.fromServiceWorker,
    redirectChain: req.redirectChain?.length ? req.redirectChain : undefined
  };
}

function bounded(value, min, max, fallback) {
  const number = Number.isFinite(value) ? Math.trunc(value) : fallback;
  return Math.max(min, Math.min(max, number));
}

export function buildSessionDiagnostics(session, {
  slowMs = 1500,
  requestLimit = 50,
  consoleLimit = 20,
  websocketLimit = 10,
  includeRequests = true
} = {}) {
  const threshold = bounded(slowMs, 1, 120_000, 1500);
  const requestCap = bounded(requestLimit, 1, 200, 50);
  const consoleCap = bounded(consoleLimit, 1, 100, 20);
  const websocketCap = bounded(websocketLimit, 1, 100, 10);

  const requests = [...session.requests.values()];
  const failures = requests.filter(req => req.failed || (req.status ?? 0) >= 400);
  const slow = requests.filter(req => (req.durationMs ?? 0) >= threshold);
  const errors = session.console.items.filter(entry => entry.level === 'error' || entry.category === 'exception');
  const warnings = session.console.items.filter(entry => entry.level === 'warning');
  const openDialogs = session.dialogs.items.filter(dialog => !dialog.handled);
  const websocketConnections = [...session.wsConnections.values()];

  return {
    page: { ...session.pageState },
    summary: {
      consoleEntries: session.console.items.length,
      consoleErrors: errors.length,
      consoleWarnings: warnings.length,
      capturedRequests: requests.length,
      capturedRequestLogEntries: session.requestLog.items.length,
      failedRequests: failures.length,
      slowRequests: slow.length,
      websocketConnections: websocketConnections.length,
      websocketFrames: session.frames.items.length,
      pendingRequests: session.pendingRequestCount(),
      paused: session.paused != null,
      dialogs: openDialogs.length,
      latestSequence: session.seq
    },
    errors: errors.slice(-consoleCap),
    warnings: warnings.slice(-Math.min(10, consoleCap)),
    failedRequests: failures.slice(-Math.min(50, requestCap)).map(publicRequest),
    slowRequests: slow.slice(-Math.min(30, requestCap)).map(publicRequest),
    requests: includeRequests ? requests.slice(-requestCap).map(publicRequest) : undefined,
    websocket: {
      connections: websocketConnections.slice(-websocketCap),
      frames: session.frames.items.length
    },
    websocketErrors: websocketConnections.filter(connection => connection.lastError),
    dialogs: openDialogs,
    suggestedNextSteps: [
      'Inspect a specific request with devtools_request and devtools_response_body.',
      'Poll devtools_console/devtools_network with afterSequence to follow new activity.',
      'Use devtools_click, devtools_type, devtools_scroll, devtools_reload or devtools_select_tab for follow-up interaction.',
      'Export with devtools_export format=har or format=report for a durable artifact.'
    ]
  };
}

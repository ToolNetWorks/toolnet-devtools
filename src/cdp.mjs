import fsp from 'node:fs/promises';
import path from 'node:path';
import {
  estimateBytes,
  isAllowedEndpoint,
  isAllowedWebSocket,
  looksTextual,
  redactHeaders,
  redactText,
  redactUrl,
  safeResponseBody
} from './security.mjs';

export const LIMITS = Object.freeze({
  consoleEntries: 1000,
  consoleBytes: 2_000_000,
  requests: 2000,
  requestBytes: 6_000_000,
  websocketFrames: 1000,
  websocketBytes: 2_000_000,
  scripts: 4000,
  dialogs: 50,
  traceEvents: 80_000,
  traceBytes: 24_000_000,
  bodyBytes: 8_000_000,
  bodyChars: 200_000,
  postDataChars: 40_000
});

const TRACE_DEFAULT_CATEGORIES = 'devtools.timeline,v8,blink.user_timing,loading,disabled-by-default-devtools.timeline';
const WS_TYPES = new Set(['WebSocket', 'EventSource']);

export function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/** Count-bounded and byte-bounded in-memory ring buffer. */
export class Ring {
  constructor(limit, maxBytes = Infinity) {
    this.limit = limit;
    this.maxBytes = maxBytes;
    this.items = [];
    this.bytes = 0;
  }

  push(item) {
    this.items.push(item);
    this.bytes += estimateBytes(item);
    while (this.items.length > this.limit || (this.bytes > this.maxBytes && this.items.length > 1)) {
      const removed = this.items.shift();
      this.bytes -= estimateBytes(removed);
      if (this.bytes < 0) this.bytes = 0;
    }
    return item;
  }

  clear() {
    this.items = [];
    this.bytes = 0;
  }

  get length() { return this.items.length; }
}

function formatStack(stackTrace, limit = 20) {
  return (stackTrace?.callFrames ?? []).slice(0, limit).map(frame => ({
    functionName: frame.functionName || '(anonymous)',
    url: redactUrl(frame.url || ''),
    line: Number.isInteger(frame.lineNumber) ? frame.lineNumber + 1 : null,
    column: Number.isInteger(frame.columnNumber) ? frame.columnNumber + 1 : null
  }));
}

function formatRemoteObject(arg) {
  if (arg == null) return 'null';
  if (arg.type === 'undefined') return 'undefined';
  if (arg.value !== undefined) {
    if (typeof arg.value === 'string') return redactText(arg.value, 4000);
    try { return redactText(JSON.stringify(arg.value), 4000); }
    catch { return redactText(String(arg.value), 4000); }
  }
  if (arg.unserializableValue != null) return redactText(String(arg.unserializableValue), 2000);
  if (arg.preview?.properties?.length) {
    const preview = Object.fromEntries(arg.preview.properties.slice(0, 20).map(prop => [prop.name, prop.value]));
    return redactText(`${arg.description ?? arg.className ?? arg.type ?? 'Object'} ${safeJson(preview, 3000)}`, 4000);
  }
  return redactText(arg.description ?? `[${arg.type ?? 'object'}]`, 4000);
}

function timestampIso(value, unit = 'seconds') {
  if (!Number.isFinite(value)) return null;
  const ms = unit === 'milliseconds' ? value : value * 1000;
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function mapConsoleLevel(type) {
  if (type === 'warning' || type === 'warn') return 'warning';
  if (type === 'error' || type === 'assert') return 'error';
  if (type === 'debug') return 'debug';
  if (type === 'trace') return 'trace';
  if (type === 'info') return 'info';
  return 'log';
}

function safeJson(value, max = 8000) {
  try { return redactText(JSON.stringify(value), max); }
  catch { return redactText(String(value), max); }
}

function headerValue(headers, name) {
  if (!headers || typeof headers !== 'object') return undefined;
  const key = Object.keys(headers).find(item => item.toLowerCase() === name.toLowerCase());
  return key == null ? undefined : headers[key];
}

function redirectLocation(headers, { includeSensitive = false } = {}) {
  const raw = headerValue(headers, 'location');
  if (raw == null) return undefined;
  return includeSensitive ? String(raw) : redactUrl(String(raw));
}

export class ChromeSession {
  /**
   * One CDP connection to one page target. Event buffers are per instance, so
   * two tabs never share console/network history.
   */
  constructor(endpoint = 'http://127.0.0.1:9222', options = {}) {
    if (!isAllowedEndpoint(endpoint)) {
      throw new Error('CDP endpoint must be loopback HTTP (127.0.0.1 / localhost / ::1) or CDP_ALLOW_REMOTE=1');
    }
    this.endpoint = endpoint.replace(/\/$/, '');
    this.options = {
      allowSensitive: options.allowSensitive === true,
      captureBodies: options.captureBodies !== false,
      autoDismissDialogs: options.autoDismissDialogs === true,
      maxBodyChars: options.maxBodyChars ?? LIMITS.bodyChars,
      maxCachedBodyBytes: options.maxCachedBodyBytes ?? LIMITS.bodyBytes,
      logger: options.logger ?? console
    };
    this.tab = null;
    this.socket = null;
    this.pending = new Map();
    this.nextId = 0;
    this.seq = 0;
    this.connectedAt = null;
    this.console = new Ring(LIMITS.consoleEntries, LIMITS.consoleBytes);
    this.requests = new Map();
    this.requestLog = new Ring(LIMITS.requests, LIMITS.requestBytes);
    this.frames = new Ring(LIMITS.websocketFrames, LIMITS.websocketBytes);
    this.scripts = new Map();
    this.breakpoints = new Map();
    this.dialogs = new Ring(LIMITS.dialogs, 200_000);
    this.wsConnections = new Map();
    this.pageState = { url: 'about:blank', title: '', readyState: 'loading', loaded: false, lastLoadAt: null };
    this.captureReadiness = {
      networkEnabled: false,
      networkEnabledAt: null,
      runtimeEnabled: false,
      runtimeEnabledAt: null,
      pageEnabled: false,
      pageEnabledAt: null,
      readyAt: null,
      enabledDomains: [],
      lastNavigationAt: null
    };
    this.lastNetworkAt = Date.now();
    this.lastWindowOpen = null;
    this.paused = null;
    this.debuggerEnabled = false;
    this.trace = null;
    this.lastTrace = null;
    this.lastProfile = null;
    this.lastProfileSummary = null;
    this.bodyQueue = [];
    this.bodyWorkers = 0;
    this.cachedBodyBytes = 0;
  }

  async requestJson(path, { method = 'GET', timeoutMs = 5000 } = {}) {
    const url = `${this.endpoint}${path}`;
    const res = await fetch(url, { method, signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) throw new Error(`Chrome debugging endpoint returned HTTP ${res.status} for ${path}`);
    try { return await res.json(); }
    catch { throw new Error(`Chrome debugging endpoint returned invalid JSON for ${path}`); }
  }

  async requestText(path, { method = 'GET', timeoutMs = 5000 } = {}) {
    const res = await fetch(`${this.endpoint}${path}`, { method, signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) throw new Error(`Chrome debugging endpoint returned HTTP ${res.status} for ${path}`);
    return await res.text();
  }

  async version() {
    return await this.requestJson('/json/version');
  }

  async tabs() {
    const targets = await this.requestJson('/json/list', { timeoutMs: 4000 });
    if (!Array.isArray(targets)) throw new Error('Chrome target list is invalid');
    return targets.filter(target => target.type === 'page').map(target => ({
      id: target.id,
      title: redactText(target.title ?? '', 300),
      url: redactUrl(target.url ?? ''),
      webSocketDebuggerUrl: target.webSocketDebuggerUrl
    }));
  }

  /** Create a real Chrome tab. The caller MUST attach before navigating. */
  async createTab(url = 'about:blank') {
    const target = await this.requestJson(`/json/new?${encodeURIComponent(url)}`, { method: 'PUT', timeoutMs: 8000 });
    if (!target?.id) throw new Error('Chrome did not return a new tab target');
    return {
      id: target.id,
      title: redactText(target.title ?? '', 300),
      url: redactUrl(target.url ?? url),
      webSocketDebuggerUrl: target.webSocketDebuggerUrl
    };
  }

  async closeTab(tabId) {
    if (typeof tabId !== 'string' || !tabId) throw new Error('tabId is required');
    await this.requestText(`/json/close/${encodeURIComponent(tabId)}`, { timeoutMs: 5000 });
    return true;
  }

  async activateTab(tabId) {
    if (typeof tabId !== 'string' || !tabId) throw new Error('tabId is required');
    return await this.requestText(`/json/activate/${encodeURIComponent(tabId)}`, { timeoutMs: 5000 });
  }

  async attach(tabId, { fresh = true, enableDebugger = false, target = null } = {}) {
    let tab = target;
    if (!tab) {
      const targets = await this.tabs();
      tab = tabId ? targets.find(item => item.id === tabId) : targets[0];
    }
    if (!tab) throw new Error('Page tab not found. Call devtools_open_url or devtools_tabs first.');
    if (!tab.webSocketDebuggerUrl) {
      // /json/new may omit the debugger URL even though /json/list has it.
      const targets = await this.tabs();
      tab = targets.find(item => item.id === tab.id) ?? tab;
    }
    if (!tab.webSocketDebuggerUrl || !isAllowedWebSocket(tab.webSocketDebuggerUrl, this.endpoint)) {
      throw new Error('Unsafe or missing Chrome WebSocket URL');
    }
    if (this.socket?.readyState === WebSocket.OPEN && this.tab?.id === tab.id && !fresh) {
      await this.ensureCaptureEnabled();
      return this.status();
    }
    await this.close();
    if (fresh) this.clearAll();
    const socket = new WebSocket(tab.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Chrome WebSocket connection timed out')), 8000);
      socket.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
      socket.addEventListener('error', () => { clearTimeout(timer); reject(new Error('Chrome WebSocket failed to connect')); }, { once: true });
    }).catch(error => { socket.close(); throw error; });
    this.socket = socket;
    this.tab = { id: tab.id, title: tab.title, url: tab.url };
    this.connectedAt = new Date().toISOString();
    this.lastNetworkAt = Date.now();
    socket.addEventListener('message', event => this.onMessage(event.data));
    socket.addEventListener('close', () => {
      if (this.socket !== socket) return;
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(new Error('Chrome tab disconnected'));
      }
      this.pending.clear();
      this.socket = null;
    });
    try {
      // Network and Runtime must be enabled before the first navigation. This
      // is the core guarantee that the initial document/API requests are
      // captured from the first byte.
      await this.enableCaptureDomains({ timeoutMs: 10_000 });
    } catch (error) {
      await this.close();
      throw error;
    }
    if (enableDebugger) await this.enableDebugger();
    return this.status();
  }

  async enableCaptureDomains({ timeoutMs = 10_000 } = {}) {
    await this.send('Network.enable', {
      maxTotalBufferSize: 16_000_000,
      maxResourceBufferSize: 2_000_000,
      maxPostDataSize: LIMITS.postDataChars
    }, timeoutMs);
    this.captureReadiness.networkEnabled = true;
    this.captureReadiness.networkEnabledAt = new Date().toISOString();
    await this.send('Runtime.enable', {}, timeoutMs);
    this.captureReadiness.runtimeEnabled = true;
    this.captureReadiness.runtimeEnabledAt = new Date().toISOString();
    await this.send('Page.enable', {}, timeoutMs);
    this.captureReadiness.pageEnabled = true;
    this.captureReadiness.pageEnabledAt = new Date().toISOString();
    const optionalDomains = await Promise.allSettled([
      this.send('Log.enable', {}, Math.min(8000, timeoutMs)),
      this.send('Page.setLifecycleEventsEnabled', { enabled: true }, Math.min(8000, timeoutMs)),
      this.send('DOM.enable', {}, Math.min(8000, timeoutMs)),
      this.send('CSS.enable', {}, Math.min(8000, timeoutMs))
    ]);
    this.captureReadiness.enabledDomains = [
      'Network', 'Runtime', 'Page',
      ...(optionalDomains[0].status === 'fulfilled' ? ['Log'] : []),
      ...(optionalDomains[1].status === 'fulfilled' ? ['Page.lifecycle'] : []),
      ...(optionalDomains[2].status === 'fulfilled' ? ['DOM'] : []),
      ...(optionalDomains[3].status === 'fulfilled' ? ['CSS'] : [])
    ];
    this.captureReadiness.readyAt = new Date().toISOString();
    return { ...this.captureReadiness };
  }

  get connected() {
    return this.socket?.readyState === WebSocket.OPEN;
  }

  status() {
    return {
      connected: this.connected,
      tab: this.tab,
      connectedAt: this.connectedAt,
      captureReadiness: { ...this.captureReadiness },
      consoleEntries: this.console.items.length,
      requests: this.requests.size,
      requestLogEntries: this.requestLog.items.length,
      websocketFrames: this.frames.items.length,
      websocketConnections: this.wsConnections.size,
      scripts: this.scripts.size,
      debuggerEnabled: this.debuggerEnabled,
      paused: this.paused != null,
      lastWindowOpen: this.lastWindowOpen,
      page: this.pageState,
      latestSequence: this.seq,
      buffers: {
        consoleBytes: this.console.bytes,
        requestBytes: this.requestLog.bytes,
        websocketBytes: this.frames.bytes,
        cachedBodyBytes: this.cachedBodyBytes
      },
      pendingRequests: this.pendingRequestCount()
    };
  }

  async send(method, params = {}, timeoutMs = 10_000) {
    if (typeof method !== 'string' || !/^[A-Za-z]+\.[A-Za-z]+$/.test(method)) throw new Error('Invalid CDP method');
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
      throw new Error('Not attached. Call devtools_attach or devtools_open_url first.');
    }
    const id = ++this.nextId;
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`CDP timeout: ${method} (${timeoutMs} ms)`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      try {
        this.socket.send(JSON.stringify({ id, method, params }));
      } catch (error) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(error);
      }
    });
  }

  onMessage(data) {
    let msg;
    try { msg = JSON.parse(typeof data === 'string' ? data : String(data)); }
    catch { return; }
    if (typeof msg.id === 'number') {
      const pending = this.pending.get(msg.id);
      if (!pending) return;
      clearTimeout(pending.timer);
      this.pending.delete(msg.id);
      if (msg.error) {
        const error = new Error(`${msg.error.message ?? 'CDP error'} (${msg.error.code ?? 'unknown'})`);
        error.code = msg.error.code;
        pending.reject(error);
      } else {
        pending.resolve(msg.result ?? {});
      }
      return;
    }
    if (!msg.method) return;
    try { this.handleEvent(msg.method, msg.params ?? {}); }
    catch (error) {
      this.options.logger?.error?.(`[toolnet-devtools] event handler failed for ${msg.method}: ${error?.message}`);
    }
  }

  nextSeq() { return ++this.seq; }

  clearAll() {
    this.console.clear();
    this.requests.clear();
    this.requestLog.clear();
    this.frames.clear();
    this.dialogs.clear();
    this.wsConnections.clear();
    this.scripts.clear();
    this.breakpoints.clear();
    this.lastWindowOpen = null;
    this.paused = null;
    this.lastTrace = null;
    this.lastProfile = null;
    this.lastProfileSummary = null;
    this.cachedBodyBytes = 0;
    this.bodyQueue.length = 0;
    this.seq = 0;
  }

  handleEvent(method, data) {
    if (method === 'Runtime.consoleAPICalled') {
      const args = (data.args ?? []).slice(0, 20).map(formatRemoteObject);
      const type = data.type ?? 'log';
      this.console.push({
        sequence: this.nextSeq(),
        category: 'console',
        level: mapConsoleLevel(type),
        type,
        text: redactText(args.join(' '), 8000),
        args,
        timestamp: data.timestamp,
        timestampIso: timestampIso(data.timestamp, 'milliseconds'),
        stackTrace: formatStack(data.stackTrace),
        executionContextId: data.executionContextId
      });
      return;
    }
    if (method === 'Runtime.exceptionThrown') {
      const detail = data.exceptionDetails ?? {};
      const description = detail.exception?.description ?? detail.text ?? 'JavaScript exception';
      this.console.push({
        sequence: this.nextSeq(),
        category: 'exception',
        level: 'error',
        type: 'exception',
        text: redactText(description, 8000),
        exception: safeJson({
          type: detail.exception?.type,
          subtype: detail.exception?.subtype,
          className: detail.exception?.className,
          description: detail.exception?.description
        }),
        url: redactUrl(detail.url ?? ''),
        line: Number.isInteger(detail.lineNumber) ? detail.lineNumber + 1 : null,
        column: Number.isInteger(detail.columnNumber) ? detail.columnNumber + 1 : null,
        stackTrace: formatStack(detail.stackTrace),
        timestamp: data.timestamp,
        timestampIso: timestampIso(data.timestamp, 'milliseconds')
      });
      return;
    }
    if (method === 'Log.entryAdded') {
      const entry = data.entry ?? {};
      this.console.push({
        sequence: this.nextSeq(),
        category: entry.source ?? 'browser',
        level: entry.level === 'warning' ? 'warning' : (entry.level ?? 'info'),
        type: 'log-entry',
        text: redactText(entry.text, 8000),
        url: redactUrl(entry.url ?? ''),
        line: entry.lineNumber,
        networkRequestId: entry.networkRequestId,
        stackTrace: formatStack(entry.stackTrace),
        timestamp: entry.timestamp,
        timestampIso: timestampIso(entry.timestamp, 'milliseconds')
      });
      return;
    }
    if (method === 'Network.requestWillBeSent') {
      this.onRequestWillBeSent(data);
      return;
    }
    if (method === 'Network.requestWillBeSentExtraInfo') {
      const req = this.requests.get(data.requestId);
      if (!req) return;
      req.requestExtraHeaders = redactHeaders(data.headers ?? {});
      req.associatedCookieCount = (data.associatedCookies ?? []).length;
      req.clientSecurityState = data.clientSecurityState?.protocol;
      return;
    }
    if (method === 'Network.responseReceived') {
      const req = this.requests.get(data.requestId);
      if (!req) return;
      const response = data.response ?? {};
      req.status = response.status ?? req.status;
      req.statusText = response.statusText ?? req.statusText;
      req.mimeType = response.mimeType ?? req.mimeType;
      req.charset = response.charset;
      req.protocol = response.protocol;
      req.responseUrl = redactUrl(response.url ?? req.url);
      req.responseHeaders = redactHeaders(response.headers ?? {});
      if (this.options.allowSensitive) req.responseHeadersRaw = redactHeaders(response.headers ?? {}, { includeSensitive: true });
      req.remoteAddress = response.remoteIPAddress;
      req.remotePort = response.remotePort;
      req.connectionId = response.connectionId;
      req.connectionReused = response.connectionReused;
      req.fromDiskCache = response.fromDiskCache;
      req.fromPrefetchCache = response.fromPrefetchCache;
      req.fromServiceWorker = response.fromServiceWorker;
      req.cacheStorageCacheName = response.cacheStorageCacheName;
      req.resourceType = data.type ?? req.resourceType;
      req.responseTimestamp = data.timestamp;
      req.timing = response.timing;
      req.securityState = response.securityState;
      req.securityDetails = response.securityDetails ? {
        protocol: response.securityDetails.protocol,
        issuer: response.securityDetails.issuer,
        validFrom: response.securityDetails.validFrom,
        validTo: response.securityDetails.validTo,
        subjectName: response.securityDetails.subjectName,
        sanList: response.securityDetails.sanList?.slice(0, 10)
      } : undefined;
      this.lastNetworkAt = Date.now();
      return;
    }
    if (method === 'Network.responseReceivedExtraInfo') {
      const req = this.requests.get(data.requestId);
      if (!req) return;
      req.status = data.statusCode ?? req.status;
      req.responseExtraHeaders = redactHeaders(data.headers ?? {});
      req.blockedCookieCount = (data.blockedCookies ?? []).length;
      return;
    }
    if (method === 'Network.dataReceived') {
      const req = this.requests.get(data.requestId);
      if (!req) return;
      req.bytes = (req.bytes ?? 0) + (data.encodedDataLength ?? 0);
      req.dataLength = (req.dataLength ?? 0) + (data.dataLength ?? 0);
      this.lastNetworkAt = Date.now();
      return;
    }
    if (method === 'Network.loadingFinished') {
      const req = this.requests.get(data.requestId);
      if (!req) return;
      req.finished = true;
      req.durationMs = Math.max(0, Math.round((data.timestamp - req.startTimestamp) * 1000));
      req.bytes = Math.max(req.bytes ?? 0, data.encodedDataLength ?? 0);
      req.encodedDataLength = data.encodedDataLength;
      this.lastNetworkAt = Date.now();
      this.scheduleBodyCapture(req);
      return;
    }
    if (method === 'Network.loadingFailed') {
      const req = this.requests.get(data.requestId);
      if (!req) return;
      req.finished = true;
      req.failed = true;
      req.errorText = redactText(data.errorText, 800);
      req.canceled = data.canceled;
      req.blockedReason = data.blockedReason;
      req.corsError = data.corsErrorStatus?.corsError;
      req.corsErrorStatus = data.corsErrorStatus ? {
        corsError: data.corsErrorStatus.corsError,
        failedParameter: data.corsErrorStatus.failedParameter
      } : undefined;
      req.durationMs = Math.max(0, Math.round((data.timestamp - req.startTimestamp) * 1000));
      this.lastNetworkAt = Date.now();
      return;
    }
    if (method === 'Network.requestServedFromCache') {
      const req = this.requests.get(data.requestId);
      if (req) req.servedFromCache = true;
      return;
    }
    if (method === 'Network.webSocketCreated') {
      this.wsConnections.set(data.requestId, {
        requestId: data.requestId,
        url: redactUrl(data.url ?? ''),
        initiator: data.initiator?.type,
        createdAt: new Date().toISOString(),
        framesSent: 0,
        framesReceived: 0,
        status: 'created'
      });
      return;
    }
    if (method === 'Network.webSocketWillSendHandshakeRequest') {
      const connection = this.wsConnections.get(data.requestId);
      if (!connection) return;
      connection.handshakeRequestHeaders = redactHeaders(data.request?.headers ?? {});
      connection.handshakeAt = data.timestamp;
      connection.status = 'handshaking';
      return;
    }
    if (method === 'Network.webSocketHandshakeResponseReceived') {
      const connection = this.wsConnections.get(data.requestId);
      if (!connection) return;
      connection.status = 'open';
      connection.handshakeStatus = data.response?.status;
      connection.handshakeResponseHeaders = redactHeaders(data.response?.headers ?? {});
      connection.protocol = data.response?.headers?.['Sec-WebSocket-Protocol'] ?? data.response?.headers?.['sec-websocket-protocol'];
      return;
    }
    if (method === 'Network.webSocketFrameReceived' || method === 'Network.webSocketFrameSent') {
      this.onWebSocketFrame(method, data);
      return;
    }
    if (method === 'Network.webSocketClosed') {
      const connection = this.wsConnections.get(data.requestId);
      if (connection) connection.status = 'closed';
      return;
    }
    if (method === 'Network.webSocketFrameError') {
      const connection = this.wsConnections.get(data.requestId);
      if (connection) connection.lastError = redactText(data.errorMessage, 500);
      return;
    }
    if (method === 'Network.eventSourceMessageReceived') {
      this.frames.push({
        sequence: this.nextSeq(),
        requestId: data.requestId,
        kind: 'eventsource',
        direction: 'received',
        eventName: data.eventName,
        eventId: data.eventId,
        payload: redactText(data.data, 4000),
        timestamp: data.timestamp
      });
      return;
    }
    if (method === 'Page.javascriptDialogOpening') {
      const dialog = {
        sequence: this.nextSeq(),
        type: data.type,
        message: redactText(data.message, 2000),
        defaultPrompt: redactText(data.defaultPrompt, 1000),
        url: redactUrl(data.url ?? ''),
        openedAt: new Date().toISOString(),
        handled: false
      };
      this.dialogs.push(dialog);
      if (this.options.autoDismissDialogs) {
        this.handleJavaScriptDialog({ accept: false }).catch(() => {});
      }
      return;
    }
    if (method === 'Fetch.requestPaused') {
      const rule = this._matchFetchRule(data);
      if (!rule || rule.action === 'continue') {
        this.send('Fetch.continueRequest', { requestId: data.requestId }).catch(() => {});
        return;
      }
      if (rule.action === 'block') {
        this.send('Fetch.failRequest', { requestId: data.requestId, errorReason: 'BlockedByClient' }).catch(() => {});
        return;
      }
      if (rule.action === 'mock') {
        const headers = Object.entries(rule.headers || { 'Content-Type': 'application/json' }).map(([name, value]) => ({ name, value: String(value) }));
        const body = Buffer.from(rule.body ?? '').toString('base64');
        this.send('Fetch.fulfillRequest', {
          requestId: data.requestId,
          responseCode: rule.status ?? 200,
          responseHeaders: headers,
          body
        }).catch(() => this.send('Fetch.continueRequest', { requestId: data.requestId }).catch(() => {}));
        return;
      }
      this.send('Fetch.continueRequest', { requestId: data.requestId }).catch(() => {});
      return;
    }
    if (method === 'Fetch.authRequired') {
      this.send('Fetch.continueWithAuth', { requestId: data.requestId, authChallengeResponse: { response: 'Default' } }).catch(() => {});
      return;
    }
    if (method === 'Page.javascriptDialogClosed') {
      const open = [...this.dialogs.items].reverse().find(item => !item.handled);
      if (open) {
        open.handled = true;
        open.accepted = data.result;
        open.userInput = redactText(data.userInput, 1000);
      }
      return;
    }
    if (method === 'Page.windowOpen') {
      this.lastWindowOpen = {
        url: redactUrl(data.url ?? ''),
        windowName: data.windowName || null,
        windowFeatures: data.windowFeatures ?? [],
        userGesture: data.userGesture === true,
        openedAt: new Date().toISOString()
      };
      return;
    }
    if (method === 'Page.frameNavigated') {
      if (!data.frame?.parentId) {
        this.pageState.url = redactUrl(data.frame?.url ?? this.pageState.url);
        this.pageState.title = redactText(data.frame?.name ?? this.pageState.title, 300);
        this.pageState.loaded = false;
      }
      return;
    }
    if (method === 'Page.domContentEventFired') {
      this.pageState.readyState = 'interactive';
      return;
    }
    if (method === 'Page.loadEventFired') {
      this.pageState.readyState = 'complete';
      this.pageState.loaded = true;
      this.pageState.lastLoadAt = new Date().toISOString();
      return;
    }
    if (method === 'Page.lifecycleEvent') {
      if (data.name === 'networkIdle') this.pageState.networkIdleAt = new Date().toISOString();
      return;
    }
    if (method === 'Debugger.scriptParsed') {
      if (this.scripts.size >= LIMITS.scripts) {
        const oldest = this.scripts.keys().next().value;
        if (oldest != null) this.scripts.delete(oldest);
      }
      this.scripts.set(data.scriptId, {
        scriptId: data.scriptId,
        url: redactUrl(data.url ?? ''),
        startLine: data.startLine,
        startColumn: data.startColumn,
        endLine: data.endLine,
        endColumn: data.endColumn,
        executionContextId: data.executionContextId,
        hash: data.hash,
        sourceMapURL: data.sourceMapURL ? redactUrl(data.sourceMapURL) : undefined,
        isModule: data.isModule
      });
      return;
    }
    if (method === 'Debugger.breakpointResolved') {
      const breakpoint = this.breakpoints.get(data.breakpointId);
      if (breakpoint) {
        breakpoint.resolved = true;
        breakpoint.locations = (breakpoint.locations ?? []).concat(data.location ? [data.location] : []);
      }
      return;
    }
    if (method === 'Debugger.paused') {
      this.paused = {
        reason: data.reason,
        data: data.data ? safeJson(data.data) : undefined,
        hitBreakpoints: data.hitBreakpoints ?? [],
        callFrames: (data.callFrames ?? []).slice(0, 40).map(frame => ({
          callFrameId: frame.callFrameId,
          functionName: frame.functionName || '(anonymous)',
          url: redactUrl(frame.url || this.scripts.get(frame.location?.scriptId)?.url || ''),
          location: frame.location ? { scriptId: frame.location.scriptId, lineNumber: frame.location.lineNumber + 1, columnNumber: frame.location.columnNumber + 1 } : null,
          scopeTypes: (frame.scopeChain ?? []).map(scope => ({ type: scope.type, name: scope.name })).slice(0, 12),
          thisType: frame.this?.type
        })),
        asyncStackTrace: formatStack(data.asyncStackTrace),
        pausedAt: new Date().toISOString()
      };
      return;
    }
    if (method === 'Debugger.resumed') {
      this.paused = null;
      return;
    }
    if (method === 'Tracing.dataCollected') {
      if (!this.trace) return;
      const events = Array.isArray(data.value) ? data.value : [];
      this.trace.receivedEvents += events.length;
      for (const event of events) {
        const name = typeof event?.name === 'string' ? event.name : 'unknown';
        this.trace.counts[name] = (this.trace.counts[name] ?? 0) + 1;
        if (this.trace.events.length >= this.trace.maxEvents) {
          this.trace.truncated = true;
          continue;
        }
        const size = estimateBytes(event);
        if (this.trace.bytes + size > this.trace.maxBytes) {
          this.trace.truncated = true;
          continue;
        }
        this.trace.events.push(event);
        this.trace.bytes += size;
      }
      return;
    }
    if (method === 'Tracing.tracingComplete') {
      if (this.trace?.completeResolve) this.trace.completeResolve(true);
      return;
    }
    if (method === 'Inspector.targetCrashed') {
      this.pageState.crashed = true;
      return;
    }
  }

  onRequestWillBeSent(data) {
    const requestId = data.requestId;
    const previous = this.requests.get(requestId);
    let redirectChain = [];
    if (previous) {
      previous.finished = true;
      previous.status = data.redirectResponse?.status ?? previous.status;
      previous.statusText = data.redirectResponse?.statusText ?? previous.statusText;
      const redirectHeaders = redactHeaders(data.redirectResponse?.headers ?? previous.responseHeaders ?? {});
      const location = redirectLocation(data.redirectResponse?.headers);
      if (location && redirectHeaders) {
        for (const key of Object.keys(redirectHeaders)) {
          if (key.toLowerCase() === 'location') redirectHeaders[key] = location;
        }
      }
      previous.responseHeaders = redirectHeaders;
      previous.redirectedTo = redactUrl(data.request?.url ?? '');
      previous.redirectResponse = {
        status: data.redirectResponse?.status,
        statusText: data.redirectResponse?.statusText,
        url: redactUrl(data.redirectResponse?.url ?? ''),
        headers: redirectHeaders,
        location
      };
      if (this.options.allowSensitive) {
        previous.redirectResponseLocationRaw = redirectLocation(data.redirectResponse?.headers, { includeSensitive: true });
      }
      redirectChain = (previous.redirectChain ?? []).concat([{
        url: previous.url,
        status: previous.status,
        statusText: previous.statusText,
        location
      }]);
    }
    const request = data.request ?? {};
    const record = {
      sequence: this.nextSeq(),
      id: requestId,
      url: redactUrl(request.url ?? ''),
      method: request.method ?? 'GET',
      resourceType: data.type ?? 'Other',
      initiatorType: data.initiator?.type,
      initiatorUrl: data.initiator?.url ? redactUrl(data.initiator.url) : undefined,
      headers: redactHeaders(request.headers ?? {}),
      postData: request.postData ? redactText(request.postData, LIMITS.postDataChars) : undefined,
      hasPostData: request.hasPostData ?? Boolean(request.postData),
      startedAt: data.wallTime,
      startedAtIso: Number.isFinite(data.wallTime) ? new Date(data.wallTime * 1000).toISOString() : null,
      startTimestamp: data.timestamp,
      status: null,
      statusText: null,
      finished: false,
      failed: false,
      redirectChain,
      redirectedFrom: previous?.url,
      frameId: data.frameId,
      loaderId: data.loaderId,
      documentURL: request.url ? redactUrl(request.url) : undefined,
      referrerPolicy: request.referrerPolicy,
      initialPriority: request.initialPriority,
      mixedContentType: request.mixedContentType
    };
    if (this.options.allowSensitive) {
      record.headersRaw = redactHeaders(request.headers ?? {}, { includeSensitive: true });
      record.urlRaw = String(request.url ?? '').slice(0, 4000);
      if (request.postData) record.postDataRaw = request.postData.slice(0, LIMITS.postDataChars);
    }
    this.requests.set(requestId, record);
    this.requestLog.push(record);
    if (this.requests.size > LIMITS.requests) {
      const oldest = this.requests.keys().next().value;
      if (oldest != null) this.requests.delete(oldest);
    }
    this.lastNetworkAt = Date.now();
  }

  onWebSocketFrame(method, data) {
    const frame = data.response ?? {};
    const direction = method.endsWith('Received') ? 'received' : 'sent';
    const opcode = frame.opcode;
    const payloadData = frame.payloadData;
    const isBinary = opcode === 2;
    const payload = isBinary
      ? `[binary frame, ${String(payloadData ?? '').length} base64 chars]`
      : redactText(payloadData, 6000);
    this.frames.push({
      sequence: this.nextSeq(),
      requestId: data.requestId,
      direction,
      opcode,
      binary: isBinary,
      payload,
      payloadLength: typeof payloadData === 'string' ? payloadData.length : 0,
      timestamp: data.timestamp,
      capturedAt: new Date().toISOString()
    });
    const connection = this.wsConnections.get(data.requestId);
    if (connection) {
      if (direction === 'received') connection.framesReceived++;
      else connection.framesSent++;
    }
  }

  pendingRequestCount() {
    let count = 0;
    for (const req of this.requests.values()) {
      if (!req.finished && !WS_TYPES.has(req.resourceType)) count++;
    }
    return count;
  }

  scheduleBodyCapture(req) {
    if (!this.options.captureBodies || req.body || req.bodyError || !req.finished || req.failed) return;
    if (!['XHR', 'Fetch', 'Document'].includes(req.resourceType)) return;
    if (!looksTextual(req.mimeType ?? '')) return;
    if (!req.mimeType || req.status === 204 || req.status === 304) return;
    if (this.bodyQueue.length > 100) {
      const dropped = this.bodyQueue.shift();
      if (dropped) dropped.bodySkipped = 'queue-limit';
    }
    this.bodyQueue.push(req);
    this.pumpBodyQueue();
  }

  pumpBodyQueue() {
    while (this.bodyWorkers < 2 && this.bodyQueue.length > 0) {
      const req = this.bodyQueue.shift();
      this.bodyWorkers++;
      this.captureResponseBody(req)
        .catch(() => {})
        .finally(() => {
          this.bodyWorkers--;
          this.pumpBodyQueue();
        });
    }
  }

  async captureResponseBody(req) {
    if (req.body || req.bodyError || !req.finished || req.failed) return;
    try {
      const raw = await this.send('Network.getResponseBody', { requestId: req.id }, 12_000);
      const safe = safeResponseBody(raw, this.options.maxBodyChars);
      const size = safe.body.length;
      if (this.cachedBodyBytes + size > this.options.maxCachedBodyBytes) {
        req.bodySkipped = 'memory-limit';
        return;
      }
      req.body = safe;
      req.bodyFetchedAt = new Date().toISOString();
      this.cachedBodyBytes += size;
    } catch (error) {
      req.bodyError = redactText(error?.message ?? String(error), 500);
    }
  }

  async responseBody(requestId, { maxChars = 20_000, includeSensitive = false } = {}) {
    const req = this.requests.get(requestId);
    if (!req) throw new Error('Request not found in buffer');
    if (includeSensitive) {
      const raw = await this.send('Network.getResponseBody', { requestId }, 12_000);
      return safeResponseBody(raw, maxChars, { includeSensitive: true });
    }
    if (req.body && !includeSensitive) {
      return { ...req.body, body: req.body.body.slice(0, maxChars), truncated: req.body.truncated || req.body.body.length > maxChars };
    }
    const raw = await this.send('Network.getResponseBody', { requestId }, 12_000);
    const safe = safeResponseBody(raw, maxChars);
    if (!req.body && !req.failed) {
      const size = safe.body.length;
      if (this.cachedBodyBytes + size <= this.options.maxCachedBodyBytes) {
        req.body = safe;
        this.cachedBodyBytes += size;
      }
    }
    return safe;
  }

  async requestBody(requestId, { maxChars = 20_000, includeSensitive = false } = {}) {
    const req = this.requests.get(requestId);
    if (!req) throw new Error('Request not found in buffer');
    if (['GET', 'HEAD'].includes(req.method)) {
      return { requestId, method: req.method, body: null, reason: 'No request body expected for this method' };
    }
    if (includeSensitive) {
      const raw = await this.send('Network.getRequestPostData', { requestId }, 12_000);
      return { requestId, method: req.method, url: req.url, ...safeResponseBody({ body: raw.postData ?? '' }, maxChars, { includeSensitive: true }) };
    }
    if (req.postData != null) {
      return { requestId, method: req.method, url: req.url, binary: false, body: req.postData.slice(0, maxChars), truncated: req.postData.length > maxChars, originalChars: req.postData.length };
    }
    const raw = await this.send('Network.getRequestPostData', { requestId }, 12_000);
    const safe = safeResponseBody({ body: raw.postData ?? '' }, maxChars);
    return { requestId, method: req.method, url: req.url, ...safe };
  }

  async evaluateValue(expression, { timeoutMs = 7000 } = {}) {
    const result = await this.send('Runtime.evaluate', {
      expression,
      returnByValue: true,
      generatePreview: true,
      awaitPromise: false,
      timeout: timeoutMs
    }, timeoutMs + 2000);
    if (result.exceptionDetails) {
      throw new Error(result.exceptionDetails.exception?.description ?? result.exceptionDetails.text ?? 'Evaluation failed');
    }
    return result.result?.value;
  }

  async waitFor(predicate, timeoutMs = 10_000, intervalMs = 100) {
    const deadline = Date.now() + Math.max(1, timeoutMs);
    while (Date.now() < deadline) {
      try {
        if (await predicate()) return true;
      } catch { /* context can disappear while navigating */ }
      await sleep(Math.min(intervalMs, Math.max(1, deadline - Date.now())));
    }
    return false;
  }

  async downloadViaClick(selector, { timeoutMs = 15000, settleMs = 1000, downloadPath } = {}) {
    const dir = downloadPath || this.options.downloadDir || '/tmp/opencode/downloads';
    await fsp.mkdir(dir, { recursive: true }).catch(() => {});
    await this.send('Browser.setDownloadBehavior', { behavior: 'allowAndName', downloadPath: dir, eventsEnabled: true }, 8000).catch(() => {});
    const before = new Set((await fsp.readdir(dir).catch(() => [])).filter(Boolean));
    await this.click(selector, { timeoutMs, settleMs });
    const deadline = Date.now() + Math.max(1000, settleMs + 5000);
    let files = [];
    while (Date.now() < deadline) {
      const after = await fsp.readdir(dir).catch(() => []);
      files = after.filter(f => !before.has(f));
      if (files.some(f => !f.endsWith('.crdownload') && !f.endsWith('.tmp'))) break;
      await sleep(250);
    }
    const completed = files.filter(f => !f.endsWith('.crdownload') && !f.endsWith('.tmp'));
    return { triggered: true, selector, downloadPath: dir, files: completed, pending: files.filter(f => f.endsWith('.crdownload') || f.endsWith('.tmp')) };
  }

  async waitForReadyState(target, timeoutMs) {
    const states = target === 'domcontentloaded' ? ['interactive', 'complete'] : ['complete'];
    return await this.waitFor(async () => {
      const state = await this.evaluateValue('document.readyState', { timeoutMs: 3000 });
      return states.includes(state);
    }, timeoutMs);
  }

  async waitForNetworkIdle({ idleMs = 600, timeoutMs = 15_000 } = {}) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const pending = this.pendingRequestCount();
      const idleFor = Date.now() - this.lastNetworkAt;
      if (pending === 0 && idleFor >= idleMs) return true;
      if (pending <= 2 && idleFor >= Math.max(idleMs * 2, 1500)) return true;
      await sleep(150);
    }
    return false;
  }

  async pageInfo() {
    try {
      const info = await this.evaluateValue(`(() => ({
        url: location.href,
        title: document.title,
        readyState: document.readyState,
        origin: location.origin,
        viewport: { width: innerWidth, height: innerHeight, devicePixelRatio },
        scroll: { x: scrollX, y: scrollY, height: document.documentElement?.scrollHeight ?? 0 },
        forms: document.forms?.length ?? 0,
        links: document.links?.length ?? 0,
        images: document.images?.length ?? 0
      }))()`);
      return { ...info, url: redactUrl(info.url ?? ''), title: redactText(info.title ?? '', 300) };
    } catch {
      return { ...this.pageState };
    }
  }

  async ensureCaptureEnabled({ timeoutMs = 10_000 } = {}) {
    if (!this.connected) throw new Error('Not attached to a Chrome tab. Attach CDP before enabling capture.');
    if (!this.captureReadiness.networkEnabled) {
      await this.send('Network.enable', {
        maxTotalBufferSize: 16_000_000,
        maxResourceBufferSize: 2_000_000,
        maxPostDataSize: LIMITS.postDataChars
      }, timeoutMs);
      this.captureReadiness.networkEnabled = true;
      this.captureReadiness.networkEnabledAt = new Date().toISOString();
    }
    if (!this.captureReadiness.runtimeEnabled) {
      await this.send('Runtime.enable', {}, timeoutMs);
      this.captureReadiness.runtimeEnabled = true;
      this.captureReadiness.runtimeEnabledAt = new Date().toISOString();
    }
    if (!this.captureReadiness.pageEnabled) {
      await this.send('Page.enable', {}, timeoutMs);
      this.captureReadiness.pageEnabled = true;
      this.captureReadiness.pageEnabledAt = new Date().toISOString();
    }
    const domains = new Set(this.captureReadiness.enabledDomains ?? []);
    for (const domain of ['Network', 'Runtime', 'Page']) domains.add(domain);
    // Re-enable optional domains after a reconnect; they are cheap and keep
    // DOM/CSS/Log available for the rest of the session.
    const optional = [];
    if (!domains.has('Log')) optional.push(['Log', 'Log.enable', {}]);
    if (!domains.has('DOM')) optional.push(['DOM', 'DOM.enable', {}]);
    if (!domains.has('CSS')) optional.push(['CSS', 'CSS.enable', {}]);
    if (optional.length) {
      const results = await Promise.allSettled(optional.map(([, method, params]) => this.send(method, params, Math.min(8000, timeoutMs))));
      results.forEach((result, index) => {
        if (result.status === 'fulfilled') domains.add(optional[index][0]);
      });
    }
    if (!domains.has('Page.lifecycle')) {
      try {
        await this.send('Page.setLifecycleEventsEnabled', { enabled: true }, Math.min(8000, timeoutMs));
        domains.add('Page.lifecycle');
      } catch { /* optional */ }
    }
    this.captureReadiness.enabledDomains = [...domains];
    this.captureReadiness.readyAt = this.captureReadiness.readyAt ?? new Date().toISOString();
    return { ...this.captureReadiness };
  }

  async navigate(url, { waitUntil = 'load', timeoutMs = 30_000 } = {}) {
    await this.ensureCaptureEnabled();
    const started = Date.now();
    const requestCountBefore = this.requestLog.items.length;
    const navigationStartedAt = new Date().toISOString();
    this.captureReadiness.lastNavigationAt = navigationStartedAt;
    this.pageState = { url: redactUrl(url), title: '', readyState: 'loading', loaded: false, lastLoadAt: null };
    this.lastNetworkAt = Date.now();
    const raw = await this.send('Page.navigate', { url }, 15_000);
    if (raw.errorText) throw new Error(`Navigation failed: ${raw.errorText}`);
    if (raw.isDownload) {
      return {
        url: redactUrl(url),
        requestedUrl: redactUrl(url),
        isDownload: true,
        frameId: raw.frameId,
        loaderId: raw.loaderId,
        timedOut: false,
        navigationStartedAt,
        networkEnabledBeforeNavigation: this.captureReadiness.networkEnabled === true,
        networkEnabledAt: this.captureReadiness.networkEnabledAt,
        requestCountBefore,
        requestCountAfter: this.requestLog.items.length
      };
    }
    let timedOut = false;
    if (waitUntil !== 'none') {
      if (waitUntil === 'domcontentloaded' || waitUntil === 'load') {
        timedOut = !(await this.waitForReadyState(waitUntil, timeoutMs));
      } else if (waitUntil === 'networkidle0' || waitUntil === 'networkidle2' || waitUntil === 'networkidle') {
        const ready = await this.waitForReadyState('load', Math.min(timeoutMs, 20_000));
        const idle = await this.waitForNetworkIdle({ idleMs: 600, timeoutMs: Math.max(1000, timeoutMs - (Date.now() - started)) });
        timedOut = !(ready && idle);
      } else {
        throw new Error(`Unsupported waitUntil "${waitUntil}". Use none, domcontentloaded, load, networkidle0 or networkidle2.`);
      }
    }
    const info = await this.pageInfo();
    this.pageState.url = redactUrl(info.url ?? url);
    this.pageState.title = redactText(info.title ?? '', 300);
    this.pageState.readyState = info.readyState ?? this.pageState.readyState;
    this.pageState.loaded = info.readyState === 'complete';
    if (this.tab) this.tab = { ...this.tab, url: this.pageState.url, title: this.pageState.title };
    return {
      url: info.url ?? redactUrl(url),
      requestedUrl: redactUrl(url),
      title: info.title,
      readyState: info.readyState,
      timedOut,
      durationMs: Date.now() - started,
      frameId: raw.frameId,
      loaderId: raw.loaderId,
      navigationStartedAt,
      networkEnabledBeforeNavigation: this.captureReadiness.networkEnabled === true,
      networkEnabledAt: this.captureReadiness.networkEnabledAt,
      requestCountBefore,
      requestCountAfter: this.requestLog.items.length
    };
  }

  async reload({ ignoreCache = false, waitUntil = 'load', timeoutMs = 30_000 } = {}) {
    await this.ensureCaptureEnabled();
    const started = Date.now();
    const requestCountBefore = this.requestLog.items.length;
    const navigationStartedAt = new Date().toISOString();
    this.captureReadiness.lastNavigationAt = navigationStartedAt;
    this.pageState.loaded = false;
    await this.send('Page.reload', { ignoreCache }, 15_000);
    let timedOut = false;
    if (waitUntil !== 'none') {
      if (waitUntil === 'networkidle0' || waitUntil === 'networkidle2' || waitUntil === 'networkidle') {
        const ready = await this.waitForReadyState('load', timeoutMs);
        const idle = await this.waitForNetworkIdle({ timeoutMs: Math.max(1000, timeoutMs - (Date.now() - started)) });
        timedOut = !(ready && idle);
      } else {
        timedOut = !(await this.waitForReadyState(waitUntil === 'domcontentloaded' ? 'domcontentloaded' : 'load', timeoutMs));
      }
    }
    const info = await this.pageInfo();
    if (this.tab) this.tab = { ...this.tab, url: info.url ?? this.tab.url, title: info.title ?? this.tab.title };
    return {
      ...info,
      reloaded: true,
      timedOut,
      durationMs: Date.now() - started,
      navigationStartedAt,
      networkEnabledBeforeNavigation: this.captureReadiness.networkEnabled === true,
      networkEnabledAt: this.captureReadiness.networkEnabledAt,
      requestCountBefore,
      requestCountAfter: this.requestLog.items.length
    };
  }

  async history(direction, { waitUntil = 'load', timeoutMs = 30_000 } = {}) {
    await this.ensureCaptureEnabled();
    const requestCountBefore = this.requestLog.items.length;
    const navigationStartedAt = new Date().toISOString();
    const history = await this.send('Page.getNavigationHistory');
    const entries = history.entries ?? [];
    const index = history.currentIndex ?? 0;
    const targetIndex = direction === 'back' ? index - 1 : index + 1;
    if (targetIndex < 0 || targetIndex >= entries.length) {
      return { moved: false, reason: `No ${direction} history entry`, index, total: entries.length };
    }
    const entry = entries[targetIndex];
    await this.send('Page.navigateToHistoryEntry', { entryId: entry.id }, 15_000);
    let timedOut = false;
    if (waitUntil !== 'none') timedOut = !(await this.waitForReadyState('load', timeoutMs));
    const info = await this.pageInfo();
    if (this.tab) this.tab = { ...this.tab, url: info.url ?? this.tab.url, title: info.title ?? this.tab.title };
    return {
      moved: true,
      direction,
      index: targetIndex,
      total: entries.length,
      ...info,
      timedOut,
      navigationStartedAt,
      networkEnabledBeforeNavigation: this.captureReadiness.networkEnabled === true,
      requestCountBefore,
      requestCountAfter: this.requestLog.items.length
    };
  }

  _locatorExpression(locator = {}) {
    // Returns a JS expression that evaluates to an Element or null. Searches document, open shadow roots, and same-origin iframes.
    const search = `((root) => {
      const all = (r) => { const out=[]; const walk=(n)=>{ if(!n||n.nodeType!==1) return; out.push(n); if(n.shadowRoot) walk(n.shadowRoot); for(const c of (n.children||[])) walk(c); }; walk(r.body||r); return out; };
      const nodes = all(root);
      const vis = (el) => { try { const r=el.getBoundingClientRect(); const s=getComputedStyle(el); return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none'; } catch { return false; } };
      return { nodes, vis };
    })(document)`;
    if (locator.selector) {
      const sel = JSON.stringify(String(locator.selector));
      return `(() => { const find=(root)=>{ try{const el=root.querySelector(${sel}); if(el) return el;}catch{} for(const n of root.querySelectorAll('*')){ if(n.shadowRoot){ const f=find(n.shadowRoot); if(f) return f; } } return null; }; return find(document); })()`;
    }
    if (locator.xpath) {
      const xp = JSON.stringify(String(locator.xpath));
      return `(() => { const find=(root,doc)=>{ try{ const r=doc.evaluate(${xp}, root, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue; if(r) return r; }catch{} for(const n of (root.querySelectorAll?root.querySelectorAll('*'):[])){ if(n.shadowRoot){ const f=find(n.shadowRoot, n.shadowRoot); if(f) return f; } } return null; }; return find(document, document); })()`;
    }
    if (locator.testId) {
      const id = JSON.stringify(String(locator.testId));
      return `(() => { const find=(root)=>{ const el=root.querySelector('[data-testid='+${id}+'],[data-test-id='+${id}+']'); if(el) return el; for(const n of root.querySelectorAll('*')){ if(n.shadowRoot){ const f=find(n.shadowRoot); if(f) return f; } } return null; }; return find(document); })()`;
    }
    if (locator.text) {
      const t = JSON.stringify(String(locator.text).toLowerCase());
      return `(() => { const find=(root)=>{ const nodes=[...root.querySelectorAll('a,button,input,textarea,select,label,[role],[aria-label],h1,h2,h3,h4,h5,h6,span,div,p,li,td,th')]; for(const el of nodes){ const txt=((el.innerText||el.textContent||el.value||'')+' '+(el.getAttribute('aria-label')||'')+' '+(el.getAttribute('title')||'')).toLowerCase(); if(txt.includes(${t})) return el; } for(const n of root.querySelectorAll('*')){ if(n.shadowRoot){ const f=find(n.shadowRoot); if(f) return f; } } return null; }; return find(document); })()`;
    }
    if (locator.role) {
      const role = JSON.stringify(String(locator.role).toLowerCase());
      const name = locator.name ? JSON.stringify(String(locator.name).toLowerCase()) : null;
      return `(() => { const find=(root)=>{ const nodes=[...root.querySelectorAll('[role],button,a,input,select,textarea,h1,h2,h3,h4,h5,h6')]; for(const el of nodes){ const tag=el.tagName.toLowerCase(); const r=(el.getAttribute('role')||'').toLowerCase(); const implicit = (${role}==='button'&&(tag==='button'||el.type==='button'||el.type==='submit')) || (${role}==='link'&&tag==='a') || (${role}==='textbox'&&(tag==='textarea'||(tag==='input'&&!['button','submit','checkbox','radio','file','hidden'].includes(el.type))));
        if(!(r===${role}||implicit)) continue; if(${name ? 'true' : 'false'}){ const n=((el.innerText||el.textContent||el.value||'')+' '+(el.getAttribute('aria-label')||'')).toLowerCase(); if(!n.includes(${name})) continue; } return el; } for(const n of root.querySelectorAll('*')){ if(n.shadowRoot){ const f=find(n.shadowRoot); if(f) return f; } } return null; }; return find(document); })()`;
    }
    throw new Error('Provide selector, xpath, text, role, or testId');
  }

  async waitForSelector(selector, timeoutMs = 10_000, { visible = false } = {}) {
    const locator = typeof selector === 'string' ? { selector } : (selector || {});
    const nodeExpr = this._locatorExpression(locator);
    const expr = visible
      ? `(() => { const el = ${nodeExpr}; if (!el) return false; const r = el.getBoundingClientRect(); const s = getComputedStyle(el); return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; })()`
      : `Boolean(${nodeExpr})`;
    return await this.waitFor(() => this.evaluateValue(expr, { timeoutMs: 3000 }), timeoutMs);
  }

  async _resolveLocator(locatorInput, { timeoutMs = 10000, visible = true } = {}) {
    const locator = typeof locatorInput === 'string' ? { selector: locatorInput } : (locatorInput || {});
    const found = await this.waitForSelector(locator, timeoutMs, { visible });
    if (!found) throw new Error(`Element not found${visible ? '/visible' : ''}: ${JSON.stringify(locator)}`);
    const nodeExpr = this._locatorExpression(locator);
    const rect = await this.evaluateValue(`(() => { const el = ${nodeExpr}; if (!el) return null; el.scrollIntoViewIfNeeded?.(); const r = el.getBoundingClientRect(); return { x:(r.left+r.right)/2, y:(r.top+r.bottom)/2, width:r.width, height:r.height, tag:el.tagName?.toLowerCase(), text:(el.innerText||el.textContent||'').trim().slice(0,200), value:el.value }; })()`, { timeoutMs: 5000 });
    if (!rect) throw new Error(`Element resolved then disappeared: ${JSON.stringify(locator)}`);
    return { locator, rect, nodeExpr };
  }

  async click(selector, { timeoutMs = 10_000, settleMs = 250, button = 'left', clickCount = 1 } = {}) {
    const locator = typeof selector === 'string' ? { selector } : selector;
    await this.ensureCaptureEnabled();
    this.lastWindowOpen = null;
    const { rect } = await this._resolveLocator(locator, { timeoutMs, visible: true });
    const x = Math.max(0, Math.round(rect.x));
    const y = Math.max(0, Math.round(rect.y));
    await this.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x, y });
    for (let i = 1; i <= Math.max(1, clickCount); i++) {
      await this.send('Input.dispatchMouseEvent', { type: 'mousePressed', x, y, button, clickCount: i });
      await this.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x, y, button, clickCount: i });
    }
    if (settleMs > 0) await sleep(settleMs);
    return { clicked: true, locator, selector: typeof selector === 'string' ? selector : undefined, x, y, ...(await this.pageInfo()), openedWindow: this.lastWindowOpen };
  }

  async dispatchKey(key, { modifiers = 0, code = null, keyCode = null, text = undefined } = {}) {
    const params = {
      key,
      code: code ?? key,
      modifiers,
      windowsVirtualKeyCode: keyCode ?? 0,
      nativeVirtualKeyCode: keyCode ?? 0
    };
    if (text != null) params.text = text;
    await this.send('Input.dispatchKeyEvent', { type: 'rawKeyDown', ...params });
    if (text) await this.send('Input.dispatchKeyEvent', { type: 'char', ...params });
    await this.send('Input.dispatchKeyEvent', { type: 'keyUp', ...params });
  }

  async pressKey(key, { modifiers = 0 } = {}) {
    const keyMap = {
      Enter: { code: 'Enter', keyCode: 13, text: '\r' },
      Tab: { code: 'Tab', keyCode: 9, text: '\t' },
      Escape: { code: 'Escape', keyCode: 27 },
      Backspace: { code: 'Backspace', keyCode: 8 },
      Delete: { code: 'Delete', keyCode: 46 },
      ArrowUp: { code: 'ArrowUp', keyCode: 38 },
      ArrowDown: { code: 'ArrowDown', keyCode: 40 },
      ArrowLeft: { code: 'ArrowLeft', keyCode: 37 },
      ArrowRight: { code: 'ArrowRight', keyCode: 39 },
      Home: { code: 'Home', keyCode: 36 },
      End: { code: 'End', keyCode: 35 },
      PageUp: { code: 'PageUp', keyCode: 33 },
      PageDown: { code: 'PageDown', keyCode: 34 },
      ' ': { code: 'Space', keyCode: 32, text: ' ' }
    };
    const mapped = keyMap[key];
    if (!mapped) throw new Error(`Unsupported key "${key}". Use a DOM key such as Enter, Tab, Escape, ArrowDown, Backspace.`);
    await this.dispatchKey(key, { modifiers, ...mapped });
    return { pressed: key, modifiers };
  }

  async typeText(selector, text, { clear = true, submit = false, timeoutMs = 10_000, settleMs = 150 } = {}) {
    if (typeof text !== 'string') throw new Error('text must be a string');
    if (text.length > 20_000) throw new Error('text is too long (maximum 20000 characters)');
    await this.ensureCaptureEnabled();
    if (selector) {
      const found = await this.waitForSelector(selector, timeoutMs, { visible: true });
      if (!found) return { typed: false, selector, reason: 'Element not found or not visible before timeout' };
      await this.click(selector, { timeoutMs, settleMs: 50 });
    }
    if (clear) {
      await this.evaluateValue(`(() => { const el = document.activeElement; if (el && typeof el.select === 'function') el.select(); return true; })()`).catch(() => {});
      await this.dispatchKey('Backspace', { code: 'Backspace', keyCode: 8 });
    }
    if (text) await this.send('Input.insertText', { text }, 15_000);
    if (submit) await this.pressKey('Enter');
    if (settleMs > 0) await sleep(settleMs);
    let value = null;
    try {
      value = await this.evaluateValue(`(() => { const el = document.activeElement; return el ? (('value' in el) ? el.value : el.textContent) : null; })()`);
    } catch { /* ignore */ }
    return { typed: true, selector: selector ?? null, value: redactText(value, 2000), submitted: submit, ...(await this.pageInfo()) };
  }

  async scroll({ x = null, y = null, deltaX = 0, deltaY = 600, selector = null, settleMs = 200 } = {}) {
    await this.ensureCaptureEnabled();
    if (selector) {
      await this.evaluateValue(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); if (!el) return false; el.scrollIntoView({ block: 'center' }); return true; })()`);
    }
    const info = await this.pageInfo();
    const pointX = x ?? Math.round((info.viewport?.width ?? 800) / 2);
    const pointY = y ?? Math.round((info.viewport?.height ?? 600) / 2);
    await this.send('Input.dispatchMouseEvent', {
      type: 'mouseWheel', x: pointX, y: pointY, deltaX, deltaY
    });
    if (settleMs > 0) await sleep(settleMs);
    return { scrolled: true, deltaX, deltaY, ...(await this.pageInfo()) };
  }

  async waitForExpression(expression, timeoutMs = 10_000) {
    if (typeof expression !== 'string' || !expression.trim()) throw new Error('expression is required');
    const matched = await this.waitFor(async () => Boolean(await this.evaluateValue(expression, { timeoutMs: 3000 })), timeoutMs);
    return { matched, expression, ...(await this.pageInfo()) };
  }

  async screenshot({ format = 'png', quality = 80, fullPage = false } = {}) {
    const params = { format, captureBeyondViewport: fullPage === true };
    if (format === 'jpeg') params.quality = Math.max(1, Math.min(100, quality));
    const { data } = await this.send('Page.captureScreenshot', params, 20_000);
    if (!data) throw new Error('Chrome did not return a screenshot');
    if (data.length > 12_000_000) throw new Error('Screenshot too large (>12 MB)');
    return { data, format };
  }

  async handleJavaScriptDialog({ accept = true, promptText = undefined } = {}) {
    await this.send('Page.handleJavaScriptDialog', { accept, promptText }, 8000);
    const dialog = [...this.dialogs.items].reverse().find(item => !item.handled);
    if (dialog) {
      dialog.handled = true;
      dialog.accepted = accept;
      dialog.handledAt = new Date().toISOString();
    }
    return { handled: true, accept, promptText: promptText == null ? undefined : '[provided]' };
  }

  async cookies(urls = null) {
    const raw = urls?.length
      ? await this.send('Network.getCookies', { urls }, 10_000)
      : await this.send('Network.getAllCookies', {}, 10_000);
    return raw.cookies ?? [];
  }

  async setCookie(params) {
    return await this.send('Network.setCookie', params, 10_000);
  }

  async clearCookies() {
    await this.send('Network.clearBrowserCookies', {}, 10_000);
    return { cleared: true };
  }

  async storage(type = 'local', limit = 200) {
    const name = type === 'session' ? 'sessionStorage' : 'localStorage';
    const expression = `(() => {
      try {
        const store = window[${JSON.stringify(name)}];
        const entries = [];
        const total = store.length;
        for (let i = 0; i < store.length && i < ${Math.max(1, Math.min(1000, limit))}; i++) {
          const key = store.key(i);
          entries.push({ key, value: store.getItem(key) });
        }
        return { origin: location.origin, type: ${JSON.stringify(name)}, total, entries };
      } catch (error) { return { error: String(error), origin: location.origin, type: ${JSON.stringify(name)}, total: 0, entries: [] }; }
    })()`;
    return await this.evaluateValue(expression);
  }

  async setStorageItem(type, key, value) {
    const name = type === 'session' ? 'sessionStorage' : 'localStorage';
    const expression = `(() => { window[${JSON.stringify(name)}].setItem(${JSON.stringify(String(key))}, ${JSON.stringify(String(value))}); return true; })()`;
    await this.evaluateValue(expression);
    return { set: true, type, key: redactText(key, 200), valueChars: String(value).length };
  }

  async removeStorageItem(type, key) {
    const name = type === 'session' ? 'sessionStorage' : 'localStorage';
    const expression = `(() => { window[${JSON.stringify(name)}].removeItem(${JSON.stringify(String(key))}); return true; })()`;
    await this.evaluateValue(expression);
    return { removed: true, type, key: redactText(key, 200) };
  }

  async clearStorage(type) {
    const name = type === 'session' ? 'sessionStorage' : 'localStorage';
    await this.evaluateValue(`(() => { window[${JSON.stringify(name)}].clear(); return true; })()`);
    return { cleared: true, type };
  }

  async storageState({ includeSensitive = false } = {}) {
    const url = this.pageState?.url || 'about:blank';
    let cookies = [];
    try {
      if (/^https?:/i.test(url)) cookies = await this.cookies([url]);
      else cookies = await this.cookies();
    } catch { /* ignore */ }
    const local = await this.storage('local', 1000).catch(() => ({ entries: [] }));
    const session = await this.storage('session', 1000).catch(() => ({ entries: [] }));
    const redact = (value) => includeSensitive ? value : (value == null ? value : '[REDACTED]');
    return {
      url,
      origin: (() => { try { return new URL(url).origin; } catch { return null; } })(),
      cookies: cookies.map(c => ({ ...c, value: redact(c.value) })),
      localStorage: (local.entries ?? []).map(e => ({ ...e, value: redact(e.value) })),
      sessionStorage: (session.entries ?? []).map(e => ({ ...e, value: redact(e.value) }))
    };
  }

  async restoreStorageState(state, { includeSensitive = false } = {}) {
    if (!state || typeof state !== 'object') throw new Error('state must be an object');
    if (!includeSensitive) throw new Error('Restoring storage state requires includeSensitive=true and full-debug+DEVTOOLS_ALLOW_SENSITIVE');
    const results = { cookies: 0, localStorage: 0, sessionStorage: 0, errors: [] };
    for (const cookie of state.cookies ?? []) {
      try { await this.setCookie(cookie); results.cookies++; } catch (e) { results.errors.push(`cookie:${cookie?.name}:${String(e?.message ?? e)}`); }
    }
    for (const entry of state.localStorage ?? []) {
      try { await this.setStorageItem('local', entry.key, entry.value ?? ''); results.localStorage++; } catch (e) { results.errors.push(`local:${entry?.key}:${String(e?.message ?? e)}`); }
    }
    for (const entry of state.sessionStorage ?? []) {
      try { await this.setStorageItem('session', entry.key, entry.value ?? ''); results.sessionStorage++; } catch (e) { results.errors.push(`session:${entry?.key}:${String(e?.message ?? e)}`); }
    }
    return results;
  }

  async performanceMetrics() {
    await this.send('Performance.enable', {}, 8000);
    const raw = await this.send('Performance.getMetrics', {}, 8000);
    return Object.fromEntries((raw.metrics ?? []).map(row => [row.name, row.value]));
  }

  async enableDebugger() {
    if (this.debuggerEnabled) return;
    await this.send('Debugger.enable', {}, 10_000);
    await this.send('Debugger.setAsyncCallStackDepth', { maxDepth: 16 }, 8000).catch(() => {});
    this.debuggerEnabled = true;
  }

  async debuggerScripts({ contains = null, limit = 100 } = {}) {
    await this.enableDebugger();
    const rows = [...this.scripts.values()].filter(script => !contains || script.url.toLowerCase().includes(String(contains).toLowerCase()));
    return { total: rows.length, scripts: rows.slice(0, Math.max(1, Math.min(500, limit))) };
  }

  async setBreakpoint({ url = null, urlRegex = null, lineNumber, columnNumber = 0, condition = undefined }) {
    if (!url && !urlRegex) throw new Error('Provide url or urlRegex for the breakpoint');
    if (!Number.isInteger(lineNumber) || lineNumber < 0) throw new Error('lineNumber must be a non-negative integer (0-based)');
    await this.enableDebugger();
    const params = { lineNumber, columnNumber: Number.isInteger(columnNumber) ? columnNumber : 0 };
    if (url) params.url = url;
    if (urlRegex) params.urlRegex = urlRegex;
    if (condition) params.condition = condition;
    const result = await this.send('Debugger.setBreakpointByUrl', params, 10_000);
    const record = {
      breakpointId: result.breakpointId,
      url,
      urlRegex,
      lineNumber,
      columnNumber: params.columnNumber,
      condition: condition ?? null,
      locations: result.locations ?? [],
      resolved: (result.locations ?? []).length > 0,
      createdAt: new Date().toISOString()
    };
    this.breakpoints.set(result.breakpointId, record);
    return record;
  }

  async removeBreakpoint(breakpointId) {
    await this.enableDebugger();
    await this.send('Debugger.removeBreakpoint', { breakpointId }, 8000);
    this.breakpoints.delete(breakpointId);
    return { removed: true, breakpointId };
  }

  listBreakpoints() {
    return { breakpoints: [...this.breakpoints.values()] };
  }

  async pause() {
    await this.enableDebugger();
    await this.send('Debugger.pause', {}, 8000);
    // Debugger.pause only takes effect at the next JavaScript statement. An
    // idle page needs a tiny evaluation to give Chrome that statement.
    this.send('Runtime.evaluate', { expression: 'void 0', returnByValue: true }, 15_000).catch(() => {});
    const paused = await this.waitFor(() => this.paused != null, 8000, 50);
    return { paused, state: this.paused, ...(paused ? {} : { reason: 'No JavaScript statement was available to pause' }) };
  }

  async resume() {
    if (!this.paused) return { resumed: false, reason: 'Debugger is not paused' };
    await this.send('Debugger.resume', {}, 8000);
    this.paused = null;
    return { resumed: true };
  }

  async debuggerStep(action) {
    await this.enableDebugger();
    if (!this.paused) return { action, stepped: false, reason: 'Debugger is not paused. Use action=pause first.' };
    const method = {
      step_over: 'Debugger.stepOver',
      step_into: 'Debugger.stepInto',
      step_out: 'Debugger.stepOut'
    }[action];
    if (!method) throw new Error('Unknown step action');
    await this.send(method, {}, 8000);
    await this.waitFor(() => this.paused != null, 8000, 100);
    return { action, stepped: true, state: this.paused };
  }

  async setPauseOnExceptions(state) {
    await this.enableDebugger();
    await this.send('Debugger.setPauseOnExceptions', { state }, 8000);
    return { state };
  }

  async evaluateOnCallFrame(callFrameId, expression) {
    if (!this.paused) throw new Error('Debugger is not paused');
    const raw = await this.send('Debugger.evaluateOnCallFrame', {
      callFrameId, expression, returnByValue: true, generatePreview: true, silent: false
    }, 10_000);
    return raw;
  }

  async scriptSource(scriptId, maxChars = 40_000) {
    await this.enableDebugger();
    const raw = await this.send('Debugger.getScriptSource', { scriptId }, 10_000);
    return { scriptId, source: redactText(raw.scriptSource ?? '', maxChars), truncated: String(raw.scriptSource ?? '').length > maxChars };
  }

  async traceStart({ categories = TRACE_DEFAULT_CATEGORIES, maxEvents = LIMITS.traceEvents, maxBytes = LIMITS.traceBytes } = {}) {
    if (this.trace) throw new Error('Tracing is already active. Stop it before starting another trace.');
    const trace = {
      startedAt: Date.now(),
      categories,
      events: [],
      bytes: 0,
      receivedEvents: 0,
      counts: {},
      truncated: false,
      maxEvents: Math.max(100, Math.min(300_000, maxEvents)),
      maxBytes: Math.max(100_000, Math.min(64_000_000, maxBytes)),
      completeResolve: null,
      completePromise: null
    };
    trace.completePromise = new Promise(resolve => { trace.completeResolve = resolve; });
    this.trace = trace;
    await this.send('Tracing.start', {
      categories: Array.isArray(categories) ? categories.join(',') : String(categories),
      transferMode: 'ReportEvents'
    }, 10_000);
    return { started: true, categories: trace.categories, startedAt: new Date(trace.startedAt).toISOString() };
  }

  async traceStop({ timeoutMs = 60_000 } = {}) {
    const trace = this.trace;
    if (!trace) throw new Error('No active trace. Call action trace_start first.');
    await this.send('Tracing.end', {}, 10_000);
    const finished = await Promise.race([
      trace.completePromise.then(() => true),
      sleep(timeoutMs).then(() => false)
    ]);
    this.trace = null;
    const durationMs = Date.now() - trace.startedAt;
    const topEvents = Object.entries(trace.counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 30)
      .map(([name, count]) => ({ name, count }));
    const summary = {
      finished,
      durationMs,
      categories: trace.categories,
      receivedEvents: trace.receivedEvents,
      storedEvents: trace.events.length,
      storedBytes: trace.bytes,
      truncated: trace.truncated,
      topEvents
    };
    this.lastTrace = { ...summary, events: trace.events };
    return summary;
  }

  traceStatus() {
    return this.trace ? {
      active: true,
      startedAt: new Date(this.trace.startedAt).toISOString(),
      categories: this.trace.categories,
      receivedEvents: this.trace.receivedEvents,
      storedEvents: this.trace.events.length,
      storedBytes: this.trace.bytes,
      truncated: this.trace.truncated
    } : { active: false, lastTrace: this.lastTrace ? {
      finished: this.lastTrace.finished,
      durationMs: this.lastTrace.durationMs,
      storedEvents: this.lastTrace.storedEvents,
      truncated: this.lastTrace.truncated
    } : null };
  }

  async profileStart({ samplingInterval = 1000 } = {}) {
    await this.send('Profiler.enable', {}, 8000);
    await this.send('Profiler.setSamplingInterval', { interval: Math.max(100, Math.min(100_000, samplingInterval)) }, 8000);
    await this.send('Profiler.start', {}, 8000);
    this.profileStartedAt = Date.now();
    return { started: true, samplingInterval };
  }

  async profileStop() {
    const { profile } = await this.send('Profiler.stop', {}, 20_000);
    const durationMs = this.profileStartedAt ? Date.now() - this.profileStartedAt : null;
    this.profileStartedAt = null;
    const nodes = profile.nodes ?? [];
    const samples = profile.samples ?? [];
    const deltas = profile.timeDeltas ?? [];
    const byId = new Map(nodes.map(node => [node.id, node]));
    const selfMicros = new Map();
    for (let i = 0; i < samples.length; i++) {
      const id = samples[i];
      const delta = deltas[i] ?? 0;
      selfMicros.set(id, (selfMicros.get(id) ?? 0) + delta);
    }
    const top = [...selfMicros.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 25)
      .map(([id, micros]) => {
        const node = byId.get(id)?.callFrame ?? {};
        return {
          functionName: node.functionName || '(anonymous)',
          url: redactUrl(node.url ?? ''),
          line: Number.isInteger(node.lineNumber) ? node.lineNumber + 1 : null,
          selfMs: Math.round(micros / 1000 * 100) / 100
        };
      });
    const size = estimateBytes(profile);
    this.lastProfile = size <= 16_000_000 ? profile : null;
    this.lastProfileSummary = {
      durationMs,
      samples: samples.length,
      nodes: nodes.length,
      startTime: profile.startTime,
      endTime: profile.endTime,
      stored: Boolean(this.lastProfile),
      bytes: size
    };
    return {
      summary: this.lastProfileSummary,
      topFunctions: top
    };
  }

  async setViewport({ width, height, deviceScaleFactor = 1, mobile = false, hasTouch = false, isLandscape = true } = {}) {
    if (!Number.isInteger(width) || !Number.isInteger(height)) throw new Error('width and height must be integers');
    await this.send('Emulation.setDeviceMetricsOverride', {
      width: Math.max(1, Math.min(10000, width)),
      height: Math.max(1, Math.min(10000, height)),
      deviceScaleFactor: Math.max(0.1, Math.min(10, Number(deviceScaleFactor) || 1)),
      mobile: Boolean(mobile),
      screenWidth: Math.max(1, Math.min(10000, width)),
      screenHeight: Math.max(1, Math.min(10000, height))
    }, 10000);
    await this.send('Emulation.setTouchEmulationEnabled', { enabled: Boolean(hasTouch || mobile), maxTouchPoints: (hasTouch || mobile) ? 5 : 0 }, 8000).catch(() => {});
    return { set: true, width, height, deviceScaleFactor, mobile, hasTouch, isLandscape };
  }

  async clearViewport() {
    await this.send('Emulation.clearDeviceMetricsOverride', {}, 8000).catch(() => {});
    await this.send('Emulation.setTouchEmulationEnabled', { enabled: false }, 8000).catch(() => {});
    return { cleared: true };
  }

  async setUserAgent(userAgent, { acceptLanguage, platform } = {}) {
    if (typeof userAgent !== 'string' || !userAgent.trim()) throw new Error('userAgent is required');
    const params = { userAgent: userAgent.slice(0, 2000) };
    if (acceptLanguage) params.acceptLanguage = String(acceptLanguage).slice(0, 200);
    if (platform) params.platform = String(platform).slice(0, 200);
    await this.send('Network.setUserAgentOverride', params, 8000);
    return { set: true, userAgent: params.userAgent, acceptLanguage: params.acceptLanguage, platform: params.platform };
  }

  async setGeolocation({ latitude, longitude, accuracy = 1 } = {}) {
    await this.send('Emulation.setGeolocationOverride', {
      latitude: Number(latitude),
      longitude: Number(longitude),
      accuracy: Math.max(0, Number(accuracy) || 1)
    }, 8000);
    return { set: true, latitude: Number(latitude), longitude: Number(longitude), accuracy: Math.max(0, Number(accuracy) || 1) };
  }

  async clearGeolocation() {
    await this.send('Emulation.clearGeolocationOverride', {}, 8000).catch(() => {});
    return { cleared: true };
  }

  async setTimezone(timezoneId) {
    await this.send('Emulation.setTimezoneOverride', { timezoneId: String(timezoneId) }, 8000);
    return { set: true, timezoneId: String(timezoneId) };
  }

  async setLocale(locale) {
    await this.send('Emulation.setLocaleOverride', { locale: String(locale) }, 8000).catch(() => {});
    return { set: true, locale: String(locale) };
  }

  async emulateMedia({ media, colorScheme, reducedMotion, forcedColors } = {}) {
    const features = [];
    if (colorScheme) features.push({ name: 'prefers-color-scheme', value: String(colorScheme) });
    if (reducedMotion) features.push({ name: 'prefers-reduced-motion', value: String(reducedMotion) });
    if (forcedColors) features.push({ name: 'forced-colors', value: String(forcedColors) });
    await this.send('Emulation.setEmulatedMedia', {
      media: media ? String(media) : '',
      features
    }, 8000);
    return { set: true, media: media || null, features };
  }

  async emulateNetwork({ offline = false, latency = 0, downloadThroughput = -1, uploadThroughput = -1, connectionType = 'none' } = {}) {
    await this.send('Network.emulateNetworkConditions', {
      offline: Boolean(offline),
      latency: Math.max(0, Number(latency) || 0),
      downloadThroughput: Number(downloadThroughput),
      uploadThroughput: Number(uploadThroughput),
      connectionType: String(connectionType || 'none')
    }, 8000);
    return { set: true, offline: Boolean(offline), latency: Math.max(0, Number(latency) || 0), downloadThroughput: Number(downloadThroughput), uploadThroughput: Number(uploadThroughput), connectionType };
  }

  async setCacheDisabled(cacheDisabled = true) {
    await this.send('Network.setCacheDisabled', { cacheDisabled: Boolean(cacheDisabled) }, 8000);
    return { cacheDisabled: Boolean(cacheDisabled) };
  }

  async setExtraHTTPHeaders(headers = {}) {
    if (headers == null || typeof headers !== 'object' || Array.isArray(headers)) throw new Error('headers must be an object');
    const safe = {};
    for (const [k, v] of Object.entries(headers).slice(0, 50)) safe[String(k)] = String(v);
    await this.send('Network.setExtraHTTPHeaders', { headers: safe }, 8000);
    return { set: true, headers: redactHeaders(safe), count: Object.keys(safe).length };
  }

  async setBlockedURLs(urls = []) {
    if (!Array.isArray(urls)) throw new Error('urls must be an array');
    const clean = urls.slice(0, 200).map(u => String(u));
    await this.send('Network.setBlockedURLs', { urls: clean }, 8000);
    return { set: true, urls: clean };
  }

  async enableFetchInterception({ patterns = ['*'], handleAuth = false } = {}) {
    this.fetchInterception = this.fetchInterception || { enabled: false, rules: [], handleAuth: Boolean(handleAuth) };
    this.fetchInterception.enabled = true;
    this.fetchInterception.handleAuth = Boolean(handleAuth);
    await this.send('Fetch.enable', {
      patterns: (Array.isArray(patterns) ? patterns : [patterns]).map(p => (typeof p === 'string' ? { urlPattern: p, requestStage: 'Request' } : p)),
      handleAuthRequests: Boolean(handleAuth)
    }, 10000);
    return { enabled: true, patterns, handleAuth: Boolean(handleAuth), rules: this.fetchInterception.rules.length };
  }

  async disableFetchInterception() {
    this.fetchInterception = { enabled: false, rules: [], handleAuth: false };
    await this.send('Fetch.disable', {}, 8000).catch(() => {});
    return { enabled: false };
  }

  addFetchRule(rule) {
    this.fetchInterception = this.fetchInterception || { enabled: false, rules: [], handleAuth: false };
    const normalized = {
      id: `rule-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      urlPattern: rule.urlPattern ? String(rule.urlPattern) : '*',
      method: rule.method ? String(rule.method).toUpperCase() : null,
      action: rule.action || 'continue', // continue|block|mock
      status: Number.isInteger(rule.status) ? rule.status : 200,
      headers: rule.headers && typeof rule.headers === 'object' ? rule.headers : null,
      body: rule.body != null ? String(rule.body) : null,
      once: rule.once === true
    };
    this.fetchInterception.rules.push(normalized);
    return normalized;
  }

  clearFetchRules() {
    this.fetchInterception = this.fetchInterception || { enabled: false, rules: [], handleAuth: false };
    this.fetchInterception.rules = [];
    return { cleared: true };
  }

  listFetchRules() {
    this.fetchInterception = this.fetchInterception || { enabled: false, rules: [], handleAuth: false };
    return { enabled: this.fetchInterception.enabled, rules: this.fetchInterception.rules };
  }

  _matchFetchRule(event) {
    const rules = this.fetchInterception?.rules ?? [];
    const url = event.request?.url || '';
    const method = event.request?.method || '';
    for (let i = 0; i < rules.length; i++) {
      const r = rules[i];
      if (r.method && r.method !== method) continue;
      const pattern = r.urlPattern === '*' ? '' : r.urlPattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\*/g, '.*');
      if (!pattern || new RegExp(pattern).test(url)) {
        if (r.once) rules.splice(i, 1);
        return r;
      }
    }
    return null;
  }

  async clearBrowserCache() {
    await this.send('Network.clearBrowserCache', {}, 10000);
    return { cleared: true };
  }

  async accessibilitySnapshot({ interestingOnly = true, root = null } = {}) {
    await this.send('Accessibility.enable', {}, 8000).catch(() => {});
    const params = { interestingOnly: Boolean(interestingOnly) };
    const raw = await this.send('Accessibility.getFullAXTree', params, 20000).catch(async () => {
      // fallback to partial snapshot
      return await this.send('Accessibility.getPartialAXTree', { interestingOnly: Boolean(interestingOnly) }, 20000);
    });
    const nodes = (raw.nodes ?? []).slice(0, 2000).map(node => ({
      nodeId: node.nodeId,
      role: node.role?.value,
      name: node.name?.value,
      value: node.value?.value,
      description: node.description?.value,
      ignored: node.ignored,
      childIds: node.childIds?.slice(0, 50),
      backendDOMNodeId: node.backendDOMNodeId
    }));
    return { total: raw.nodes?.length ?? 0, nodes, interestingOnly: Boolean(interestingOnly) };
  }

  async printToPDF({ landscape = false, printBackground = true, scale = 1, paperWidth, paperHeight } = {}) {
    const params = {
      landscape: Boolean(landscape),
      printBackground: Boolean(printBackground),
      scale: Math.max(0.1, Math.min(2, Number(scale) || 1))
    };
    if (Number.isFinite(paperWidth)) params.paperWidth = paperWidth;
    if (Number.isFinite(paperHeight)) params.paperHeight = paperHeight;
    const raw = await this.send('Page.printToPDF', params, 30000);
    return { data: raw.data, bytes: Buffer.from(raw.data, 'base64').length };
  }

  async uploadFile(selector, files) {
    if (!selector || typeof selector !== 'string') throw new Error('selector is required');
    const paths = Array.isArray(files) ? files : [files];
    if (!paths.length) throw new Error('files is required');
    const { root } = await this.send('DOM.getDocument', { depth: 0 }, 8000);
    const node = await this.send('DOM.querySelector', { nodeId: root.nodeId, selector }, 8000);
    if (!node?.nodeId) throw new Error(`Selector not found: ${selector}`);
    await this.send('DOM.setFileInputFiles', {
      files: paths.map(f => String(f)),
      nodeId: node.nodeId
    }, 10000);
    return { uploaded: true, selector, files: paths.map(f => String(f)), count: paths.length };
  }

  async hover(selector, { timeoutMs = 10000 } = {}) {
    await this.ensureCaptureEnabled();
    const { rect, locator } = await this._resolveLocator(selector, { timeoutMs, visible: true });
    const x = Math.round(rect.x), y = Math.round(rect.y);
    await this.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x, y }, 5000);
    return { hovered: true, locator, selector: typeof selector === 'string' ? selector : undefined, x, y, ...(await this.pageInfo()) };
  }

  async dblclick(selector, { timeoutMs = 10000, settleMs = 250 } = {}) {
    return await this.click(selector, { timeoutMs, settleMs, clickCount: 2 });
  }

  async focus(selector, { timeoutMs = 10000 } = {}) {
    await this.ensureCaptureEnabled();
    const { nodeExpr, locator } = await this._resolveLocator(selector, { timeoutMs, visible: false });
    await this.evaluateValue(`(() => { const el = ${nodeExpr}; el?.focus?.(); return true; })()`, { timeoutMs: 5000 });
    return { focused: true, locator, selector: typeof selector === 'string' ? selector : undefined, ...(await this.pageInfo()) };
  }

  async dragAndDrop(source, target, { timeoutMs = 10000, steps = 12 } = {}) {
    await this.ensureCaptureEnabled();
    const src = await this._resolveLocator(source, { timeoutMs, visible: true });
    const dst = await this._resolveLocator(target, { timeoutMs, visible: true });
    const sx = Math.round(src.rect.x), sy = Math.round(src.rect.y);
    const tx = Math.round(dst.rect.x), ty = Math.round(dst.rect.y);
    await this.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: sx, y: sy });
    await this.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: sx, y: sy, button: 'left', clickCount: 1 });
    for (let i = 1; i <= steps; i++) {
      const x = Math.round(sx + (tx - sx) * i / steps);
      const y = Math.round(sy + (ty - sy) * i / steps);
      await this.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x, y, button: 'left' });
      await sleep(16);
    }
    await this.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: tx, y: ty, button: 'left', clickCount: 1 });
    return { dragged: true, source: src.locator, target: dst.locator, from: { x: sx, y: sy }, to: { x: tx, y: ty }, ...(await this.pageInfo()) };
  }

  async selectOption(selector, values = []) {
    await this.ensureCaptureEnabled();
    const vals = Array.isArray(values) ? values : [values];
    const expression = `(() => {
      const el = document.querySelector(${JSON.stringify(selector)});
      if (!el) return { found: false };
      const wanted = new Set(${JSON.stringify(vals.map(String))});
      let matched = [];
      for (const opt of el.options ?? []) {
        const should = wanted.has(opt.value) || wanted.has(opt.text) || wanted.has(opt.label);
        if (el.multiple) opt.selected = should;
        else if (should && matched.length === 0) opt.selected = true;
        else if (!el.multiple) opt.selected = false;
        if (opt.selected) matched.push({ value: opt.value, text: opt.text, label: opt.label });
      }
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
      return { found: true, matched, value: el.value, selectedIndex: el.selectedIndex };
    })()`;
    const result = await this.evaluateValue(expression);
    if (!result.found) throw new Error(`Selector not found: ${selector}`);
    return { selected: true, selector, ...result };
  }

  async close() {
    const socket = this.socket;
    this.socket = null;
    this.tab = null;
    this.paused = null;
    this.captureReadiness.networkEnabled = false;
    this.captureReadiness.runtimeEnabled = false;
    this.captureReadiness.pageEnabled = false;
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error('Chrome session closed'));
    }
    this.pending.clear();
    if (socket && socket.readyState !== WebSocket.CLOSED) socket.close();
  }
}

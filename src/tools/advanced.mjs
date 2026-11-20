import { assertPermission, redactJsonish, redactText } from '../security.mjs';
import { writeExportFile } from '../export.mjs';
import { enumStr, flag, num, result, shape, str, tabIdSchema } from './registry.mjs';

const DESTRUCTIVE_CDP = /^(?:Browser\.(?:close|crash|crashGpuProcess|resetPermissions)|Target\.(?:closeTarget|disposeBrowserContext|attachToBrowserTarget)|Page\.(?:close|crash)|Storage\.clearDataForOrigin|Network\.clearBrowserCookies|Network\.clearBrowserCache)$/;
const SENSITIVE_CDP = /^(?:Network\.(?:getAllCookies|getCookies|setCookie|deleteCookies)|Storage\.(?:getCookies|setCookies)|DOMStorage\.)/;

function slowThreshold(value, fallback = 1500) {
  return Number.isInteger(value) ? Math.max(1, Math.min(120_000, value)) : fallback;
}

export function registerAdvancedTools(registry) {
  const { add } = registry;

  add(
    'devtools_cdp',
    'Advanced raw CDP method. Requires full-debug permission. Destructive browser-process commands are blocked; cookie APIs require the sensitive-data gate.',
    shape({
      tabId: tabIdSchema,
      method: str('CDP domain.method, e.g. Page.getNavigationHistory'),
      params: { type: 'object', description: 'Method parameters', additionalProperties: true },
      confirmSensitive: flag('Confirm sensitive CDP data access (requires DEVTOOLS_ALLOW_SENSITIVE=1)'),
      timeoutMs: num('Timeout in ms (100-60000)', { minimum: 100, maximum: 60_000 })
    }, ['method']),
    'full-debug',
    async ({ tabId, method, params = {}, confirmSensitive = false, timeoutMs = 15_000 }, ctx) => {
      if (typeof method !== 'string' || !/^[A-Za-z]+\.[A-Za-z]+$/.test(method)) throw new Error('Invalid CDP method');
      if (DESTRUCTIVE_CDP.test(method)) throw new Error('Blocked destructive CDP command. Use the dedicated tab/storage tools instead.');
      if (params == null || typeof params !== 'object' || Array.isArray(params)) throw new Error('params must be an object');
      if (JSON.stringify(params).length > 200_000) throw new Error('CDP params are too large');
      const sensitive = SENSITIVE_CDP.test(method) ? ctx.sensitive(confirmSensitive) : false;
      const session = await ctx.session(tabId);
      const raw = await session.send(method, params, Math.max(100, Math.min(60_000, timeoutMs)));
      return {
        sessionId: session.tab?.id,
        method,
        result: redactJsonish(raw, { includeSensitive: sensitive })
      };
    }
  );

  add(
    'devtools_debugger',
    'JavaScript debugger: scripts, breakpoints, pause/resume/step, call stack and paused-frame evaluation. Requires full-debug permission.',
    shape({
      tabId: tabIdSchema,
      action: enumStr('Debugger action', [
        'enable', 'scripts', 'set_breakpoint', 'remove_breakpoint', 'list_breakpoints',
        'pause', 'resume', 'step_over', 'step_into', 'step_out', 'state',
        'evaluate', 'set_pause_on_exceptions', 'source'
      ], { default: 'state' }),
      contains: str('Filter script URL'),
      limit: num('Script list limit (1-500)', { minimum: 1, maximum: 500 }),
      url: str('Breakpoint URL (exact)'),
      urlRegex: str('Breakpoint URL regex'),
      lineNumber: num('0-based source line for breakpoints', { minimum: 0, maximum: 10_000_000 }),
      columnNumber: num('0-based source column', { minimum: 0, maximum: 1_000_000 }),
      condition: str('Conditional breakpoint expression'),
      breakpointId: str('Breakpoint ID'),
      callFrameId: str('Paused call frame ID'),
      expression: str('Expression to evaluate on the paused frame', { maxLength: 6000 }),
      state: enumStr('Pause-on-exceptions state', ['none', 'uncaught', 'all']),
      scriptId: str('Debugger script ID'),
      maxChars: num('Source/eval result limit (100-200000)', { minimum: 100, maximum: 200_000 })
    }, ['action']),
    'full-debug',
    async (args, ctx) => {
      const session = await ctx.session(args.tabId);
      switch (args.action) {
        case 'enable': {
          await session.enableDebugger();
          return { sessionId: session.tab?.id, enabled: true, scripts: session.scripts.size };
        }
        case 'scripts':
          return { sessionId: session.tab?.id, ...(await session.debuggerScripts({ contains: args.contains, limit: args.limit ?? 100 })) };
        case 'set_breakpoint':
          return { sessionId: session.tab?.id, ...(await session.setBreakpoint({
            url: args.url, urlRegex: args.urlRegex, lineNumber: args.lineNumber,
            columnNumber: args.columnNumber ?? 0, condition: args.condition
          })) };
        case 'remove_breakpoint':
          if (!args.breakpointId) throw new Error('breakpointId is required');
          return { sessionId: session.tab?.id, ...(await session.removeBreakpoint(args.breakpointId)) };
        case 'list_breakpoints':
          return { sessionId: session.tab?.id, ...session.listBreakpoints() };
        case 'pause':
          return { sessionId: session.tab?.id, ...(await session.pause()) };
        case 'resume':
          return { sessionId: session.tab?.id, ...(await session.resume()) };
        case 'step_over':
        case 'step_into':
        case 'step_out':
          return { sessionId: session.tab?.id, ...(await session.debuggerStep(args.action)) };
        case 'state':
          return { sessionId: session.tab?.id, paused: session.paused != null, state: session.paused, breakpoints: [...session.breakpoints.values()] };
        case 'evaluate': {
          if (!args.callFrameId) throw new Error('callFrameId is required');
          if (!args.expression) throw new Error('expression is required');
          const raw = await session.evaluateOnCallFrame(args.callFrameId, args.expression);
          return {
            sessionId: session.tab?.id,
            result: redactJsonish(raw.result?.value ?? raw.result?.description ?? null),
            type: raw.result?.type,
            exception: raw.exceptionDetails ? redactText(raw.exceptionDetails.exception?.description ?? raw.exceptionDetails.text, 4000) : null
          };
        }
        case 'set_pause_on_exceptions':
          return { sessionId: session.tab?.id, ...(await session.setPauseOnExceptions(args.state ?? 'none')) };
        case 'source':
          if (!args.scriptId) throw new Error('scriptId is required');
          return { sessionId: session.tab?.id, ...(await session.scriptSource(args.scriptId, args.maxChars ?? 40_000)) };
        default:
          throw new Error('Unknown debugger action');
      }
    }
  );

  add(
    'devtools_performance',
    'Performance metrics, Chrome tracing and CPU profiling. Use action=metrics for lightweight read-only metrics; trace/profile require full-debug.',
    shape({
      tabId: tabIdSchema,
      action: enumStr('Performance action', ['metrics', 'trace_start', 'trace_stop', 'trace_status', 'profile_start', 'profile_stop'], { default: 'metrics' }),
      categories: str('Comma-separated tracing categories'),
      maxEvents: num('Maximum stored trace events (100-300000)', { minimum: 100, maximum: 300_000 }),
      maxBytes: num('Maximum trace bytes (100000-64000000)', { minimum: 100_000, maximum: 64_000_000 }),
      samplingInterval: num('CPU sampling interval in microseconds (100-100000)', { minimum: 100, maximum: 100_000 }),
      timeoutMs: num('Trace stop timeout in ms (1000-120000)', { minimum: 1000, maximum: 120_000 })
    }),
    'read-only',
    async ({ tabId, action = 'metrics', categories, maxEvents, maxBytes, samplingInterval, timeoutMs }, ctx) => {
      const session = await ctx.session(tabId);
      if (action === 'metrics') {
        return { sessionId: session.tab?.id, action, metrics: await session.performanceMetrics() };
      }
      assertPermission(ctx.permission, 'full-debug', `Performance action ${action}`);
      if (action === 'trace_start') {
        return { sessionId: session.tab?.id, action, ...(await session.traceStart({
          categories: categories ?? undefined,
          maxEvents: maxEvents ?? undefined,
          maxBytes: maxBytes ?? undefined
        })) };
      }
      if (action === 'trace_stop') {
        return { sessionId: session.tab?.id, action, ...(await session.traceStop({ timeoutMs: timeoutMs ?? 60_000 })) };
      }
      if (action === 'trace_status') {
        return { sessionId: session.tab?.id, action, ...session.traceStatus() };
      }
      if (action === 'profile_start') {
        return { sessionId: session.tab?.id, action, ...(await session.profileStart({ samplingInterval: samplingInterval ?? 1000 })) };
      }
      if (action === 'profile_stop') {
        return { sessionId: session.tab?.id, action, ...(await session.profileStop()) };
      }
      throw new Error('Unknown performance action');
    }
  );

  add(
    'devtools_storage',
    'Cookies and localStorage/sessionStorage inspection and mutation. Values are redacted by default; raw export requires full-debug + DEVTOOLS_ALLOW_SENSITIVE=1 + includeSensitive=true.',
    shape({
      tabId: tabIdSchema,
      scope: enumStr('Storage scope', ['cookies', 'local', 'session'], { default: 'cookies' }),
      action: enumStr('Storage action', ['list', 'set', 'remove', 'clear'], { default: 'list' }),
      urls: { type: 'array', description: 'Cookie URL filters', items: { type: 'string', maxLength: 2000 }, maxItems: 20 },
      key: str('Storage key or cookie name', { maxLength: 1000 }),
      value: str('Storage/cookie value', { maxLength: 100_000 }),
      url: str('Cookie URL for set/remove'),
      domain: str('Cookie domain'),
      path: str('Cookie path'),
      secure: flag('Cookie Secure attribute'),
      httpOnly: flag('Cookie HttpOnly attribute'),
      sameSite: enumStr('Cookie SameSite', ['Strict', 'Lax', 'None']),
      expires: { type: 'number', description: 'Cookie expiry as Unix seconds' },
      limit: num('Maximum rows (1-1000)', { minimum: 1, maximum: 1000 }),
      includeSensitive: flag('Return raw values (requires full-debug + DEVTOOLS_ALLOW_SENSITIVE=1)'),
      confirm: flag('Required for destructive clear operations')
    }),
    'interactive',
    async (args, ctx) => {
      const session = await ctx.session(args.tabId);
      const limit = args.limit ?? 200;
      const sensitive = ctx.sensitive(args.includeSensitive === true);
      const action = args.action ?? 'list';
      const scope = args.scope ?? 'cookies';
      if (scope === 'cookies') {
        if (action === 'list') {
          let cookieUrls = args.urls ?? null;
          if (!cookieUrls?.length) {
            const page = await session.pageInfo();
            if (!/^https?:/i.test(page.url ?? '')) {
              return { sessionId: session.tab?.id, scope, total: 0, cookies: [], note: 'Current tab is not on an HTTP(S) page.' };
            }
            cookieUrls = [page.url];
          }
          const cookies = await session.cookies(cookieUrls);
          return {
            sessionId: session.tab?.id,
            scope,
            origin: cookieUrls,
            total: cookies.length,
            cookies: cookies.slice(0, Math.max(1, Math.min(1000, limit))).map(cookie => ({
              name: cookie.name,
              value: sensitive ? cookie.value : '[REDACTED]',
              valueLength: cookie.value?.length ?? 0,
              domain: cookie.domain,
              path: cookie.path,
              expires: cookie.expires,
              httpOnly: cookie.httpOnly,
              secure: cookie.secure,
              sameSite: cookie.sameSite,
              session: cookie.session,
              size: cookie.size,
              priority: cookie.priority
            }))
          };
        }
        assertPermission(ctx.permission, 'full-debug', 'Cookie mutation');
        if (action === 'set') {
          if (!args.key) throw new Error('key (cookie name) is required');
          if (!args.value && args.value !== '') throw new Error('value is required');
          if (!args.url && !args.domain) throw new Error('url or domain is required');
          const params = {
            name: args.key,
            value: args.value,
            path: args.path ?? '/',
            secure: args.secure === true,
            httpOnly: args.httpOnly === true,
            sameSite: args.sameSite
          };
          if (args.url) params.url = args.url;
          if (args.domain) params.domain = args.domain;
          if (args.expires != null) params.expires = args.expires;
          const response = await session.setCookie(params);
          return { sessionId: session.tab?.id, scope, action, set: response.success === true, cookie: { name: args.key, domain: args.domain, path: params.path } };
        }
        if (action === 'remove') {
          if (!args.key) throw new Error('key (cookie name) is required');
          const params = { name: args.key };
          if (args.url) params.url = args.url;
          if (args.domain) params.domain = args.domain;
          if (args.path) params.path = args.path;
          await session.send('Network.deleteCookies', params, 10_000);
          return { sessionId: session.tab?.id, scope, action, removed: true, name: args.key };
        }
        if (action === 'clear') {
          if (args.confirm !== true) throw new Error('Set confirm=true to clear all browser cookies');
          return { sessionId: session.tab?.id, scope, action, ...(await session.clearCookies()) };
        }
        throw new Error('Unknown cookie action');
      }
      const type = scope === 'session' ? 'session' : 'local';
      if (action === 'list') {
        const snapshot = await session.storage(type, limit);
        return {
          sessionId: session.tab?.id,
          scope,
          ...snapshot,
          entries: (snapshot.entries ?? []).map(entry => ({
            key: entry.key,
            value: sensitive ? entry.value : '[REDACTED]',
            valueLength: entry.value?.length ?? 0
          }))
        };
      }
      assertPermission(ctx.permission, 'full-debug', 'Browser storage mutation');
      if (action === 'set') {
        if (!args.key) throw new Error('key is required');
        if (args.value == null) throw new Error('value is required');
        return { sessionId: session.tab?.id, scope, ...(await session.setStorageItem(type, args.key, args.value)) };
      }
      if (action === 'remove') {
        if (!args.key) throw new Error('key is required');
        return { sessionId: session.tab?.id, scope, ...(await session.removeStorageItem(type, args.key)) };
      }
      if (action === 'clear') {
        if (args.confirm !== true) throw new Error('Set confirm=true to clear browser storage');
        return { sessionId: session.tab?.id, scope, ...(await session.clearStorage(type)) };
      }
      throw new Error('Unknown storage action');
    }
  );

  add(
    'devtools_capture',
    'Start, stop or inspect a continuous capture window. Events are always buffered after attach; this marks a start sequence and returns a bounded summary on stop.',
    shape({
      tabId: tabIdSchema,
      action: enumStr('Capture action', ['start', 'stop', 'status'], { default: 'status' }),
      clear: flag('Clear existing capture buffers when starting'),
      slowMs: num('Slow-request threshold on stop (1-120000)', { minimum: 1, maximum: 120_000 })
    }),
    'interactive',
    async ({ tabId, action = 'status', clear = false, slowMs = 1500 }, ctx) => {
      const session = await ctx.session(tabId);
      if (action === 'start') {
        if (clear) session.clearAll();
        session.captureWindow = {
          startedAt: new Date().toISOString(),
          startSequence: session.seq,
          requestsAtStart: session.requests.size,
          consoleAtStart: session.console.items.length
        };
        return { sessionId: session.tab?.id, started: true, captureWindow: session.captureWindow, capture: session.status() };
      }
      if (action === 'status') {
        return {
          sessionId: session.tab?.id,
          active: Boolean(session.captureWindow),
          captureWindow: session.captureWindow ?? null,
          capture: session.status()
        };
      }
      assertPermission(ctx.permission, 'interactive', 'Stopping capture');
      const window = session.captureWindow ?? { startedAt: null, startSequence: 0 };
      const after = window.startSequence ?? 0;
      const requests = [...session.requests.values()].filter(req => req.sequence > after);
      const consoleEntries = session.console.items.filter(entry => entry.sequence > after);
      const failures = requests.filter(req => req.failed || (req.status ?? 0) >= 400);
      const slow = requests.filter(req => (req.durationMs ?? 0) >= slowThreshold(slowMs));
      const errors = consoleEntries.filter(entry => entry.level === 'error' || entry.category === 'exception');
      const summary = {
        startedAt: window.startedAt,
        stoppedAt: new Date().toISOString(),
        durationMs: window.startedAt ? Date.now() - Date.parse(window.startedAt) : null,
        consoleEntries: consoleEntries.length,
        consoleErrors: errors.length,
        requests: requests.length,
        failedRequests: failures.length,
        slowRequests: slow.length,
        websocketFrames: session.frames.items.filter(frame => frame.sequence > after).length,
        pendingRequests: session.pendingRequestCount()
      };
      session.captureWindow = null;
      return {
        sessionId: session.tab?.id,
        stopped: true,
        summary,
        errors: errors.slice(-20),
        failedRequests: failures.slice(-20).map(req => ({ id: req.id, url: req.url, method: req.method, status: req.status, error: req.errorText, corsError: req.corsError })),
        slowRequests: slow.slice(-10).map(req => ({ id: req.id, url: req.url, durationMs: req.durationMs }))
      };
    }
  );

  add(
    'devtools_export',
    'Export captured data to a JSON/HAR/error report/trace/CPU profile file. Files stay inside DEVTOOLS_EXPORT_DIR unless an in-directory path is supplied.',
    shape({
      tabId: tabIdSchema,
      format: enumStr('Export format', ['json', 'har', 'report', 'trace', 'profile'], { default: 'report' }),
      path: str('Optional file name or path inside DEVTOOLS_EXPORT_DIR'),
      includeBodies: flag('Include response bodies in HAR/JSON'),
      includeSensitive: flag('Include raw headers/URLs (requires full-debug + DEVTOOLS_ALLOW_SENSITIVE=1)'),
      maxBodies: num('Maximum HAR bodies to fetch (0-500)', { minimum: 0, maximum: 500 })
    }),
    'read-only',
    async ({ tabId, format = 'report', path, includeBodies = false, includeSensitive = false, maxBodies = 100 }, ctx) => {
      const session = await ctx.session(tabId);
      const sensitive = ctx.sensitive(includeSensitive);
      const output = await writeExportFile({
        session,
        format,
        includeBodies,
        includeSensitive: sensitive,
        path: path ?? null,
        exportDir: ctx.manager.exportDir
      });
      return result({ sessionId: session.tab?.id, ...output, exportDir: ctx.manager.exportDir });
    }
  );
}

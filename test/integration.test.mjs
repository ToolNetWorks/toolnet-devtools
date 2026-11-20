import { test } from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createFixtureServer } from './fixtures/server.mjs';
import { McpClient } from './helpers/mcp-client.mjs';

const MAIN_ENDPOINT = 'http://127.0.0.1:9222';
const AUTO_ENDPOINT = 'http://127.0.0.1:9333';

async function reachable(endpoint, timeoutMs = 2500) {
  try {
    const res = await fetch(`${endpoint}/json/version`, { signal: AbortSignal.timeout(timeoutMs) });
    return res.ok;
  } catch {
    return false;
  }
}

async function waitFor(predicate, timeoutMs = 10_000, intervalMs = 100) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return true;
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  }
  return false;
}

const chromeReady = await reachable(MAIN_ENDPOINT);
const autoPortFree = !(await reachable(AUTO_ENDPOINT));

test('real Chromium 127.0.0.1:9222 end-to-end F12 workflow', { timeout: 180_000 }, async t => {
  if (!chromeReady) {
    t.skip(`Chrome is not reachable at ${MAIN_ENDPOINT}; start Chromium with --remote-debugging-port=9222`);
    return;
  }
  const fixture = await createFixtureServer();
  const exportDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'toolnet-integration-'));
  const client = new McpClient({
    env: {
      CDP_ENDPOINT: MAIN_ENDPOINT,
      DEVTOOLS_PERMISSION: 'full-debug',
      DEVTOOLS_ALLOW_SENSITIVE: '1',
      DEVTOOLS_AUTO_LAUNCH: '0',
      DEVTOOLS_EXPORT_DIR: exportDir
    }
  });
  const opened = new Set();
  const closed = new Set();

  async function open(url, options = {}) {
    const result = await client.call('devtools_open_url', {
      url,
      waitUntil: 'networkidle2',
      timeoutMs: 20_000,
      settleMs: 500,
      ...options
    });
    opened.add(result.sessionId);
    return result;
  }

  async function closeTab(tabId) {
    if (!tabId || closed.has(tabId)) return;
    closed.add(tabId);
    await client.call('devtools_close_tab', { tabId }).catch(() => {});
  }

  try {
    await t.test('initialize and list a compact universal tool set', async () => {
      const init = await client.initialize();
      assert.equal(init.serverInfo.name, 'toolnet-devtools-mcp');
      assert.equal(init.protocolVersion, '2025-11-25');
      const list = await client.request('tools/list', {});
      assert.ok(list.tools.length >= 30, `expected >=30 tools, got ${list.tools.length}`);
      const names = list.tools.map(tool => tool.name);
      for (const required of [
        'devtools_navigate_and_capture', 'devtools_open_url', 'devtools_console', 'devtools_network',
        'devtools_debugger', 'devtools_performance', 'devtools_storage', 'devtools_export'
      ]) {
        assert.ok(names.includes(required), `missing ${required}`);
      }
    });

    const home = await open(fixture.origin + '/');
    const tab = home.sessionId;
    assert.ok(tab, 'open_url must return a sessionId');

    await t.test('navigate_and_capture proves Network is enabled before navigation and captures from the first byte', async () => {
      assert.equal(home.navigation.title, 'Fixture Home');
      assert.equal(home.navigation.timedOut, false);
      assert.equal(home.verified.networkEnabledBeforeNavigation, true, 'Network must be enabled before navigation');
      assert.equal(home.verified.runtimeEnabledBeforeNavigation, true);
      assert.equal(home.verified.pageEnabledBeforeNavigation, true);
      assert.ok(home.captureReadiness.networkEnabledAt, 'network enable timestamp must exist');
      assert.ok(home.navigation.navigationStartedAt, 'navigation start timestamp must exist');
      assert.ok(
        Date.parse(home.captureReadiness.networkEnabledAt) <= Date.parse(home.navigation.navigationStartedAt),
        'Network.enable must happen before Page.navigate'
      );
      assert.equal(home.navigation.networkEnabledBeforeNavigation, true);
      assert.ok(home.capture.requests >= 3, 'initial document/API requests were captured');
      await waitFor(async () => {
        const result = await client.call('devtools_console', { tabId: tab, limit: 100 });
        return result.entries.some(entry => entry.category === 'exception');
      }, 5000, 150);
      const consoleResult = await client.call('devtools_console', { tabId: tab, limit: 100 });
      const levels = new Set(consoleResult.entries.map(entry => entry.level));
      assert.ok(levels.has('log'));
      assert.ok(levels.has('warning'));
      assert.ok(levels.has('error'));
      const exception = consoleResult.entries.find(entry => entry.category === 'exception');
      assert.ok(exception, 'uncaught exception should be captured');
      assert.match(exception.text, /fixture-uncaught/);
      assert.match(exception.timestampIso, /^2026-/);
      assert.ok(exception.stackTrace.length >= 1);

      const network = await client.call('devtools_network', { tabId: tab, limit: 100, includeBodies: true });
      const documentRequest = network.requests.find(req => req.type === 'Document');
      assert.ok(documentRequest, 'document request captured');
      assert.ok(documentRequest.bytes > 0, 'document response size captured');
      const api = network.requests.find(req => req.url.endsWith('/api/data'));
      assert.ok(api, 'API request captured');
      assert.equal(api.status, 200);
      assert.ok(api.bytes > 0);
      assert.match(api.body.body, /"ok":true/);
      assert.doesNotMatch(api.body.body, /supersecret/);
      const echo = network.requests.find(req => req.url.endsWith('/api/echo'));
      assert.equal(echo.method, 'POST');

      const body = await client.call('devtools_request_body', { tabId: tab, requestId: echo.id });
      assert.match(body.body, /"hello":"world"/);
      assert.doesNotMatch(body.body, /post-secret/);
      const rawBody = await client.call('devtools_request_body', { tabId: tab, requestId: echo.id, includeSensitive: true });
      assert.match(rawBody.body, /post-secret/);
      const response = await client.call('devtools_response_body', { tabId: tab, requestId: api.id });
      assert.match(response.body, /"ok":true/);
      assert.doesNotMatch(response.body, /supersecret/);
      const rawResponse = await client.call('devtools_response_body', { tabId: tab, requestId: api.id, includeSensitive: true });
      assert.match(rawResponse.body, /supersecret/);

      const search = await client.call('devtools_network_search', { tabId: tab, query: 'api/data' });
      assert.ok(search.totalMatches >= 2);

      const ws = await client.call('devtools_websocket', { tabId: tab, limit: 50 });
      assert.ok(ws.connections.length >= 1);
      assert.equal(ws.connections[0].status, 'open');
      const payloads = ws.frames.map(frame => frame.payload).join('\n');
      assert.match(payloads, /server-hello/);
      assert.match(payloads, /client-hello/);
      assert.match(payloads, /echo:client-hello/);
    });

    await t.test('DOM/CSS, click, type, scroll and screenshot work without manual Chrome interaction', async () => {
      const dom = await client.call('devtools_dom_inspect', { tabId: tab, selector: '#result' });
      assert.equal(dom.found, true);
      assert.equal(dom.text, 'api:true');
      assert.ok(dom.computedStyles.length > 10);
      const query = await client.call('devtools_dom_query', { tabId: tab, selector: 'input, button, a', limit: 10 });
      assert.ok(query.total >= 3);

      const click = await client.call('devtools_click', { tabId: tab, selector: '#name' });
      assert.equal(click.clicked, true);
      const typed = await client.call('devtools_type', { tabId: tab, selector: '#name', text: 'Alice', clear: true });
      assert.equal(typed.value, 'Alice');
      const clicked = await client.call('devtools_click', { tabId: tab, selector: '#go', settleMs: 300 });
      assert.equal(clicked.clicked, true);
      const result = await client.call('devtools_evaluate', { tabId: tab, expression: 'document.querySelector("#result").textContent' });
      assert.equal(result.result, 'clicked:Alice');

      const scrolled = await client.call('devtools_scroll', { tabId: tab, deltaY: 500 });
      assert.ok(scrolled.scroll.y > 0);
      const screenshot = await client.callRaw('devtools_screenshot', { tabId: tab, format: 'png' });
      assert.equal(screenshot.content[0].type, 'image');
      assert.ok(screenshot.content[0].data.length > 1000);
    });

    await t.test('debugger understands scripts, breakpoints, paused call frames and frame evaluation', async () => {
      const enabled = await client.call('devtools_debugger', { action: 'enable', tabId: tab });
      assert.equal(enabled.enabled, true);
      const scripts = await client.call('devtools_debugger', { action: 'scripts', tabId: tab, contains: fixture.origin });
      const script = scripts.scripts.find(item => item.url === fixture.origin + '/');
      assert.ok(script, 'inline page script should be registered');
      const source = await client.call('devtools_debugger', { action: 'source', tabId: tab, scriptId: script.scriptId, maxChars: 30_000 });
      const lines = source.source.split('\n');
      const relativeLine = lines.findIndex(line => line.includes('const sum = a + b'));
      assert.ok(relativeLine >= 0);
      const breakpoint = await client.call('devtools_debugger', {
        action: 'set_breakpoint', tabId: tab, url: fixture.origin + '/',
        lineNumber: script.startLine + relativeLine, columnNumber: 0
      });
      assert.equal(breakpoint.resolved, true);

      const evaluationPromise = client.callRaw('devtools_evaluate', {
        tabId: tab, expression: 'fixtureDebug(2,3)', allowSideEffects: true
      }, 30_000);
      const paused = await waitFor(async () => {
        const state = await client.call('devtools_debugger', { action: 'state', tabId: tab }).catch(() => null);
        return state?.paused === true;
      }, 8000, 100);
      assert.equal(paused, true, 'breakpoint should pause execution');
      const state = await client.call('devtools_debugger', { action: 'state', tabId: tab });
      assert.ok(state.state.hitBreakpoints.length >= 1);
      assert.ok(state.state.callFrames.length >= 1);
      assert.match(state.state.callFrames[0].functionName, /fixtureDebug/);
      const frameEval = await client.call('devtools_debugger', {
        action: 'evaluate', tabId: tab,
        callFrameId: state.state.callFrames[0].callFrameId, expression: 'a + b'
      });
      assert.equal(frameEval.result, 5);
      await client.call('devtools_debugger', { action: 'resume', tabId: tab });
      const evaluation = await evaluationPromise;
      assert.match(evaluation.content[0].text, /"result":5/);
      await client.call('devtools_debugger', { action: 'remove_breakpoint', tabId: tab, breakpointId: breakpoint.breakpointId });

      const explicitPause = await client.call('devtools_debugger', { action: 'pause', tabId: tab });
      assert.equal(explicitPause.paused, true);
      assert.ok(explicitPause.state.callFrames.length >= 1);
      const resumed = await client.call('devtools_debugger', { action: 'resume', tabId: tab });
      assert.equal(resumed.resumed, true);
    });

    await t.test('dialog handling prevents page hangs', async () => {
      const alertPromise = client.callRaw('devtools_evaluate', {
        tabId: tab, expression: 'alert("hello-dialog")', allowSideEffects: true
      }, 20_000);
      await new Promise(resolve => setTimeout(resolve, 500));
      const dialogs = await client.call('devtools_dialog', { tabId: tab, action: 'list' });
      assert.ok(dialogs.open.some(dialog => dialog.type === 'alert' && dialog.message === 'hello-dialog'));
      const accepted = await client.call('devtools_dialog', { tabId: tab, action: 'accept' });
      assert.equal(accepted.handled, true);
      const alertResult = await alertPromise;
      assert.match(alertResult.content[0].text, /"exception":null/);
    });

    await t.test('performance metrics, tracing and CPU profiling produce usable summaries', async () => {
      const metrics = await client.call('devtools_performance', { action: 'metrics', tabId: tab });
      assert.equal(typeof metrics.metrics.JSHeapUsedSize, 'number');
      const traceStart = await client.call('devtools_performance', { action: 'trace_start', tabId: tab });
      assert.equal(traceStart.started, true);
      await new Promise(resolve => setTimeout(resolve, 400));
      const traceStop = await client.call('devtools_performance', { action: 'trace_stop', tabId: tab, timeoutMs: 20_000 });
      assert.equal(traceStop.finished, true);
      assert.ok(traceStop.storedEvents > 0);
      const profileStart = await client.call('devtools_performance', { action: 'profile_start', tabId: tab, samplingInterval: 500 });
      assert.equal(profileStart.started, true);
      await client.call('devtools_evaluate', {
        tabId: tab, allowSideEffects: true,
        expression: '(() => { let x = 0; for (let i = 0; i < 300000; i++) x += i; return x; })()'
      });
      const profileStop = await client.call('devtools_performance', { action: 'profile_stop', tabId: tab });
      assert.ok(profileStop.summary.samples > 0);
      assert.ok(profileStop.topFunctions.length > 0);
    });

    await t.test('cookies and storage are redacted by default and scoped to the tab origin', async () => {
      const cookies = await client.call('devtools_storage', { tabId: tab, scope: 'cookies' });
      assert.ok(cookies.total >= 1);
      const fixtureCookie = cookies.cookies.find(cookie => cookie.name === 'fixtureCookie');
      assert.ok(fixtureCookie);
      assert.equal(fixtureCookie.value, '[REDACTED]');
      const rawCookies = await client.call('devtools_storage', { tabId: tab, scope: 'cookies', includeSensitive: true });
      assert.equal(rawCookies.cookies.find(cookie => cookie.name === 'fixtureCookie').value, 'fixtureCookieValue');

      const local = await client.call('devtools_storage', { tabId: tab, scope: 'local' });
      assert.equal(local.entries.find(entry => entry.key === 'fixtureKey').value, '[REDACTED]');
      const rawLocal = await client.call('devtools_storage', { tabId: tab, scope: 'local', includeSensitive: true });
      assert.equal(rawLocal.entries.find(entry => entry.key === 'fixtureKey').value, 'fixtureValue');

      await client.call('devtools_storage', { tabId: tab, scope: 'local', action: 'set', key: 'testKey', value: 'testValue' });
      const setLocal = await client.call('devtools_storage', { tabId: tab, scope: 'local', includeSensitive: true });
      assert.equal(setLocal.entries.find(entry => entry.key === 'testKey').value, 'testValue');
      await client.call('devtools_storage', { tabId: tab, scope: 'local', action: 'remove', key: 'testKey' });
      const removedLocal = await client.call('devtools_storage', { tabId: tab, scope: 'local', includeSensitive: true });
      assert.equal(removedLocal.entries.some(entry => entry.key === 'testKey'), false);
    });

    await t.test('continuous capture can be started and stopped on demand', async () => {
      const started = await client.call('devtools_capture', { action: 'start', tabId: tab, clear: false });
      assert.equal(started.started, true);
      await client.call('devtools_evaluate', { tabId: tab, expression: '1 + 1' });
      const stopped = await client.call('devtools_capture', { action: 'stop', tabId: tab });
      assert.equal(stopped.stopped, true);
      assert.ok(stopped.summary.durationMs >= 0);
      assert.ok(stopped.summary.requests >= 0);
    });

    await t.test('HAR, JSON, error-report, trace and CPU-profile exports are written and sanitized', async () => {
      const har = await client.call('devtools_export', {
        tabId: tab, format: 'har', includeBodies: true, path: 'workflow.har'
      });
      const harText = await fsp.readFile(har.path, 'utf8');
      const harDoc = JSON.parse(harText);
      assert.equal(harDoc.log.version, '1.2');
      const apiEntry = harDoc.log.entries.find(entry => entry.request.url.includes('/api/data'));
      assert.ok(apiEntry);
      assert.ok(apiEntry.response.content.text.includes('"ok":true'));
      assert.doesNotMatch(apiEntry.response.content.text, /supersecret/);
      assert.equal(har.path.startsWith(exportDir), true);

      const report = await client.call('devtools_export', { tabId: tab, format: 'report', path: 'report.json' });
      const reportDoc = JSON.parse(await fsp.readFile(report.path, 'utf8'));
      assert.ok(reportDoc.summary.failedRequests >= 0);
      assert.ok(reportDoc.summary.consoleErrors >= 1);

      const json = await client.call('devtools_export', { tabId: tab, format: 'json', includeBodies: true, path: 'workflow.json' });
      assert.ok(json.bytes > 0);
      const trace = await client.call('devtools_export', { tabId: tab, format: 'trace', path: 'trace.json' });
      assert.ok(trace.bytes > 0);
      const profile = await client.call('devtools_export', { tabId: tab, format: 'profile', path: 'profile.cpuprofile' });
      assert.ok(profile.bytes > 0);
    });

    await t.test('navigation, reload and back/forward history work', async () => {
      const second = await client.call('devtools_navigate', { url: fixture.origin + '/second', tabId: tab, waitUntil: 'load' });
      assert.equal(second.navigation.title, 'Fixture Second');
      const reload = await client.call('devtools_reload', { tabId: tab, waitUntil: 'load' });
      assert.equal(reload.reloaded, true);
      assert.equal(reload.title, 'Fixture Second');
      const back = await client.call('devtools_history', { tabId: tab, direction: 'back', waitUntil: 'load' });
      assert.equal(back.moved, true);
      assert.equal(back.title, 'Fixture Home');
      const forward = await client.call('devtools_history', { tabId: tab, direction: 'forward', waitUntil: 'load' });
      assert.equal(forward.moved, true);
      assert.equal(forward.title, 'Fixture Second');
    });

    await t.test('two tabs keep independent capture buffers', async () => {
      const second = await open(fixture.origin + '/second');
      const secondTab = second.sessionId;
      const firstConsole = await client.call('devtools_console', { tabId: tab, limit: 100 });
      const secondConsole = await client.call('devtools_console', { tabId: secondTab, limit: 100 });
      assert.ok(firstConsole.entries.some(entry => entry.text.includes('fixture-log')));
      assert.equal(secondConsole.entries.length, 0);
      const firstNetwork = await client.call('devtools_network', { tabId: tab, limit: 200 });
      const secondNetwork = await client.call('devtools_network', { tabId: secondTab, limit: 200 });
      assert.ok(firstNetwork.requests.some(req => req.url.includes('/api/data')));
      assert.equal(secondNetwork.requests.some(req => req.url.includes('/api/data')), false);
      const selected = await client.call('devtools_select_tab', { tabId: tab });
      assert.equal(selected.selected, tab);
      await closeTab(secondTab);
    });

    await t.test('any public HTTP(S) domain works, not only social networks', async () => {
      for (const url of ['https://example.com', 'https://example.org', 'https://www.iana.org']) {
        const result = await open(url, { waitUntil: 'load', settleMs: 200 });
        assert.match(result.navigation.url, /^https:\/\//);
        assert.ok(result.navigation.title.length > 0);
        assert.ok(result.capture.requests >= 1);
        await closeTab(result.sessionId);
      }
      const localhost = await open(fixture.localhostOrigin + '/second', { waitUntil: 'load', settleMs: 200 });
      assert.equal(localhost.navigation.title, 'Fixture Second');
      await closeTab(localhost.sessionId);
    });

    await t.test('devtools_navigate_and_capture performs the full automatic flow in one call on any URL', async () => {
      const result = await client.call('devtools_navigate_and_capture', {
        url: fixture.origin + '/second',
        waitUntil: 'networkidle2',
        timeoutMs: 20_000,
        settleMs: 200
      });
      opened.add(result.sessionId);
      assert.equal(result.createdNewTab, true);
      assert.equal(result.navigation.title, 'Fixture Second');
      assert.equal(result.verified.networkEnabledBeforeNavigation, true);
      assert.ok(Date.parse(result.captureReadiness.networkEnabledAt) <= Date.parse(result.navigation.navigationStartedAt));
      assert.ok(result.capture.requests >= 1, 'document request must be captured from the first byte');
      const network = await client.call('devtools_network', { tabId: result.sessionId, limit: 20 });
      assert.ok(network.requests.some(req => req.type === 'Document' && req.url.includes('/second')));
      await closeTab(result.sessionId);
    });

    await t.test('tabs and status expose isolated sessions and permission tier', async () => {
      const tabs = await client.call('devtools_tabs');
      assert.ok(tabs.tabs.some(item => item.id === tab));
      const status = await client.call('devtools_status', { tabId: tab });
      assert.equal(status.permission, 'full-debug');
      assert.equal(status.activeSession.connected, true);
      assert.ok(status.activeSession.captureReadiness.networkEnabled, true);
      assert.ok(status.browser.browser.length > 0);
    });
  } finally {
    for (const tabId of opened) await closeTab(tabId);
    await client.close();
    await fixture.close();
    await fsp.rm(exportDir, { recursive: true, force: true });
  }
});

test('read-only permission blocks navigation but still allows observation', { timeout: 60_000 }, async t => {
  if (!chromeReady) {
    t.skip(`Chrome is not reachable at ${MAIN_ENDPOINT}`);
    return;
  }
  const client = new McpClient({
    env: { CDP_ENDPOINT: MAIN_ENDPOINT, DEVTOOLS_PERMISSION: 'read-only', DEVTOOLS_AUTO_LAUNCH: '0' }
  });
  try {
    await client.initialize();
    const tabs = await client.call('devtools_tabs');
    assert.ok(Array.isArray(tabs.tabs));
    const denied = await client.callRaw('devtools_open_url', { url: 'https://example.com' });
    assert.equal(denied.isError, true);
    assert.match(denied.content[0].text, /read-only/);
    const evaluated = await client.call('devtools_evaluate', { expression: '2 + 2' });
    assert.equal(evaluated.result, 4);
    const sideEffect = await client.callRaw('devtools_evaluate', { expression: 'document.body.dataset.readOnlyTest = "1"', allowSideEffects: true });
    assert.equal(sideEffect.isError, true);
    assert.match(sideEffect.content[0].text, /interactive/);
  } finally {
    await client.close();
  }
});

test('auto-launches a headless Chromium when no browser is listening', { timeout: 120_000 }, async t => {
  if (!autoPortFree) {
    t.skip(`${AUTO_ENDPOINT} is already in use; auto-launch test needs a free port`);
    return;
  }
  const fixture = await createFixtureServer();
  const profileDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'toolnet-auto-profile-'));
  const client = new McpClient({
    env: {
      CDP_ENDPOINT: AUTO_ENDPOINT,
      DEVTOOLS_PERMISSION: 'interactive',
      DEVTOOLS_AUTO_LAUNCH: '1',
      DEVTOOLS_HEADLESS: '1',
      DEVTOOLS_PROFILE_DIR: profileDir,
      DEVTOOLS_LAUNCH_TIMEOUT: '30000',
      DEVTOOLS_EXPORT_DIR: profileDir
    }
  });
  try {
    await client.initialize();
    const status = await client.call('devtools_status', {}, 60_000);
    assert.match(status.browser.browser, /Chrome|Chromium/i);
    const opened = await client.call('devtools_open_url', {
      url: fixture.origin + '/second', waitUntil: 'load', settleMs: 200
    }, 60_000);
    assert.equal(opened.navigation.title, 'Fixture Second');
    assert.ok(opened.capture.requests >= 1);
    await client.call('devtools_close_tab', { tabId: opened.sessionId });
  } finally {
    await client.close();
    await fixture.close();
    await fsp.rm(profileDir, { recursive: true, force: true });
  }
  await new Promise(resolve => setTimeout(resolve, 1200));
  assert.equal(await reachable(AUTO_ENDPOINT), false, 'auto-launched Chromium should be shut down with the MCP server');
});

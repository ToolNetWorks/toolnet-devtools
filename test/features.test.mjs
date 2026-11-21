import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ChromeSession, Ring } from '../src/cdp.mjs';
import {
  assertPermission,
  assertSensitiveAllowed,
  compactJson,
  normalizePageUrl,
  normalizePermission,
  redactHeaders,
  redactUrl,
  safeResponseBody
} from '../src/security.mjs';
import { buildErrorReport, buildHar, buildJsonExport, resolveExportPath } from '../src/export.mjs';
import { BrowserManager } from '../src/browser.mjs';
import { createRegistry } from '../src/tools/registry.mjs';
import { registerTools } from '../src/tools/index.mjs';

test('permission tiers are explicit and navigation does not require ALLOW_UNSAFE_CDP', () => {
  assert.equal(normalizePermission('read-only'), 'read-only');
  assert.equal(normalizePermission('interactive'), 'interactive');
  assert.equal(normalizePermission('full-debug'), 'full-debug');
  assert.throws(() => normalizePermission('admin'), /Invalid permission/);
  assert.doesNotThrow(() => assertPermission('interactive', 'interactive', 'open URL'));
  assert.throws(() => assertPermission('read-only', 'interactive', 'open URL'), /requires the "interactive"/);
  assert.doesNotThrow(() => assertPermission('full-debug', 'full-debug', 'debugger'));
  assert.throws(() => assertSensitiveAllowed('full-debug', false), /disabled by default/);
  assert.throws(() => assertSensitiveAllowed('interactive', true, 'cookies'), /disabled by default/);
  const oldUnsafe = process.env.ALLOW_UNSAFE_CDP;
  const oldPermission = process.env.DEVTOOLS_PERMISSION;
  const oldCdpPermission = process.env.CDP_PERMISSION;
  delete process.env.DEVTOOLS_PERMISSION;
  delete process.env.CDP_PERMISSION;
  process.env.ALLOW_UNSAFE_CDP = '1';
  assert.equal(normalizePermission(), 'full-debug');
  if (oldUnsafe == null) delete process.env.ALLOW_UNSAFE_CDP; else process.env.ALLOW_UNSAFE_CDP = oldUnsafe;
  if (oldPermission == null) delete process.env.DEVTOOLS_PERMISSION; else process.env.DEVTOOLS_PERMISSION = oldPermission;
  if (oldCdpPermission == null) delete process.env.CDP_PERMISSION; else process.env.CDP_PERMISSION = oldCdpPermission;
});

test('URL validation accepts all HTTP(S) hosts and rejects non-web schemes', () => {
  assert.equal(normalizePageUrl('https://example.com/a?b=c'), 'https://example.com/a?b=c');
  assert.equal(normalizePageUrl('http://127.0.0.1:8080/x'), 'http://127.0.0.1:8080/x');
  assert.equal(normalizePageUrl('https://sub.domain.test/path'), 'https://sub.domain.test/path');
  assert.throws(() => normalizePageUrl('example.com'), /Include a scheme/);
  assert.throws(() => normalizePageUrl('file:///etc/passwd'), /Only HTTP and HTTPS/);
  assert.throws(() => normalizePageUrl('javascript:alert(1)'), /Only HTTP and HTTPS/);
  assert.throws(() => normalizePageUrl('https://user:pass@example.com/'), /embedded credentials/);
  assert.throws(() => normalizePageUrl(''), /must not be empty/);
});

test('redaction keeps useful URLs but removes credentials and secrets', () => {
  assert.equal(redactHeaders({ Authorization: 'Bearer secret', 'X-API-Key': 'xyz', Accept: 'application/json' }).Authorization, '[REDACTED]');
  const url = redactUrl('https://example.org/api?q=hello&token=abcd&page=2#frag');
  assert.match(url, /q=hello/);
  assert.match(url, /page=2/);
  assert.match(url, /token=%5BREDACTED%5D/);
  assert.doesNotMatch(url, /abcd|frag/);
  const raw = redactHeaders({ Authorization: 'Bearer secret' }, { includeSensitive: true });
  assert.equal(raw.Authorization, 'Bearer [REDACTED]'); // text-level bearer redaction still applies
  assert.doesNotMatch(safeResponseBody({ body: '{"password":"abc","name":"demo"}' }).body, /abc/);
  assert.match(safeResponseBody({ body: '{"password":"abc","name":"demo"}' }).body, /demo/);
  assert.equal(safeResponseBody({ body: 'AAAA', base64Encoded: true }).binary, true);
  assert.equal(compactJson({ a: 'x'.repeat(100) }, 50).includes('truncated'), true);
});

test('ring buffers enforce both count and byte limits', () => {
  const ring = new Ring(100, 50);
  ring.push({ value: 'x'.repeat(30) });
  ring.push({ value: 'y'.repeat(30) });
  assert.ok(ring.items.length <= 2);
  assert.ok(ring.bytes <= 60);
  ring.clear();
  assert.equal(ring.items.length, 0);
  assert.equal(ring.bytes, 0);
});

test('network redirects, websocket frames and console metadata are captured', () => {
  const session = new ChromeSession();
  session.handleEvent('Runtime.consoleAPICalled', {
    type: 'log', timestamp: 1795145725291.373,
    args: [{ type: 'string', value: 'hello' }, { type: 'object', description: 'Object', preview: { properties: [{ name: 'ok', value: 'true' }] } }],
    stackTrace: { callFrames: [{ functionName: 'test', url: 'https://site.test/app.js', lineNumber: 4, columnNumber: 2 }] }
  });
  session.handleEvent('Network.requestWillBeSent', {
    requestId: 'r1', type: 'Document', timestamp: 1,
    request: { url: 'https://site.test/start?token=abc', method: 'GET', headers: { Authorization: 'Bearer xyz', Accept: 'text/html' } }
  });
  session.handleEvent('Network.responseReceived', {
    requestId: 'r1', type: 'Document', timestamp: 1.05,
    response: { status: 302, statusText: 'Found', headers: { location: '/final', 'set-cookie': 'a=b' }, mimeType: 'text/html' }
  });
  session.handleEvent('Network.requestWillBeSent', {
    requestId: 'r1', type: 'Document', timestamp: 1.1, redirectResponse: { status: 302, statusText: 'Found', url: 'https://site.test/start', headers: { location: '/final' } },
    request: { url: 'https://site.test/final', method: 'GET', headers: { Accept: 'text/html' } }
  });
  session.handleEvent('Network.responseReceived', {
    requestId: 'r1', type: 'Document', timestamp: 1.2,
    response: { status: 200, statusText: 'OK', headers: { 'content-type': 'text/html' }, mimeType: 'text/html' }
  });
  session.handleEvent('Network.loadingFinished', { requestId: 'r1', timestamp: 1.3, encodedDataLength: 42 });
  session.handleEvent('Network.webSocketCreated', { requestId: 'ws1', url: 'wss://site.test/socket', initiator: { type: 'script' } });
  session.handleEvent('Network.webSocketHandshakeResponseReceived', { requestId: 'ws1', response: { status: 101, headers: {} } });
  session.handleEvent('Network.webSocketFrameSent', { requestId: 'ws1', response: { opcode: 1, payloadData: 'ping' }, timestamp: 2 });
  session.handleEvent('Network.webSocketFrameReceived', { requestId: 'ws1', response: { opcode: 1, payloadData: 'pong' }, timestamp: 2.1 });

  const consoleEntry = session.console.items[0];
  assert.match(consoleEntry.text, /hello/);
  assert.match(consoleEntry.text, /ok/);
  assert.equal(consoleEntry.stackTrace[0].line, 5);
  assert.match(consoleEntry.timestampIso, /^2026-/);
  assert.equal(session.console.items[0].args[0], 'hello');

  const first = session.requestLog.items.find(req => req.url.includes('/start'));
  assert.equal(first.status, 302);
  assert.equal(first.headers.Authorization, '[REDACTED]');
  assert.doesNotMatch(first.url, /abc/);
  const final = session.requests.get('r1');
  assert.equal(final.status, 200);
  assert.equal(final.redirectChain[0].status, 302);
  assert.equal(final.redirectChain[0].location, '/final');
  assert.equal(final.durationMs, 200);
  assert.equal(final.bytes, 42);
  assert.equal(session.wsConnections.get('ws1').status, 'open');
  assert.deepEqual(session.frames.items.map(frame => frame.direction), ['sent', 'received']);
  assert.equal(session.frames.items[1].payload, 'pong');
});

test('HAR export is redacted by default and bodies are opt-in', async () => {
  const session = new ChromeSession('http://127.0.0.1:9222', { allowSensitive: true });
  session.tab = { id: 'tab1', title: 'Demo', url: 'https://site.test/' };
  session.requestLog.push({
    sequence: 1, id: 'r1', url: 'https://site.test/api?token=abc&q=ok', urlRaw: 'https://site.test/api?token=abc&q=ok',
    method: 'POST', resourceType: 'Fetch', status: 200, statusText: 'OK', finished: true, failed: false,
    startedAt: 1795145725, startedAtIso: '2026-11-20T00:00:00.000Z', durationMs: 20, bytes: 10,
    headers: { Authorization: '[REDACTED]', Accept: 'application/json' },
    headersRaw: { Authorization: 'Bearer secret', Accept: 'application/json' },
    responseHeaders: { 'content-type': 'application/json' }, responseHeadersRaw: { 'content-type': 'application/json' },
    postData: '{"password":"[REDACTED]"}', postDataRaw: '{"password":"secret"}', hasPostData: true,
    body: { binary: false, body: '{"password":"[REDACTED]","ok":true}', truncated: false, originalChars: 40 },
    timing: { requestTime: 1, sendStart: 0, sendEnd: 1, receiveHeadersEnd: 5 }
  });
  session.requests.set('r1', session.requestLog.items[0]);

  const plain = await buildHar(session, { includeBodies: false });
  assert.equal(plain.log.version, '1.2');
  assert.equal(plain.log.entries.length, 1);
  assert.equal(plain.log.entries[0].request.headers.find(h => h.name === 'Authorization').value, '[REDACTED]');
  assert.equal(plain.log.entries[0].response.content.text, '');
  assert.doesNotMatch(plain.log.entries[0].request.url, /abc/);

  const withBodies = await buildHar(session, { includeBodies: true });
  assert.match(withBodies.log.entries[0].response.content.text, /"ok":true/);
  assert.doesNotMatch(withBodies.log.entries[0].response.content.text, /secret/);

  const sensitive = await buildHar(session, { includeBodies: true, includeSensitive: true });
  assert.match(sensitive.log.entries[0].request.headers.find(h => h.name === 'Authorization').value, /Bearer/);
  assert.match(sensitive.log.entries[0].request.url, /token=abc/);
});

test('error reports and JSON exports contain summaries without raw secrets', () => {
  const session = new ChromeSession();
  session.tab = { id: 'tab2', title: 'Error page', url: 'https://site.test/' };
  session.console.push({ sequence: 1, level: 'error', category: 'exception', text: 'boom', stackTrace: [] });
  session.requests.set('r1', {
    sequence: 2, id: 'r1', url: 'https://site.test/api?token=abc', method: 'GET', resourceType: 'Fetch',
    status: 500, finished: true, failed: false, headers: { Authorization: '[REDACTED]' }, durationMs: 300
  });
  const report = buildErrorReport(session);
  assert.equal(report.summary.consoleErrors, 1);
  assert.equal(report.summary.failedRequests, 1);
  assert.doesNotMatch(JSON.stringify(report), /abc|Bearer/);
  const json = buildJsonExport(session, { includeBodies: false });
  assert.equal(json.requests.length, 1);
  assert.equal(json.requests[0].body, undefined);
});

test('export paths are confined to the export directory', () => {
  const root = '/tmp/toolnet-export-test';
  assert.equal(resolveExportPath('report.json', 'report', root), `${root}/report.json`);
  assert.equal(resolveExportPath(`${root}/nested/report.json`, 'report', root), `${root}/nested/report.json`);
  assert.throws(() => resolveExportPath('../outside.json', 'report', root), /must stay inside/);
});

test('tool registry exposes all required DevTools domains with permission tiers', () => {
  const manager = new BrowserManager({ endpoint: 'http://127.0.0.1:9222', autoLaunch: false });
  const registry = createRegistry({ manager, permission: 'interactive', allowSensitive: false });
  registerTools(registry);
  const names = registry.list().map(tool => tool.name);
  for (const name of [
    'devtools_f12_check', 'devtools_navigate_and_capture', 'devtools_open_url', 'devtools_navigate', 'devtools_reload', 'devtools_history',
    'devtools_click', 'devtools_type', 'devtools_scroll', 'devtools_hover', 'devtools_dblclick', 'devtools_focus', 'devtools_select', 'devtools_drag', 'devtools_upload_file', 'devtools_download',
    'devtools_tabs', 'devtools_select_tab',
    'devtools_console', 'devtools_network', 'devtools_websocket', 'devtools_dom_inspect', 'devtools_accessibility', 'devtools_snapshot',
    'devtools_debugger', 'devtools_performance', 'devtools_intercept', 'devtools_emulate', 'devtools_storage', 'devtools_storage_state', 'devtools_export', 'devtools_pdf',
    'devtools_cdp', 'devtools_diagnose', 'devtools_capture', 'devtools_screenshot'
  ]) assert.ok(names.includes(name), `missing ${name}`);
  assert.equal(names[0], 'devtools_navigate_and_capture', 'primary workflow must be listed first');
  assert.equal(registry.get('devtools_f12_check').minPermission, 'interactive');
  assert.equal(registry.get('devtools_emulate').minPermission, 'interactive');
  assert.equal(registry.get('devtools_accessibility').minPermission, 'read-only');
  assert.equal(registry.get('devtools_pdf').minPermission, 'read-only');
  assert.equal(registry.get('devtools_open_url').minPermission, 'interactive');
  assert.equal(registry.get('devtools_debugger').minPermission, 'full-debug');
  assert.equal(registry.get('devtools_console').minPermission, 'read-only');
});

test('manager endpoint validation and binary discovery do not crash', () => {
  assert.throws(() => new BrowserManager({ endpoint: 'http://10.0.0.5:9222', autoLaunch: false }), /loopback/);
  const manager = new BrowserManager({ endpoint: 'http://127.0.0.1:9222', autoLaunch: false });
  assert.equal(manager.endpoint, 'http://127.0.0.1:9222');
});

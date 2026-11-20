import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Ring, ChromeSession } from '../src/cdp.mjs';
import { redactHeaders, redactText, redactUrl, safeResponseBody, isAllowedEndpoint, isAllowedWebSocket } from '../src/security.mjs';

test('ring always caps memory', () => {
  const ring = new Ring(2); ring.push(1); ring.push(2); ring.push(3);
  assert.deepEqual(ring.items, [2,3]); ring.clear(); assert.deepEqual(ring.items, []);
});
test('redacts secrets and URL parameters', () => {
  assert.equal(redactHeaders({ Authorization: 'Bearer secret', 'X-API-Key': 'xyz', Accept: 'application/json' }).Authorization, '[REDACTED]');
  assert.match(redactUrl('https://example.org/api?token=abcd#frag'), /REDACTED/);
  assert.doesNotMatch(redactUrl('https://example.org/api?token=abcd#frag'), /abcd|frag/);
  assert.doesNotMatch(redactText('Authorization: Bearer secretvalue'), /secretvalue/);
  assert.doesNotMatch(safeResponseBody({ body: '{"password":"abc","name":"demo"}' }).body, /abc/);
});
test('refuses remote debugging endpoints', () => {
  assert.equal(isAllowedEndpoint('http://127.0.0.1:9222'), true);
  assert.equal(isAllowedEndpoint('http://10.0.0.1:9222'), false);
  assert.equal(isAllowedWebSocket('ws://127.0.0.1:9222/devtools/page/test', 'http://127.0.0.1:9222'), true);
  assert.equal(isAllowedWebSocket('ws://evil.com:9222/devtools/page/test', 'http://127.0.0.1:9222'), false);
});
test('captures events and summarizes response lifecycles', () => {
  const s = new ChromeSession();
  s.handleEvent('Runtime.consoleAPICalled', { type: 'error', args: [{ value: 'bad JS' }], timestamp: 123 });
  s.handleEvent('Network.requestWillBeSent', { requestId: 'one', request: { url:'https://site.test/data?key=abc', method: 'GET', headers: { Authorization: 'xyz' } }, timestamp:1 });
  s.handleEvent('Network.responseReceived', { requestId: 'one', response: { status: 404, mimeType:'application/json' }, timestamp: 1.1 });
  s.handleEvent('Network.loadingFinished', { requestId:'one', timestamp:1.25, encodedDataLength:42 });
  s.handleEvent('Network.webSocketFrameReceived', { requestId:'ws1', response: { opcode:1, payloadData:'hello' } });
  assert.equal(s.console.items[0].text, 'bad JS');
  assert.equal(s.requests.get('one').status, 404);
  assert.equal(s.requests.get('one').durationMs, 250);
  assert.doesNotMatch(s.requests.get('one').url, /abc/);
  assert.equal(s.frames.items[0].direction, 'received');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { buildReverseReport, registerReverseTools } from '../src/tools/reverse.mjs';

const captured = [
  { id: '1', url: 'https://demo.test/api/users/123456?token=secret', method: 'GET', resourceType: 'Fetch', status: 200, body: { body: '{"name":"Demo","token":"[REDACTED]","count":2}' } },
  { id: '2', url: 'https://demo.test/api/users/654321', method: 'GET', resourceType: 'XHR', status: 404 },
  { id: '3', url: 'https://demo.test/_next/static/chunks/app.js', method: 'GET', resourceType: 'Script', status: 200 },
  { id: '4', url: 'https://demo.test/account', method: 'GET', resourceType: 'Document', status: 200 }
];

function captureTool() {
  let tool;
  registerReverseTools({ add: (...args) => { tool = args; } });
  return { name: tool[0], minPermission: tool[3], run: tool[4] };
}

function fakeSession({ scripts = new Map() } = {}) {
  return {
    tab: { id: 'tab1' },
    captureReadiness: { networkEnabled: true },
    scripts,
    requests: new Map(),
    requestLog: { items: captured },
    pageInfo: async () => ({ url: 'https://demo.test/', title: 'Demo' }),
    evaluateValue: async () => ({ title: 'Demo', technologies: { next: true }, forms: [], routes: [] }),
    enableDebugger: async () => {},
    send: async () => ({ scriptSource: 'fetch("/api/orders/123456");const password="hidden";' })
  };
}

test('groups captured API patterns, JSON shapes and resource inventory without exposing tokens', () => {
  const report = buildReverseReport({ page: { url: 'https://demo.test/', title: 'Demo' }, requests: captured });
  assert.equal(report.totals.apiPatterns, 1);
  assert.equal(report.apiEndpoints[0].path, '/api/users/:id');
  assert.deepEqual(report.apiEndpoints[0].statuses, { '200': 1, '404': 1 });
  assert.deepEqual(report.apiEndpoints[0].responseShape, { name: 'string', '[SENSITIVE_FIELD]': '[REDACTED]', count: 'number' });
  assert.equal(report.assets.length, 1);
  assert.doesNotMatch(JSON.stringify(report), /token=secret|"hidden"/);
});

test('read-only permission prevents navigating a new URL', async () => {
  const tool = captureTool();
  assert.equal(tool.name, 'devtools_reverse_engineer');
  assert.equal(tool.minPermission, 'read-only');
  await assert.rejects(() => tool.run({ url: 'https://demo.test' }, { permission: 'read-only' }), /requires the .* permission tier/);
});

test('inspects an existing session without requiring navigation', async () => {
  const tool = captureTool();
  const result = await tool.run({ includeDom: false }, { permission: 'read-only', session: async () => fakeSession() });
  assert.equal(result.report.apiEndpoints.length, 1);
  assert.equal(result.report.dom, null);
  assert.equal(result.captureReadiness.networkEnabled, true);
});

test('script inspection requires full-debug and returns indicators, not the raw source', async () => {
  const tool = captureTool();
  await assert.rejects(() => tool.run({ analyzeScripts: true }, { permission: 'interactive' }), /requires the .* permission tier/);
  const session = fakeSession({ scripts: new Map([['s1', { scriptId: 's1', url: 'https://demo.test/main.js' }]]) });
  const result = await tool.run({ analyzeScripts: true }, { permission: 'full-debug', session: async () => session });
  assert.equal(result.report.analyzedScripts[0].indicators.fetch, true);
  assert.equal(result.report.analyzedScripts[0].urlCandidates[0], '/api/orders/123456');
  assert.doesNotMatch(JSON.stringify(result.report), /hidden/);
});

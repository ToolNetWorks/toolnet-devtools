import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateAuthGate, registerSecurityProbeTools, scanAttackSurface, scanCredentialExposure } from '../src/tools/security-probe.mjs';

function captureTool() {
  let tool;
  registerSecurityProbeTools({ add: (...args) => { tool = args; } });
  return { name: tool[0], minPermission: tool[3], run: tool[4] };
}

const requests = [
  { url: 'https://demo.test/login?token=abc123&user=bob', method: 'GET', resourceType: 'Document', status: 200 },
  { url: 'https://demo.test/reset?password=hunter2', method: 'GET', resourceType: 'Document', status: 200 },
  { url: 'https://demo.test/page?theme=dark', method: 'GET', resourceType: 'Document', status: 200 }
];
const storages = [
  { type: 'local', entries: [
    { key: 'access_token', value: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123-def456' },
    { key: 'profile', value: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI5ODc2NTQzMjExIn0.ghi789-jkl012' },
    { key: 'theme', value: 'dark' }
  ] },
  { type: 'session', entries: [{ key: 'session_id', value: 'zzz' }] }
];

test('scanCredentialExposure finds URL and storage secrets without leaking values', () => {
  const scan = scanCredentialExposure({ requests, storages });
  assert.equal(scan.exposed, true);
  assert.equal(scan.findings.length, 5);
  const types = scan.findings.map(f => f.type).sort();
  assert.deepEqual(types, ['storage-jwt', 'storage-secret', 'storage-secret', 'url-query-param', 'url-query-param']);
  assert.equal(scan.findings.filter(f => f.type === 'url-query-param').length, 2);
  assert.equal(scan.totals.scannedStorageEntries, 4);
  const json = JSON.stringify(scan);
  assert.doesNotMatch(json, /abc123|hunter2|zzz|def456/);
  assert.ok(scan.findings.every(f => f.value === '[REDACTED]'));
});

test('scanCredentialExposure reports nothing for clean targets', () => {
  const scan = scanCredentialExposure({ requests: [requests[2]], storages: [{ type: 'local', entries: [{ key: 'theme', value: 'dark' }] }] });
  assert.equal(scan.exposed, false);
  assert.equal(scan.findings.length, 0);
});

test('evaluateAuthGate flags gated content served without a login form', () => {
  const hit = evaluateAuthGate({ documentStatus: 200, hasPasswordField: false, pageText: 'Welcome back! Premium content unlocked.', authenticatedMarkers: ['Premium content'] });
  assert.equal(hit.gateBypassed, true);
  assert.equal(hit.severity, 'high');
  assert.deepEqual(hit.markersFound, ['Premium content']);
  assert.ok(hit.remediation.includes('server-side'));

  const clean = evaluateAuthGate({ documentStatus: 200, hasPasswordField: true, pageText: 'Sign in to continue. Premium content.', authenticatedMarkers: ['Premium content'] });
  assert.equal(clean.gateBypassed, false);
  assert.equal(clean.severity, 'none');

  const gated = evaluateAuthGate({ documentStatus: 403, hasPasswordField: false, pageText: 'Premium content', authenticatedMarkers: ['Premium content'] });
  assert.equal(gated.gateBypassed, false);
});

function fakeSession({ replies = [] } = {}) {
  const queue = [...replies];
  return {
    tab: { id: 'tab1' },
    requestLog: { items: [{ url: 'https://demo.test/premium', resourceType: 'Document', status: 200, responseReceivedAt: '2026-01-01T00:00:02Z' }] },
    requests: new Map(),
    storage: async type => ({ type, entries: type === 'local' ? [{ key: 'api_key', value: 'k1' }] : [] }),
    pageInfo: async () => ({ url: 'https://demo.test/premium', title: 'Premium' }),
    evaluateValue: async () => queue.shift() ?? ''
  };
}

test('devtools_security_probe runs secrets and auth_gate checks on the current tab', async () => {
  const tool = captureTool();
  assert.equal(tool.name, 'devtools_security_probe');
  assert.equal(tool.minPermission, 'read-only');

  const session = fakeSession({ replies: ['Welcome back! Premium content unlocked.', false] });
  const result = await tool.run(
    { tabId: 'tab1', action: 'all', authenticatedMarkers: ['Premium content'] },
    { permission: 'read-only', session: async () => session }
  );
  assert.equal(result.credentials.exposed, true);
  assert.equal(result.credentials.findings[0].type, 'storage-secret');
  assert.equal(result.authGate.gateBypassed, true);
  assert.equal(result.authGate.documentStatus, 200);
});

test('devtools_security_probe action=surface uses the DOM probe', async () => {
  const tool = captureTool();
  const session = fakeSession({ replies: [surfaceDom] });
  const result = await tool.run({ tabId: 'tab1', action: 'surface' }, { permission: 'read-only', session: async () => session });
  assert.equal(result.surface.risky, true);
  assert.ok(result.surface.findings.length > 0);
  assert.ok(result.surface.findings.some(f => f.type === 'credential-form-third-party'));
});

test('navigation requires the interactive permission tier', async () => {
  const tool = captureTool();
  await assert.rejects(
    () => tool.run({ url: 'https://demo.test/premium' }, { permission: 'read-only', session: async () => fakeSession() }),
    /requires the .* permission tier/
  );
});

const surfaceRequests = [
  { url: 'https://demo.test/app', resourceType: 'Document', status: 200 },
  { url: 'http://cdn.demo.test/tracker.js', resourceType: 'Script', status: 200 },
  { url: 'https://demo.test/go?next=https://evil.test', resourceType: 'Document', status: 200 },
  { url: 'https://demo.test/admin', resourceType: 'Document', status: 200 },
  { url: 'https://demo.test/app?ok=1', resourceType: 'Document', status: 200 }
];
const surfaceDom = {
  forms: [
    { action: 'https://other.test/login', method: 'POST', fields: [{ tag: 'input', type: 'password', name: 'password' }] },
    { action: '/search', method: 'GET', fields: [{ tag: 'input', type: 'password', name: 'password' }] },
    { action: '/subscribe', method: 'POST', fields: [{ tag: 'input', type: 'email', name: 'email' }] }
  ],
  scripts: ['https://demo.test/app.js', 'https://analytics.test/lib.js'],
  links: ['https://demo.test/out?redirect=https://evil.test'],
  dangerous: { eval: 2, newFunction: 0, innerHtml: 3, documentWrite: 0, locationAssign: 0 }
};

test('scanAttackSurface maps mixed content, credential forms, redirects, paths, scripts and sinks', () => {
  const scan = scanAttackSurface({ requests: surfaceRequests, pageUrl: 'https://demo.test/app', dom: surfaceDom });
  const types = scan.findings.map(f => f.type);
  assert.ok(types.includes('mixed-content'));
  assert.ok(types.includes('open-redirect-param'));
  assert.ok(types.includes('sensitive-path-exposed'));
  assert.ok(types.includes('credential-form-get'));
  assert.ok(types.includes('credential-form-third-party'));
  assert.ok(types.includes('third-party-scripts'));
  assert.ok(types.includes('dangerous-js-eval'));
  assert.ok(types.includes('dangerous-js-dom-sink'));
  assert.equal(scan.risky, true);
  assert.equal(scan.findings[0].severity === 'high' || scan.findings[0].severity === 'critical', true);
  const json = JSON.stringify(scan);
  assert.doesNotMatch(json, /evil\.test[^\"]*token/);
  assert.ok(scan.findings.every(f => f.remediation));
});

test('scanAttackSurface stays quiet for a clean page', () => {
  const scan = scanAttackSurface({
    requests: [{ url: 'https://demo.test/app', resourceType: 'Document', status: 200 }],
    pageUrl: 'https://demo.test/app',
    dom: { forms: [{ action: '/login', method: 'POST', fields: [{ tag: 'input', type: 'password', name: 'password' }] }], scripts: ['https://demo.test/app.js'], links: ['https://demo.test/about'], dangerous: { eval: 0, newFunction: 0, innerHtml: 0, documentWrite: 0 } }
  });
  assert.equal(scan.findings.length, 0);
  assert.equal(scan.risky, false);
});

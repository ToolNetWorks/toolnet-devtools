import test from 'node:test';
import assert from 'node:assert/strict';
import { registerDeepProbeTools } from '../src/tools/deep-probe.mjs';

function captureTools() {
  const tools = new Map();
  registerDeepProbeTools({ add: (name, description, schema, minPermission, handler) => tools.set(name, { name, minPermission, run: handler }) });
  return tools;
}

function fakeSession({ requests = [], scripts = new Map(), evaluateResults = [] } = {}) {
  const queue = [...evaluateResults];
  const sent = [];
  return {
    tab: { id: 'tab1' },
    sent,
    requests: new Map(requests.map(r => [r.id, r])),
    requestLog: { items: requests },
    scripts,
    enableDebugger: async () => { sent.push({ method: 'enableDebugger' }); },
    send: async (method, params) => {
      sent.push({ method, params });
      return { result: { value: queue.shift() ?? null } };
    }
  };
}

const graphqlRequests = [
  { id: '1', url: 'https://demo.test/graphql', method: 'POST', resourceType: 'Fetch', status: 200, postData: JSON.stringify({ operationName: 'GetUser', query: 'query GetUser { user { id } }' }) },
  { id: '2', url: 'https://demo.test/graphql', method: 'POST', resourceType: 'Fetch', status: 200, postData: JSON.stringify({ operationName: 'CreatePost', query: 'mutation CreatePost { createPost { id } }' }) },
  { id: '3', url: 'https://demo.test/api/users', method: 'GET', resourceType: 'Fetch', status: 200 }
];

test('devtools_graphql lists endpoints and operations from captured traffic', async () => {
  const tools = captureTools();
  const tool = tools.get('devtools_graphql');
  assert.equal(tool.minPermission, 'read-only');
  const result = await tool.run({ action: 'endpoints' }, { permission: 'read-only', session: async () => fakeSession({ requests: graphqlRequests }) });
  assert.equal(result.endpoints.length, 1);
  assert.equal(result.endpoints[0].endpoint, 'https://demo.test/graphql');
  assert.deepEqual(result.endpoints[0].operations, ['GetUser', 'CreatePost']);
  assert.equal(result.totals.endpoints, 1);
});

test('devtools_graphql introspection requires interactive and summarizes the schema', async () => {
  const tools = captureTools();
  const tool = tools.get('devtools_graphql');
  await assert.rejects(
    () => tool.run({ action: 'introspect' }, { permission: 'read-only', session: async () => fakeSession({ requests: graphqlRequests }) }),
    /requires the .* permission tier/
  );

  const schemaPayload = {
    ok: true, status: 200, statusText: 'OK', ms: 42, headers: {}, bodyChars: 500,
    body: JSON.stringify({ data: { __schema: { queryType: { name: 'Query' }, mutationType: { name: 'Mutation' }, subscriptionType: null, types: [{ name: 'User', kind: 'OBJECT', fields: [{ name: 'id' }, { name: 'email' }] }, { name: '__Type', kind: 'OBJECT', fields: [] }] } } })
  };
  const session = fakeSession({ requests: graphqlRequests, evaluateResults: [schemaPayload] });
  const result = await tool.run({ action: 'introspect' }, { permission: 'interactive', session: async () => session });
  assert.equal(result.introspectionAvailable, true);
  assert.equal(result.schema.queryType, 'Query');
  assert.equal(result.schema.mutationType, 'Mutation');
  assert.equal(result.schema.typeCount, 1); // __-prefixed types are excluded
  assert.equal(result.schema.types[0].name, 'User');
  assert.equal(result.schema.types[0].fieldCount, 2);
});

test('devtools_graphql reports unavailable introspection without crashing', async () => {
  const tools = captureTools();
  const tool = tools.get('devtools_graphql');
  const session = fakeSession({ requests: graphqlRequests, evaluateResults: [{ ok: true, status: 200, body: JSON.stringify({ errors: [{ message: 'introspection disabled' }] }) }] });
  const result = await tool.run({ action: 'introspect' }, { permission: 'interactive', session: async () => session });
  assert.equal(result.introspectionAvailable, false);
  assert.match(result.note, /disabled|not an introspection/);
});

test('devtools_sourcemap lists and fetches bounded map metadata (full-debug)', async () => {
  const tools = captureTools();
  const tool = tools.get('devtools_sourcemap');
  assert.equal(tool.minPermission, 'full-debug');

  const scripts = new Map([
    ['s1', { scriptId: 's1', url: 'https://demo.test/app.js', sourceMapURL: 'https://demo.test/app.js.map' }],
    ['s2', { scriptId: 's2', url: 'https://demo.test/vendor.js' }]
  ]);
  const listResult = await tool.run({ action: 'list' }, { permission: 'full-debug', session: async () => fakeSession({ scripts }) });
  assert.equal(listResult.totals.scripts, 2);
  assert.equal(listResult.totals.withSourceMaps, 1);
  assert.equal(listResult.scripts[0].sourceMapURL, 'https://demo.test/app.js.map');

  const mapBody = JSON.stringify({ version: 3, file: 'app.js', sources: ['webpack://src/a.js', 'webpack://src/b.js'], sourcesContent: ['x', null] });
  const session = fakeSession({ scripts, evaluateResults: [{ ok: true, status: 200, bodyChars: mapBody.length, body: mapBody }] });
  const fetchResult = await tool.run({ action: 'fetch', maxMaps: 2 }, { permission: 'full-debug', session: async () => session });
  assert.equal(fetchResult.totals.fetched, 1);
  assert.equal(fetchResult.maps[0].map.sourcesCount, 2);
  assert.equal(fetchResult.maps[0].map.sourcesContentCount, 1);
  assert.deepEqual(fetchResult.maps[0].map.sources, ['webpack://src/a.js', 'webpack://src/b.js']);
});

test('devtools_replay re-sends a captured request and redacts the response', async () => {
  const tools = captureTools();
  const tool = tools.get('devtools_replay');
  assert.equal(tool.minPermission, 'interactive');

  const captured = [{ id: 'r1', url: 'https://demo.test/api/orders/123', method: 'GET', resourceType: 'XHR', status: 200, postData: null, headers: { authorization: '[REDACTED]' } }];
  const fetchValue = { ok: true, status: 200, statusText: 'OK', ms: 33, headers: { 'content-type': 'application/json', 'set-cookie': 'sid=abc' }, bodyChars: 200, body: '{"ok":true,"token":"supersecret","data":[1,2,3]}' };
  const session = fakeSession({ requests: captured, evaluateResults: [fetchValue] });
  const result = await tool.run({ requestId: 'r1' }, { permission: 'interactive', session: async () => session });

  assert.equal(result.request.method, 'GET');
  assert.equal(result.request.url, 'https://demo.test/api/orders/123');
  assert.equal(result.response.status, 200);
  assert.equal(result.response.ms, 33);
  assert.doesNotMatch(JSON.stringify(result), /supersecret|sid=abc/);

  await assert.rejects(
    () => tool.run({ requestId: 'missing' }, { permission: 'interactive', session: async () => fakeSession({ requests: captured }) }),
    /Unknown requestId/
  );
  await assert.rejects(
    () => tool.run({}, { permission: 'interactive', session: async () => fakeSession({ requests: captured }) }),
    /Provide requestId or url/
  );
});

test('devtools_replay json override builds an application/json body', async () => {
  const tools = captureTools();
  const tool = tools.get('devtools_replay');
  const session = fakeSession({ evaluateResults: [{ ok: true, status: 201, statusText: 'Created', ms: 12, headers: {}, bodyChars: 2, body: '{}' }] });
  const result = await tool.run({ url: 'https://demo.test/api/items', method: 'POST', json: { name: 'x' } }, { permission: 'interactive', session: async () => session });
  assert.equal(result.response.status, 201);
  const init = session.sent.find(call => call.method === 'Runtime.evaluate').params;
  assert.match(init.expression, /"method":"POST"/);
  assert.match(init.expression, /content-type/);
  assert.match(init.expression, /"body":"{\\"name\\":\\"x\\"}"/);
});

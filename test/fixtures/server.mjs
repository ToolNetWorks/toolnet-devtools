import http from 'node:http';
import crypto from 'node:crypto';

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function sendWsText(socket, text) {
  const payload = Buffer.from(String(text));
  if (payload.length < 126) {
    socket.write(Buffer.concat([Buffer.from([0x81, payload.length]), payload]));
    return;
  }
  if (payload.length < 65536) {
    const header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(payload.length, 2);
    socket.write(Buffer.concat([header, payload]));
    return;
  }
  const header = Buffer.alloc(10);
  header[0] = 0x81;
  header[1] = 127;
  header.writeBigUInt64BE(BigInt(payload.length), 2);
  socket.write(Buffer.concat([header, payload]));
}

function decodeClientFrames(buffer, onText) {
  let offset = 0;
  while (buffer.length - offset >= 2) {
    const first = buffer[offset];
    const second = buffer[offset + 1];
    const opcode = first & 0x0f;
    const masked = (second & 0x80) !== 0;
    let length = second & 0x7f;
    let headerSize = 2;
    if (length === 126) {
      if (buffer.length - offset < 4) break;
      length = buffer.readUInt16BE(offset + 2);
      headerSize = 4;
    } else if (length === 127) {
      if (buffer.length - offset < 10) break;
      length = Number(buffer.readBigUInt64BE(offset + 2));
      headerSize = 10;
    }
    const maskSize = masked ? 4 : 0;
    if (buffer.length - offset < headerSize + maskSize + length) break;
    const mask = masked ? buffer.subarray(offset + headerSize, offset + headerSize + 4) : null;
    const payloadStart = offset + headerSize + maskSize;
    const payload = Buffer.from(buffer.subarray(payloadStart, payloadStart + length));
    if (mask) {
      for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
    }
    if (opcode === 0x1) onText(payload.toString('utf8'));
    if (opcode === 0x8) return buffer.subarray(offset);
    offset = payloadStart + length;
  }
  return buffer.subarray(offset);
}

export async function createFixtureServer() {
  const sockets = new Set();
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://fixture.test');
    const send = (status, body, type = 'text/html; charset=utf-8', extra = {}) => {
      const payload = Buffer.isBuffer(body) ? body : Buffer.from(body);
      res.writeHead(status, {
        'content-type': type,
        'content-length': payload.length,
        'cache-control': 'no-store',
        ...extra
      });
      res.end(payload);
    };

    if (url.pathname === '/') {
      const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Fixture Home</title></head>
<body>
  <h1 id="heading">ToolNet Fixture</h1>
  <label for="name">Name</label>
  <input id="name" name="name" placeholder="name" value="">
  <button id="go" type="button">Go</button>
  <div id="result">waiting</div>
  <a id="second-link" href="/second">Second page</a>
  <a id="popup-link" href="/second" target="_blank" rel="noopener">Open second page in a new tab</a>
  <div id="tall" style="height:2400px;background:linear-gradient(#fff,#eee)"></div>
  <script>
    window.fixtureDebug = function fixtureDebug(a, b) {
      const sum = a + b;
      return sum;
    };
    console.log('fixture-log', { ok: true, nested: { value: 42 } });
    console.warn('fixture-warning');
    setTimeout(() => console.error('fixture-error'), 40);
    setTimeout(() => { throw new Error('fixture-uncaught'); }, 90);
    fetch('/api/data').then(r => r.json()).then(data => {
      document.querySelector('#result').textContent = 'api:' + data.ok;
      console.log('api-loaded', data.ok);
    }).catch(error => console.error('api-failed', String(error)));
    fetch('/api/echo', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ hello: 'world', password: 'post-secret' })
    }).then(r => r.json()).then(data => console.log('echo-loaded', data.ok));
    localStorage.setItem('fixtureKey', 'fixtureValue');
    sessionStorage.setItem('sessionKey', 'sessionValue');
    document.cookie = 'fixtureCookie=fixtureCookieValue; path=/';
    const ws = new WebSocket('ws://' + location.host + '/ws');
    ws.onopen = () => { ws.send('client-hello'); console.log('ws-open'); };
    ws.onmessage = event => { window.__wsMessage = event.data; console.log('ws-message', event.data); };
    ws.onerror = () => console.error('ws-error');
    document.querySelector('#go').addEventListener('click', () => {
      const value = document.querySelector('#name').value;
      document.querySelector('#result').textContent = 'clicked:' + value;
      console.log('button-clicked', value);
    });
  </script>
</body></html>`;
      send(200, html);
      return;
    }
    if (url.pathname === '/second') {
      send(200, '<!doctype html><html><head><title>Fixture Second</title></head><body><h1>Second</h1><p id="second">second-page</p></body></html>');
      return;
    }
    if (url.pathname === '/delayed') {
      send(200, `<!doctype html><html><head><title>Fixture Delayed</title></head><body>
        <div id="result">waiting</div>
        <script>
          setTimeout(() => {
            fetch('/api/delayed').then(r => r.json()).then(data => {
              document.querySelector('#result').textContent = 'delayed:' + data.ok;
              console.log('delayed-loaded', data.ok);
            }).catch(error => console.error('delayed-failed', String(error)));
          }, 700);
        </script>
      </body></html>`);
      return;
    }
    if (url.pathname === '/api/delayed') {
      send(200, JSON.stringify({ ok: true, secret: 'delayed-secret', items: ['a', 'b'] }), 'application/json');
      return;
    }
    if (url.pathname === '/api/data') {
      send(200, JSON.stringify({
        ok: true,
        password: 'supersecret',
        token: 'token-value-123',
        access_token: 'access-value-456',
        items: [1, 2, 3]
      }), 'application/json');
      return;
    }
    if (url.pathname === '/api/echo') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => send(200, JSON.stringify({ ok: true, received: body, method: req.method }), 'application/json'));
      return;
    }
    if (url.pathname === '/api/error') {
      send(500, JSON.stringify({ ok: false, error: 'fixture-500' }), 'application/json');
      return;
    }
    if (url.pathname === '/redirect') {
      res.writeHead(302, { location: '/api/data', 'cache-control': 'no-store' });
      res.end();
      return;
    }
    if (url.pathname === '/slow') {
      const ms = Math.min(10_000, Number(url.searchParams.get('ms') ?? 200));
      setTimeout(() => send(200, JSON.stringify({ ok: true, ms }), 'application/json'), ms);
      return;
    }
    if (url.pathname === '/binary') {
      const data = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01, 0x02]);
      send(200, data, 'image/png');
      return;
    }
    if (url.pathname === '/graphql') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        if (body.includes('__schema')) {
          send(200, JSON.stringify({ data: { __schema: {
            queryType: { name: 'Query' },
            mutationType: { name: 'Mutation' },
            subscriptionType: null,
            types: [
              { name: 'User', kind: 'OBJECT', fields: [{ name: 'id' }, { name: 'email' }] },
              { name: 'Post', kind: 'OBJECT', fields: [{ name: 'id' }, { name: 'title' }] },
              { name: '__Type', kind: 'OBJECT', fields: [] }
            ]
          } } }), 'application/json');
          return;
        }
        send(200, JSON.stringify({ data: { user: { id: 'u1', email: 'user@fixture.test' } } }), 'application/json');
      });
      return;
    }
    if (url.pathname === '/graph.html') {
      send(200, `<!doctype html><html><head><title>Fixture GraphQL</title></head><body>
        <h1>GraphQL fixture</h1><div id="result">waiting</div>
        <script>
          fetch('/graphql', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ operationName: 'GetUser', query: 'query GetUser { user { id email } }' }) })
            .then(r => r.json()).then(data => { document.querySelector('#result').textContent = 'user:' + data.data.user.id; })
            .catch(error => console.error('graphql-failed', String(error)));
        </script>
      </body></html>`);
      return;
    }
    if (url.pathname === '/app.js') {
      send(200, `function fixtureApp() { return 'app'; }\nconsole.log('app-loaded');\n//# sourceMappingURL=app.js.map\n`, 'application/javascript');
      return;
    }
    if (url.pathname === '/app.js.map') {
      send(200, JSON.stringify({
        version: 3,
        file: 'app.js',
        sources: ['webpack://fixture/src/a.js', 'webpack://fixture/src/b.js'],
        sourcesContent: ['export const a = 1;', 'export const b = 2;']
      }), 'application/json');
      return;
    }
    if (url.pathname === '/map.html') {
      send(200, `<!doctype html><html><head><title>Fixture Source Map</title></head><body>
        <h1>Source map fixture</h1><script src="/app.js"></script>
      </body></html>`);
      return;
    }
    if (url.pathname === '/third-party.js') {
      send(200, `console.log('third-party-loaded');\n`, 'application/javascript');
      return;
    }
    if (url.pathname === '/login-form.html') {
      const hostPort = new URL('http://' + (req.headers.host ?? '127.0.0.1:80')).port || '80';
      send(200, `<!doctype html><html><head><title>Fixture Login</title></head><body>
        <h1>Login fixture</h1>
        <form method="GET" action="/login">
          <input type="text" name="user" value="">
          <input type="password" name="password" value="">
          <button type="submit">Sign in</button>
        </form>
        <a id="out-link" href="/out?redirect=https://example.test/away">Go out</a>
        <script src="http://localhost:${hostPort}/third-party.js"></script>
        <script>
          localStorage.setItem('access_token', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.abcdef123456');
          sessionStorage.setItem('session_id', 'fixture-session-1');
          fetch('/api/data?token=url-token-9').then(r => r.json()).catch(() => {});
        </script>
      </body></html>`);
      return;
    }
    if (url.pathname === '/login' || url.pathname === '/out') {
      send(200, '<!doctype html><title>Fixture landing</title><h1>Landed</h1>');
      return;
    }
    if (url.pathname === '/chat.html') {
      send(200, `<!doctype html><html><head><title>Fixture Chat</title></head><body>
        <h1>Chat fixture</h1>
        <input id="chat-input" type="text" placeholder="message">
        <button id="send" type="button">Send</button>
        <div id="response"></div>
        <script>
          const respond = () => {
            const text = document.querySelector('#chat-input').value;
            if (!text) return;
            setTimeout(() => { document.querySelector('#response').textContent = 'Opposite Day accepted: false'; }, 60);
          };
          document.querySelector('#send').addEventListener('click', respond);
          document.querySelector('#chat-input').addEventListener('keydown', event => { if (event.key === 'Enter') respond(); });
        </script>
      </body></html>`);
      return;
    }
    if (url.pathname === '/favicon.ico') { send(204, ''); return; }
    send(404, '<!doctype html><title>Not found</title><h1>404</h1>');
  });

  server.on('connection', socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  server.on('upgrade', (req, socket) => {
    if (new URL(req.url ?? '/', 'http://fixture.test').pathname !== '/ws') {
      socket.destroy();
      return;
    }
    const key = req.headers['sec-websocket-key'];
    if (!key) { socket.destroy(); return; }
    const accept = crypto.createHash('sha1').update(String(key) + WS_GUID).digest('base64');
    socket.write([
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Accept: ${accept}`,
      '\r\n'
    ].join('\r\n'));
    setTimeout(() => sendWsText(socket, 'server-hello'), 100);
    let buffer = Buffer.alloc(0);
    socket.on('data', chunk => {
      buffer = Buffer.concat([buffer, chunk]);
      buffer = decodeClientFrames(buffer, text => {
        sendWsText(socket, `echo:${text}`);
      });
    });
    socket.on('error', () => {});
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => resolve());
  });
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  return {
    server,
    port,
    origin: `http://127.0.0.1:${port}`,
    localhostOrigin: `http://localhost:${port}`,
    async close() {
      for (const socket of sockets) socket.destroy();
      sockets.clear();
      await new Promise(resolve => server.close(resolve));
    }
  };
}

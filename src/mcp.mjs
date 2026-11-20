import { compactJson, redactText } from './security.mjs';

const ACCEPTED_PROTOCOLS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26'];
const MAX_INPUT_BYTES = 8_000_000;

function protocolVersion(requested) {
  return ACCEPTED_PROTOCOLS.includes(requested) ? requested : ACCEPTED_PROTOCOLS[1];
}

export function runStdioServer({ registry, manager, version = '0.2.0', logger = console }) {
  const maxResponse = (() => {
    const raw = Number(process.env.DEVTOOLS_MAX_RESPONSE_CHARS);
    return Number.isInteger(raw) ? Math.max(10_000, Math.min(500_000, raw)) : 60_000;
  })();

  const write = (message) => {
    process.stdout.write(`${JSON.stringify(message)}\n`);
  };
  const reply = (id, resultValue) => write({ jsonrpc: '2.0', id, result: resultValue });
  const rpcError = (id, code, message) => write({ jsonrpc: '2.0', id, error: { code, message } });
  const log = (...parts) => logger.error?.(...parts);

  function toToolResult(value) {
    if (value && Array.isArray(value.content)) return value;
    return { content: [{ type: 'text', text: compactJson(value, maxResponse) }] };
  }

  async function handleRequest(message) {
    if (message == null || typeof message !== 'object' || message.jsonrpc !== '2.0') return;
    if (!Object.hasOwn(message, 'id')) return; // client notification
    const { id, method, params = {} } = message;
    if (typeof method !== 'string') { rpcError(id, -32600, 'Invalid request'); return; }
    if (method === 'initialize') {
      reply(id, {
        protocolVersion: protocolVersion(params.protocolVersion),
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'toolnet-devtools-mcp', version },
        instructions: [
          'Universal Chrome DevTools MCP for any HTTP/HTTPS site. Fully automatic CDP control: no manual tab opening, navigation or reload is required when DEVTOOLS_AUTO_LAUNCH is enabled.',
          'For a complete F12 check from the first byte, call devtools_navigate_and_capture (or devtools_open_url). It ensures Chrome is available, creates a blank tab when needed, attaches CDP and enables Network/Runtime/Page/Log BEFORE navigation, navigates, waits and returns capture data with proof that Network was enabled before navigation.',
          'After capture: devtools_diagnose, devtools_console, devtools_network, devtools_request, devtools_response_body and devtools_websocket for analysis; devtools_click, devtools_type, devtools_scroll, devtools_reload and devtools_select_tab for interaction and multi-tab workflows.',
          'Export with devtools_export format=har or format=report. Default permission is interactive; debugger/tracing/raw CDP require full-debug. Sensitive cookie/token values are redacted by default and require full-debug + DEVTOOLS_ALLOW_SENSITIVE=1 + includeSensitive=true.'
        ].join(' ')
      });
      return;
    }
    if (method === 'ping') { reply(id, {}); return; }
    if (method === 'tools/list') {
      reply(id, { tools: registry.list() });
      return;
    }
    if (method === 'tools/call') {
      if (typeof params?.name !== 'string' || !params.name) {
        rpcError(id, -32602, 'tools/call requires params.name');
        return;
      }
      const tool = registry.get(params.name);
      if (!tool) { rpcError(id, -32602, `Unknown tool: ${params.name}`); return; }
      const started = Date.now();
      try {
        const value = await registry.call(params.name, params.arguments ?? {});
        reply(id, toToolResult(value));
        if (process.env.DEVTOOLS_DEBUG === '1') log(`[toolnet-devtools] tools/call ${params.name} ${Date.now() - started}ms`);
      } catch (error) {
        log(`[toolnet-devtools] tools/call ${params.name} failed: ${redactText(error?.message ?? String(error), 600)}`);
        reply(id, {
          content: [{ type: 'text', text: redactText(error?.message ?? String(error), 4000) }],
          isError: true
        });
      }
      return;
    }
    if (method === 'resources/list') { reply(id, { resources: [] }); return; }
    if (method === 'prompts/list') { reply(id, { prompts: [] }); return; }
    rpcError(id, -32601, `Method not found: ${method}`);
  }

  let stdinBuffer = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', chunk => {
    stdinBuffer += chunk;
    if (Buffer.byteLength(stdinBuffer) > MAX_INPUT_BYTES) {
      stdinBuffer = '';
      log('[toolnet-devtools] Oversized RPC input dropped');
      return;
    }
    for (;;) {
      const newline = stdinBuffer.indexOf('\n');
      if (newline < 0) break;
      const line = stdinBuffer.slice(0, newline).trim();
      stdinBuffer = stdinBuffer.slice(newline + 1);
      if (!line) continue;
      let input;
      try { input = JSON.parse(line); }
      catch { rpcError(null, -32700, 'Parse error'); continue; }
      if (Array.isArray(input)) {
        for (const item of input) void handleRequest(item).catch(error => log('[toolnet-devtools] RPC error:', error?.message));
      } else {
        void handleRequest(input).catch(error => log('[toolnet-devtools] RPC error:', error?.message));
      }
    }
  });

  let shuttingDown = false;
  async function shutdown(code = 0) {
    if (shuttingDown) return;
    shuttingDown = true;
    try { await manager.close(); } catch { /* ignore */ }
    process.exit(code);
  }
  process.on('SIGINT', () => void shutdown(0));
  process.on('SIGTERM', () => void shutdown(0));
  process.stdin.on('end', () => void shutdown(0));
  process.on('uncaughtException', error => {
    log('[toolnet-devtools] uncaught exception:', redactText(error?.stack ?? String(error), 2000));
  });
  process.on('unhandledRejection', error => {
    log('[toolnet-devtools] unhandled rejection:', redactText(error?.stack ?? String(error), 2000));
  });
  log(`[toolnet-devtools] MCP stdio server ready (v${version}, ${registry.tools.size} tools, permission ${registry.ctx.permission})`);
}

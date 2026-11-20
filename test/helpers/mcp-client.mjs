import { spawn } from 'node:child_process';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SERVER = path.join(ROOT, 'src/index.mjs');

export class McpClient {
  constructor({ env = {}, command = process.execPath, args = [SERVER], cwd = ROOT } = {}) {
    this.child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe']
    });
    this.pending = new Map();
    this.nextId = 0;
    this.stderr = '';
    this.notifications = [];
    this.exited = null;
    this.child.stderr.on('data', chunk => { this.stderr += String(chunk); });
    this.rl = readline.createInterface({ input: this.child.stdout });
    this.rl.on('line', line => this.onLine(line));
    this.exitPromise = new Promise(resolve => {
      this.child.once('exit', (code, signal) => {
        this.exited = { code, signal };
        for (const pending of this.pending.values()) {
          clearTimeout(pending.timer);
          pending.reject(new Error(`MCP server exited: ${code ?? signal}\n${this.stderr}`));
        }
        this.pending.clear();
        resolve(this.exited);
      });
    });
  }

  onLine(line) {
    if (!line.trim()) return;
    let msg;
    try { msg = JSON.parse(line); }
    catch { this.stderr += `\n[invalid stdout] ${line}`; return; }
    if (msg.id == null) { this.notifications.push(msg); return; }
    const pending = this.pending.get(msg.id);
    if (!pending) return;
    clearTimeout(pending.timer);
    this.pending.delete(msg.id);
    if (msg.error) pending.reject(new Error(`${msg.error.message} (${msg.error.code})`));
    else pending.resolve(msg.result);
  }

  request(method, params = {}, timeoutMs = 120_000) {
    const id = ++this.nextId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`MCP request timeout: ${method}${this.stderr ? `\n${this.stderr.slice(-2000)}` : ''}`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    });
  }

  async initialize() {
    const result = await this.request('initialize', {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'toolnet-integration-test', version: '1.0.0' }
    }, 15_000);
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
    return result;
  }

  async callRaw(name, args = {}, timeoutMs = 120_000) {
    return await this.request('tools/call', { name, arguments: args }, timeoutMs);
  }

  async call(name, args = {}, timeoutMs = 120_000) {
    const result = await this.callRaw(name, args, timeoutMs);
    if (result?.isError) {
      throw new Error(`Tool ${name} failed: ${result.content?.map(item => item.text).join(' ')}`);
    }
    const text = result?.content?.find(item => item.type === 'text')?.text;
    if (text == null) return result;
    try { return JSON.parse(text); }
    catch { return { text }; }
  }

  async close() {
    if (this.exited) return this.exited;
    this.child.stdin.end();
    this.child.kill('SIGTERM');
    const result = await Promise.race([
      this.exitPromise,
      new Promise(resolve => setTimeout(() => resolve(null), 5000))
    ]);
    if (!result) {
      this.child.kill('SIGKILL');
      await this.exitPromise;
    }
    this.rl.close();
    return this.exited;
  }
}

export { ROOT, SERVER };

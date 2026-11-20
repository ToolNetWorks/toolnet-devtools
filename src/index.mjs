#!/usr/bin/env node
import { BrowserManager } from './browser.mjs';
import { runStdioServer } from './mcp.mjs';
import { normalizePermission } from './security.mjs';
import { registerTools } from './tools/index.mjs';
import { createRegistry } from './tools/registry.mjs';

const VERSION = '0.2.0';

function main() {
  let permission;
  try {
    permission = normalizePermission();
  } catch (error) {
    console.error(`[toolnet-devtools] ${error.message}`);
    process.exit(2);
  }
  const manager = new BrowserManager({
    endpoint: process.env.CDP_ENDPOINT || 'http://127.0.0.1:9222',
    permission,
    allowSensitive: process.env.DEVTOOLS_ALLOW_SENSITIVE === '1',
    autoLaunch: process.env.DEVTOOLS_AUTO_LAUNCH !== '0',
    headless: process.env.DEVTOOLS_HEADLESS !== '0'
  });
  const registry = createRegistry({
    manager,
    permission,
    allowSensitive: process.env.DEVTOOLS_ALLOW_SENSITIVE === '1',
    version: VERSION
  });
  registerTools(registry);
  runStdioServer({ registry, manager, version: VERSION });
}

main();

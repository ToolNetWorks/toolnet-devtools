import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ChromeSession, LIMITS, sleep } from './cdp.mjs';
import { buildSessionDiagnostics } from './diagnostics.mjs';
import {
  isAllowedEndpoint,
  normalizeEndpoint,
  normalizePageUrl,
  permissionAtLeast
} from './security.mjs';

const DEFAULT_ENDPOINT = 'http://127.0.0.1:9222';
const CHROME_CANDIDATES = [
  process.env.CHROME_PATH,
  process.env.CHROME_BIN,
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/snap/bin/chromium',
  '/opt/google/chrome/chrome',
  '/usr/local/bin/chromium',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe'
].filter(Boolean);

function isExecutable(file) {
  try {
    fs.accessSync(file, fs.constants.X_OK);
    return fs.statSync(file).isFile();
  } catch {
    return false;
  }
}

export function findChromeBinary() {
  for (const candidate of CHROME_CANDIDATES) {
    if (isExecutable(candidate)) return candidate;
  }
  for (const name of ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser', 'chrome']) {
    try {
      const found = execFileSync('which', [name], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
      if (found && isExecutable(found)) return found;
    } catch { /* try next */ }
  }
  return null;
}

function parseExtraArgs(raw = '') {
  if (!raw.trim()) return [];
  return (raw.match(/"[^"]*"|'[^']*'|\S+/g) ?? []).map(token => token.replace(/^["']|["']$/g, ''));
}

function chromeArgs({ port, profileDir, headlessFlag, endpoint }) {
  const host = new URL(endpoint).hostname;
  const args = [
    `--remote-debugging-address=${host}`,
    `--remote-debugging-port=${port}`,
    `--user-data-dir=${profileDir}`,
    '--remote-allow-origins=*',
    '--no-first-run',
    '--no-default-browser-check',
    '--noerrdialogs',
    '--disable-background-networking',
    '--disable-component-update',
    '--disable-sync',
    '--disable-extensions',
    '--disable-popup-blocking',
    '--disable-notifications',
    '--disable-background-timer-throttling',
    '--disable-renderer-backgrounding',
    '--disable-backgrounding-occluded-windows',
    '--disable-dev-shm-usage',
    '--mute-audio',
    '--window-size=1440,900'
  ];
  if (headlessFlag) args.push(headlessFlag, '--disable-gpu');
  if (process.platform === 'linux' && headlessFlag) args.push('--ozone-platform=headless');
  if (process.getuid?.() === 0 || process.env.DEVTOOLS_NO_SANDBOX === '1') args.push('--no-sandbox');
  if (process.env.DEVTOOLS_CHROME_ARGS) args.push(...parseExtraArgs(process.env.DEVTOOLS_CHROME_ARGS));
  args.push('about:blank');
  return args;
}

export class BrowserManager {
  constructor(options = {}) {
    const rawEndpoint = options.endpoint ?? process.env.CDP_ENDPOINT ?? DEFAULT_ENDPOINT;
    this.endpoint = normalizeEndpoint(rawEndpoint);
    if (!isAllowedEndpoint(this.endpoint)) throw new Error('Unsafe CDP endpoint');
    this.permission = options.permission ?? 'interactive';
    this.allowSensitive = options.allowSensitive === true;
    this.autoLaunch = options.autoLaunch ?? process.env.DEVTOOLS_AUTO_LAUNCH !== '0';
    this.headless = options.headless ?? process.env.DEVTOOLS_HEADLESS !== '0';
    this.logger = options.logger ?? console;
    this.autoDismissDialogs = options.autoDismissDialogs ?? process.env.DEVTOOLS_AUTO_DISMISS_DIALOGS === '1';
    this.captureBodies = options.captureBodies ?? process.env.DEVTOOLS_CAPTURE_BODIES !== '0';
    this.exportDir = options.exportDir ?? process.env.DEVTOOLS_EXPORT_DIR ?? path.join(os.tmpdir(), 'toolnet-devtools-exports');
    this.sessions = new Map();
    this.activeTabId = null;
    this.transport = new ChromeSession(this.endpoint, { captureBodies: false, logger: this.logger });
    this.launchProcess = null;
    this.launchedByUs = false;
    this.launchPromise = null;
    this.launchLogPath = null;
    this.reachability = { checkedAt: 0, value: null };
    this.locks = new Map();
    this.closed = false;
  }

  sessionOptions() {
    return {
      allowSensitive: this.allowSensitive,
      captureBodies: this.captureBodies,
      autoDismissDialogs: this.autoDismissDialogs,
      logger: this.logger
    };
  }

  async checkReachable({ force = false, timeoutMs = 2500 } = {}) {
    if (!force && Date.now() - this.reachability.checkedAt < 1500) return this.reachability.value;
    try {
      const res = await fetch(`${this.endpoint}/json/version`, { signal: AbortSignal.timeout(timeoutMs) });
      if (!res.ok) {
        this.reachability = { checkedAt: Date.now(), value: null };
        return null;
      }
      const value = await res.json();
      this.reachability = { checkedAt: Date.now(), value };
      return value;
    } catch {
      this.reachability = { checkedAt: Date.now(), value: null };
      return null;
    }
  }

  async browserInfo() {
    if (!(await this.checkReachable()) && this.autoLaunch) {
      try { await this.ensureBrowser(); } catch { return null; }
    }
    const version = await this.checkReachable({ force: true });
    if (!version) return null;
    return {
      browser: version.Browser,
      protocolVersion: version['Protocol-Version'],
      userAgent: version['User-Agent'],
      webSocketDebuggerUrl: undefined
    };
  }

  async ensureBrowser() {
    if (this.closed) throw new Error('Browser manager is closed');
    const info = await this.checkReachable({ force: true });
    if (info) return info;
    if (!this.autoLaunch) {
      throw new Error(
        `No Chrome/Chromium CDP endpoint at ${this.endpoint}. Start Chrome with ` +
        '`--remote-debugging-port=9222 --user-data-dir=<isolated profile>` or set DEVTOOLS_AUTO_LAUNCH=1.'
      );
    }
    if (!['127.0.0.1', 'localhost', '::1', '[::1]'].includes(new URL(this.endpoint).hostname)) {
      throw new Error('Auto-launch is only supported for loopback CDP endpoints');
    }
    return await this.launchBrowser();
  }

  async launchBrowser() {
    if (this.launchPromise) return await this.launchPromise;
    this.launchPromise = this.launchBrowserInternal().finally(() => { this.launchPromise = null; });
    return await this.launchPromise;
  }

  async launchBrowserInternal() {
    const binary = findChromeBinary();
    if (!binary) {
      throw new Error(
        'Chrome/Chromium executable not found. Install Chrome or set CHROME_PATH. ' +
        'Auto-launch is unavailable without a local browser.'
      );
    }
    const port = new URL(this.endpoint).port || '80';
    const profileDir = process.env.DEVTOOLS_PROFILE_DIR || path.join(os.tmpdir(), `toolnet-devtools-profile-${port}`);
    await fsp.mkdir(profileDir, { recursive: true });
    this.launchLogPath = path.join(profileDir, 'chrome-launch.log');
    const flags = this.headless ? ['--headless=new', '--headless'] : [null];
    let lastError = null;
    for (const flag of flags) {
      try {
        const args = chromeArgs({ port, profileDir, headlessFlag: flag, endpoint: this.endpoint });
        this.logger?.error?.(`[toolnet-devtools] launching ${binary} on ${this.endpoint} (${flag ?? 'headed'})`);
        const child = spawn(binary, args, { stdio: ['ignore', 'ignore', 'pipe'] });
        this.launchProcess = child;
        this.launchedByUs = true;
        let spawnError = null;
        const logStream = fs.createWriteStream(this.launchLogPath, { flags: 'a' });
        child.once('error', error => {
          spawnError = error;
          logStream.write(`[spawn error] ${error?.message ?? String(error)}\n`);
          if (this.launchProcess === child) {
            this.launchProcess = null;
            this.launchedByUs = false;
          }
        });
        child.stderr?.on('data', chunk => {
          if (process.env.DEVTOOLS_DEBUG === '1') this.logger?.error?.(String(chunk).trim().slice(0, 1000));
          logStream.write(chunk);
        });
        let exitCode = null;
        child.once('exit', (code, signal) => {
          exitCode = { code, signal };
          logStream.end();
          if (this.launchProcess === child) {
            this.launchProcess = null;
            this.launchedByUs = false;
          }
          if (process.env.DEVTOOLS_DEBUG === '1') this.logger?.error?.(`[toolnet-devtools] Chrome exited (${code ?? signal})`);
        });
        const ready = await this.waitForEndpoint({
          child,
          timeoutMs: Number(process.env.DEVTOOLS_LAUNCH_TIMEOUT || 20_000),
          getSpawnError: () => spawnError
        });
        if (ready) return ready;
        if (spawnError) throw spawnError;
        lastError = new Error(`Chrome did not expose ${this.endpoint} within the launch timeout`);
        if (!exitCode && child.exitCode == null) {
          try { child.kill('SIGTERM'); } catch { /* ignore */ }
          await new Promise(resolve => setTimeout(resolve, 800));
        }
      } catch (error) {
        lastError = error;
      }
    }
    throw new Error(
      `Unable to auto-launch Chrome${lastError ? `: ${lastError.message}` : ''}. ` +
      `Check ${this.launchLogPath} or start Chrome manually on ${this.endpoint}.`
    );
  }

  async waitForEndpoint({ child, timeoutMs, getSpawnError = () => null }) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (getSpawnError()) return null;
      if (child.exitCode != null) return null;
      const info = await this.checkReachable({ force: true, timeoutMs: 1000 });
      if (info) return info;
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    return null;
  }

  async tabs() {
    await this.ensureBrowser();
    const tabs = await this.transport.tabs();
    return tabs.map(({ webSocketDebuggerUrl, ...tab }) => ({
      ...tab,
      attached: this.sessions.get(tab.id)?.connected === true,
      active: this.activeTabId === tab.id
    }));
  }

  status() {
    return {
      endpoint: this.endpoint,
      permission: this.permission,
      autoLaunch: this.autoLaunch,
      launchedByUs: this.launchedByUs,
      activeTabId: this.activeTabId,
      sessions: [...this.sessions.values()].map(session => ({
        sessionId: session.tab?.id,
        tab: session.tab,
        connected: session.connected,
        requests: session.requests.size,
        requestLogEntries: session.requestLog.items.length,
        consoleEntries: session.console.items.length,
        websocketFrames: session.frames.items.length,
        captureReadiness: { ...session.captureReadiness }
      }))
    };
  }

  async attach(tabId, { fresh = true } = {}) {
    await this.ensureBrowser();
    const existing = tabId ? this.sessions.get(tabId) : null;
    if (existing?.connected && !fresh) {
      this.activeTabId = tabId;
      await existing.ensureCaptureEnabled();
      return existing.status();
    }
    const targets = await this.transport.tabs();
    let target = tabId
      ? targets.find(tab => tab.id === tabId)
      : (targets.find(tab => tab.id === this.activeTabId) ?? targets[0]);
    // A fresh browser may expose no page targets at all. Creating an
    // about:blank tab here is what makes devtools_attach safe to call first.
    if (!target) target = await this.transport.createTab('about:blank');
    if (!target) throw new Error(tabId ? `Tab ${tabId} not found` : 'Chrome did not provide a page target');
    if (existing) await existing.close();
    const session = new ChromeSession(this.endpoint, this.sessionOptions());
    await session.attach(target.id, { fresh, target });
    this.sessions.set(target.id, session);
    this.activeTabId = target.id;
    return session.status();
  }

  async attachFirstPage({ fresh = true } = {}) {
    await this.ensureBrowser();
    const targets = await this.transport.tabs();
    let target = this.activeTabId ? targets.find(tab => tab.id === this.activeTabId) : null;
    if (!target) target = targets[0];
    if (!target) target = await this.transport.createTab('about:blank');
    const session = new ChromeSession(this.endpoint, this.sessionOptions());
    await session.attach(target.id, { fresh, target });
    this.sessions.set(target.id, session);
    this.activeTabId = target.id;
    return session;
  }

  async sessionFor(tabId = null) {
    await this.ensureBrowser();
    if (tabId) {
      const session = this.sessions.get(tabId);
      if (session?.connected) {
        this.activeTabId = tabId;
        await session.ensureCaptureEnabled();
        return session;
      }
      const targets = await this.transport.tabs();
      const target = targets.find(tab => tab.id === tabId);
      if (!target) throw new Error(`Tab ${tabId} not found. Call devtools_tabs for current tabs.`);
      if (session) {
        await session.attach(tabId, { fresh: false, target });
        this.activeTabId = tabId;
        return session;
      }
      const created = new ChromeSession(this.endpoint, this.sessionOptions());
      await created.attach(tabId, { fresh: true, target });
      this.sessions.set(tabId, created);
      this.activeTabId = tabId;
      return created;
    }
    if (this.activeTabId) {
      const active = this.sessions.get(this.activeTabId);
      if (active?.connected) {
        await active.ensureCaptureEnabled();
        return active;
      }
    }
    for (const [id, session] of this.sessions) {
      if (session.connected) {
        this.activeTabId = id;
        await session.ensureCaptureEnabled();
        return session;
      }
    }
    return await this.attachFirstPage();
  }

  async newTab({ activate = true } = {}) {
    await this.ensureBrowser();
    let target = await this.transport.createTab('about:blank');
    if (!target) throw new Error('Chrome did not create a new page target');
    const session = new ChromeSession(this.endpoint, this.sessionOptions());
    try {
      await session.attach(target.id, { fresh: true, target });
    } catch (error) {
      // /json/new can return before the target is visible in /json/list.
      // Give Chrome a moment, then resolve the target by URL and retry once.
      await sleep(150);
      const targets = await this.transport.tabs();
      target = targets.find(tab => tab.id === target.id)
        ?? targets.find(tab => tab.url === 'about:blank' && !this.sessions.has(tab.id));
      if (!target) throw error;
      await session.attach(target.id, { fresh: true, target });
    }
    this.sessions.set(target.id, session);
    this.activeTabId = target.id;
    if (activate) await this.transport.activateTab(target.id).catch(() => {});
    return { sessionId: target.id, tab: session.tab, capture: session.status() };
  }

  async openUrl(rawUrl, options = {}) {
    return await this.navigateAndCapture(rawUrl, options);
  }

  async navigateAndCapture(rawUrl, {
    tabId = null,
    newTab = true,
    waitUntil = 'load',
    timeoutMs = 30_000,
    settleMs = 400,
    networkIdleWaitMs = 1000,
    clearFirst = true,
    slowMs = 1500,
    includeDiagnostics = true,
    requestLimit = 50
  } = {}) {
    const url = normalizePageUrl(rawUrl);
    const lockKey = tabId ?? (newTab ? `navigate-and-capture-${Date.now()}-${Math.random().toString(16).slice(2)}` : 'navigate-and-capture-active');
    return await this.withLock(lockKey, async () => {
      await this.ensureBrowser();
      let session;
      let createdNewTab = false;
      if (tabId) {
        session = await this.sessionFor(tabId);
        if (clearFirst) session.clearAll();
      } else if (newTab) {
        const created = await this.newTab({ activate: true });
        session = this.sessions.get(created.sessionId);
        createdNewTab = true;
      } else {
        session = await this.sessionFor();
        if (clearFirst) session.clearAll();
      }
      if (!session) throw new Error('Unable to create or attach a page session');

      // Capture domains must be live before Page.navigate. attach() already
      // enables them, and this second call is an explicit readiness barrier.
      const captureReadiness = await session.ensureCaptureEnabled();
      const readinessBeforeNavigation = { ...captureReadiness };
      const requestCountBefore = session.requestLog.items.length;
      const navigation = await session.navigate(url, { waitUntil, timeoutMs });
      this.activeTabId = session.tab?.id ?? this.activeTabId;
      if (settleMs > 0) await sleep(Math.min(10_000, Number(settleMs) || 0));
      let networkIdleReached = null;
      const quietWindow = Math.max(0, Number(networkIdleWaitMs) || 0);
      if (quietWindow > 0) {
        // Wait for a continuous quiet window instead of a single instant.
        // This catches XHR/fetch calls scheduled shortly after load (analytics,
        // hydration, lazy data) without requiring a manual reload.
        networkIdleReached = await session.waitForNetworkIdle({
          idleMs: Math.max(100, quietWindow),
          timeoutMs: Math.min(15_000, Math.max(2000, quietWindow * 2))
        });
      }
      const capture = session.status();
      const diagnostics = includeDiagnostics
        ? buildSessionDiagnostics(session, {
            slowMs,
            requestLimit,
            consoleLimit: 20,
            websocketLimit: 10,
            includeRequests: true
          })
        : undefined;
      return {
        sessionId: session.tab?.id,
        tab: session.tab,
        createdNewTab,
        navigation,
        captureReadiness: readinessBeforeNavigation,
        verified: {
          networkEnabledBeforeNavigation: readinessBeforeNavigation.networkEnabled === true &&
            navigation.networkEnabledBeforeNavigation === true &&
            Boolean(readinessBeforeNavigation.networkEnabledAt) &&
            Boolean(navigation.navigationStartedAt) &&
            Date.parse(readinessBeforeNavigation.networkEnabledAt) <= Date.parse(navigation.navigationStartedAt),
          runtimeEnabledBeforeNavigation: readinessBeforeNavigation.runtimeEnabled === true,
          pageEnabledBeforeNavigation: readinessBeforeNavigation.pageEnabled === true,
          readyAt: readinessBeforeNavigation.readyAt,
          navigationStartedAt: navigation.navigationStartedAt
        },
        requestCountBefore,
        requestCountAfter: session.requestLog.items.length,
        networkIdleReached,
        capture,
        diagnostics,
        nextSteps: [
          'The returned diagnostics already summarize console errors, failed/slow requests, WebSocket activity and page state.',
          'Call devtools_console or devtools_network with afterSequence to inspect new activity.',
          'Call devtools_request and devtools_response_body for a specific request.',
          'Call devtools_export with format har or format report to write a forensic capture file.'
        ]
      };
    });
  }

  async selectTab(tabId) {
    await this.ensureBrowser();
    const session = await this.sessionFor(tabId);
    await session.ensureCaptureEnabled();
    this.activeTabId = tabId;
    await this.transport.activateTab(tabId).catch(() => {});
    return { selected: tabId, tab: session.tab, capture: session.status() };
  }

  async closeTab(tabId = this.activeTabId) {
    if (!tabId) throw new Error('No active tab to close');
    const session = this.sessions.get(tabId);
    if (session) {
      await session.close();
      this.sessions.delete(tabId);
    }
    try { await this.transport.closeTab(tabId); }
    catch { /* tab may already be gone */ }
    if (this.activeTabId === tabId) {
      this.activeTabId = [...this.sessions.keys()][0] ?? null;
    }
    return { closed: tabId, activeTabId: this.activeTabId };
  }

  async navigate(rawUrl, { tabId = null, waitUntil = 'load', timeoutMs = 30_000, networkIdleWaitMs = 0 } = {}) {
    const url = normalizePageUrl(rawUrl);
    const session = await this.sessionFor(tabId);
    await session.ensureCaptureEnabled();
    const requestCountBefore = session.requestLog.items.length;
    const navigation = await session.navigate(url, { waitUntil, timeoutMs });
    let networkIdleReached = null;
    const quietWindow = Math.max(0, Number(networkIdleWaitMs) || 0);
    if (quietWindow > 0) {
      networkIdleReached = await session.waitForNetworkIdle({
        idleMs: Math.max(100, quietWindow),
        timeoutMs: Math.min(15_000, Math.max(2000, quietWindow * 2))
      });
    }
    return {
      sessionId: session.tab?.id,
      tab: session.tab,
      navigation,
      requestCountBefore,
      requestCountAfter: session.requestLog.items.length,
      networkIdleReached,
      capture: session.status(),
      diagnostics: buildSessionDiagnostics(session, { includeRequests: true, requestLimit: 30 })
    };
  }

  async reload({ tabId = null, ignoreCache = false, waitUntil = 'load', timeoutMs = 30_000 } = {}) {
    const session = await this.sessionFor(tabId);
    const result = await session.reload({ ignoreCache, waitUntil, timeoutMs });
    return {
      sessionId: session.tab?.id,
      ...result,
      capture: session.status(),
      diagnostics: buildSessionDiagnostics(session, { includeRequests: true, requestLimit: 30 })
    };
  }

  async history(direction, { tabId = null, waitUntil = 'load', timeoutMs = 30_000 } = {}) {
    const session = await this.sessionFor(tabId);
    await session.ensureCaptureEnabled();
    return {
      sessionId: session.tab?.id,
      ...(await session.history(direction, { waitUntil, timeoutMs })),
      capture: session.status()
    };
  }

  async withLock(key, fn) {
    const previous = this.locks.get(key) ?? Promise.resolve();
    const run = previous.catch(() => {}).then(fn);
    const tail = run.then(() => undefined, () => undefined);
    this.locks.set(key, tail);
    try { return await run; }
    finally { if (this.locks.get(key) === tail) this.locks.delete(key); }
  }

  async close() {
    if (this.closed) return;
    this.closed = true;
    for (const session of this.sessions.values()) {
      await session.close().catch(() => {});
    }
    this.sessions.clear();
    this.activeTabId = null;
    const child = this.launchProcess;
    this.launchProcess = null;
    if (child && this.launchedByUs) {
      try { child.kill('SIGTERM'); } catch { /* ignore */ }
      await new Promise(resolve => setTimeout(resolve, 500));
      if (child.exitCode == null) {
        try { child.kill('SIGKILL'); } catch { /* ignore */ }
      }
    }
    this.launchedByUs = false;
  }
}

export { LIMITS };

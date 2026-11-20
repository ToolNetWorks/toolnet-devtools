import { enumStr, flag, result, shape, str, tabIdSchema } from './registry.mjs';

export function registerSessionTools(registry) {
  const { add } = registry;

  add(
    'devtools_tabs',
    'List Chrome page tabs. If no Chrome is reachable and auto-launch is enabled, a headless Chromium is started automatically. No manual tab opening is required.',
    shape(),
    'read-only',
    async (_args, ctx) => {
      const tabs = await ctx.manager.tabs();
      return { endpoint: ctx.manager.endpoint, activeTabId: ctx.manager.activeTabId, tabs };
    }
  );

  add(
    'devtools_attach',
    'Attach CDP to an existing tab and immediately enable Network/Runtime/Log/Page capture. Use devtools_open_url to create a new tab and navigate without missing initial requests.',
    shape({ tabId: tabIdSchema }),
    'read-only',
    async ({ tabId }, ctx) => {
      const status = await ctx.manager.attach(tabId ?? null, { fresh: true });
      return { attached: true, ...status, permission: ctx.permission };
    }
  );

  add(
    'devtools_status',
    'Show browser/session status, permission tier, active tab, buffer sizes, pending requests and capture cursor.',
    shape({ tabId: tabIdSchema }),
    'read-only',
    async ({ tabId }, ctx) => {
      const active = tabId ? await ctx.manager.sessionFor(tabId) : (ctx.manager.activeTabId ? ctx.manager.sessions.get(ctx.manager.activeTabId) : null);
      return {
        ...ctx.manager.status(),
        serverVersion: ctx.version,
        browser: await ctx.manager.browserInfo().catch(() => null),
        activeSession: active?.status() ?? null
      };
    }
  );

  add(
    'devtools_select_tab',
    'Select and activate a specific Chrome tab as the default target for subsequent tools.',
    shape({ tabId: str('Tab ID from devtools_tabs', { minLength: 1 }) }, ['tabId']),
    'interactive',
    async ({ tabId }, ctx) => await ctx.manager.selectTab(tabId)
  );

  add(
    'devtools_close_tab',
    'Close a tab and release its CDP session. Defaults to the active tab.',
    shape({ tabId: tabIdSchema }),
    'interactive',
    async ({ tabId }, ctx) => await ctx.manager.closeTab(tabId ?? ctx.manager.activeTabId)
  );

  add(
    'devtools_page',
    'Read page URL, title, readyState, viewport, scroll position, links/images/forms counts and Chrome layout metrics.',
    shape({ tabId: tabIdSchema }),
    'read-only',
    async ({ tabId }, ctx) => {
      const session = await ctx.session(tabId);
      const info = await session.pageInfo();
      let layout = null;
      try { layout = await session.send('Page.getLayoutMetrics'); } catch { /* optional */ }
      return { sessionId: session.tab?.id, ...info, layout };
    }
  );

  add(
    'devtools_screenshot',
    'Capture a PNG or JPEG screenshot of the attached tab. Use only when visual inspection is needed.',
    shape({
      tabId: tabIdSchema,
      format: enumStr('Image format', ['png', 'jpeg']),
      quality: { type: 'integer', description: 'JPEG quality 1-100', minimum: 1, maximum: 100 },
      fullPage: flag('Capture content beyond the viewport')
    }),
    'read-only',
    async ({ tabId, format = 'png', quality = 80, fullPage = false }, ctx) => {
      const session = await ctx.session(tabId);
      const shot = await session.screenshot({ format, quality, fullPage });
      return { content: [{ type: 'image', mimeType: `image/${shot.format}`, data: shot.data }] };
    }
  );

  add(
    'devtools_dialog',
    'Inspect or handle JavaScript alert/confirm/prompt dialogs without hanging the page.',
    shape({
      tabId: tabIdSchema,
      action: enumStr('Dialog action', ['list', 'accept', 'dismiss'], { default: 'list' }),
      promptText: str('Text for a prompt dialog when accepting', { maxLength: 2000 })
    }),
    'interactive',
    async ({ tabId, action = 'list', promptText }, ctx) => {
      const session = await ctx.session(tabId);
      if (action === 'list') {
        return { dialogs: session.dialogs.items, open: session.dialogs.items.filter(dialog => !dialog.handled) };
      }
      return await session.handleJavaScriptDialog({ accept: action === 'accept', promptText });
    }
  );

  add(
    'devtools_clear',
    'Clear captured Console, Network, WebSocket, debugger-script or dialog buffers. This does not delete Chrome/browser data.',
    shape({
      tabId: tabIdSchema,
      scope: enumStr('Buffer to clear', ['all', 'console', 'network', 'websocket', 'scripts', 'dialogs'], { default: 'all' })
    }),
    'interactive',
    async ({ tabId, scope = 'all' }, ctx) => {
      const session = await ctx.session(tabId);
      if (scope === 'all' || scope === 'console') session.console.clear();
      if (scope === 'all' || scope === 'network') { session.requests.clear(); session.requestLog.clear(); session.cachedBodyBytes = 0; }
      if (scope === 'all' || scope === 'websocket') { session.frames.clear(); session.wsConnections.clear(); }
      if (scope === 'all' || scope === 'scripts') session.scripts.clear();
      if (scope === 'all' || scope === 'dialogs') session.dialogs.clear();
      return { cleared: scope, sequence: session.seq, status: session.status() };
    }
  );
}

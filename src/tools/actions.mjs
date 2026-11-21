import { assertPermission, normalizePageUrl, redactJsonish, redactText } from '../security.mjs';
import { enumStr, flag, num, result, shape, str, tabIdSchema } from './registry.mjs';

const WAIT_UNTIL = ['load', 'domcontentloaded', 'networkidle0', 'networkidle2', 'none'];

function timeoutValue(value, fallback = 30_000) {
  return Number.isInteger(value) ? Math.max(500, Math.min(120_000, value)) : fallback;
}

function lockKey(ctx, tabId) {
  return tabId ?? ctx.manager.activeTabId ?? 'active-tab';
}

export function registerActionTools(registry) {
  const { add } = registry;

  const navigateAndCaptureSchema = shape({
    url: str('Any http:// or https:// URL', { minLength: 1, maxLength: 8192 }),
    tabId: tabIdSchema,
    newTab: flag('Create a new blank tab (default true). Set false to reuse the active tab when tabId is omitted.'),
    waitUntil: enumStr('Navigation completion condition', WAIT_UNTIL, { default: 'load' }),
    timeoutMs: num('Navigation timeout in ms (500-120000)', { minimum: 500, maximum: 120_000 }),
    settleMs: num('Extra wait after navigation to collect initial requests (0-10000)', { minimum: 0, maximum: 10_000 }),
    networkIdleWaitMs: num('Continuous network-quiet window in ms after load, so delayed XHR/fetch calls are captured (0 disables, max 10000)', { minimum: 0, maximum: 10_000 }),
    clearFirst: flag('Clear existing buffers before reusing a tab (default true)'),
    slowMs: num('Slow-request threshold used in the returned diagnostics (1-120000)', { minimum: 1, maximum: 120_000 }),
    includeDiagnostics: flag('Include console/network/WebSocket diagnostics in the result (default true)'),
    requestLimit: num('Maximum request rows in diagnostics (1-200)', { minimum: 1, maximum: 200 })
  }, ['url']);

  async function runNavigateAndCapture(args, ctx) {
    return await ctx.manager.navigateAndCapture(normalizePageUrl(args.url), {
      tabId: args.tabId,
      newTab: args.newTab ?? true,
      waitUntil: args.waitUntil ?? 'load',
      timeoutMs: timeoutValue(args.timeoutMs),
      settleMs: args.settleMs ?? 400,
      networkIdleWaitMs: args.networkIdleWaitMs ?? 1000,
      clearFirst: args.clearFirst ?? true,
      slowMs: args.slowMs ?? 1500,
      includeDiagnostics: args.includeDiagnostics ?? true,
      requestLimit: args.requestLimit ?? 50
    });
  }

  add(
    'devtools_navigate_and_capture',
    'PRIMARY one-call F12 workflow for any HTTP/HTTPS URL. Fully automatic: ensures Chrome is available, creates a blank tab when needed, attaches CDP, enables Network/Runtime/Page/Log before navigation, navigates, waits for load/network quiet, and returns captured console/network/WebSocket data plus diagnostics and proof that Network was enabled before navigation. Never ask the user to open a tab, navigate, reload or click manually.',
    navigateAndCaptureSchema,
    'interactive',
    async (args, ctx) => await runNavigateAndCapture(args, ctx)
  );

  add(
    'devtools_open_url',
    'Open any HTTP/HTTPS URL with automatic full capture. Alias of devtools_navigate_and_capture: creates a blank tab, attaches CDP, enables Network/Runtime/Log/Page BEFORE navigating, then waits for the page so initial document/API requests are never missed.',
    navigateAndCaptureSchema,
    'interactive',
    async (args, ctx) => await runNavigateAndCapture(args, ctx)
  );

  add(
    'devtools_f12_check',
    'One-call end-to-end F12 inspection for any URL. Runs the complete automatic workflow (Chrome launch/attach, blank tab, Network/Runtime/Page enabled BEFORE navigation, navigate, wait for delayed requests) and returns console errors, network failures, slow requests, WebSocket activity, page state and performance metrics. Use this when the user says "check F12", "inspect this site" or gives a URL to debug. No manual browser steps are required.',
    navigateAndCaptureSchema,
    'interactive',
    async (args, ctx) => {
      const result = await runNavigateAndCapture({ ...args, includeDiagnostics: true }, ctx);
      let performance = null;
      try {
        const session = await ctx.manager.sessionFor(result.sessionId);
        performance = await session.performanceMetrics();
      } catch { /* metrics are optional */ }
      return {
        ...result,
        f12: {
          ...result.diagnostics,
          performance
        }
      };
    }
  );

  add(
    'devtools_new_tab',
    'Create a blank Chrome tab and attach CDP before any navigation. Use this when the agent wants to control the exact first navigation.',
    shape({ activate: flag('Focus the new Chrome tab (default true)') }),
    'interactive',
    async ({ activate = true }, ctx) => await ctx.manager.withLock('new-tab', () => ctx.manager.newTab({ activate }))
  );

  add(
    'devtools_navigate',
    'Navigate the active or specified tab to any HTTP/HTTPS URL. Capture continues on the same session.',
    shape({
      url: str('Any http:// or https:// URL', { minLength: 1, maxLength: 8192 }),
      tabId: tabIdSchema,
      waitUntil: enumStr('Navigation completion condition', WAIT_UNTIL, { default: 'load' }),
      timeoutMs: num('Timeout in ms (500-120000)', { minimum: 500, maximum: 120_000 }),
      networkIdleWaitMs: num('Continuous network-quiet window in ms after load (0 disables, max 10000)', { minimum: 0, maximum: 10_000 })
    }, ['url']),
    'interactive',
    async ({ url, tabId, waitUntil = 'load', timeoutMs, networkIdleWaitMs = 0 }, ctx) => {
      const target = normalizePageUrl(url);
      return await ctx.manager.withLock(lockKey(ctx, tabId), () =>
        ctx.manager.navigate(target, {
          tabId,
          waitUntil,
          timeoutMs: timeoutValue(timeoutMs),
          networkIdleWaitMs
        })
      );
    }
  );

  add(
    'devtools_reload',
    'Reload the active or specified tab, optionally bypassing the cache.',
    shape({
      tabId: tabIdSchema,
      ignoreCache: flag('Bypass the HTTP cache'),
      waitUntil: enumStr('Completion condition', WAIT_UNTIL, { default: 'load' }),
      timeoutMs: num('Timeout in ms (500-120000)', { minimum: 500, maximum: 120_000 })
    }),
    'interactive',
    async ({ tabId, ignoreCache = false, waitUntil = 'load', timeoutMs }, ctx) => {
      return await ctx.manager.withLock(lockKey(ctx, tabId), () =>
        ctx.manager.reload({ tabId, ignoreCache, waitUntil, timeoutMs: timeoutValue(timeoutMs) })
      );
    }
  );

  add(
    'devtools_history',
    'Move back or forward in the tab navigation history.',
    shape({
      tabId: tabIdSchema,
      direction: enumStr('History direction', ['back', 'forward'], { default: 'back' }),
      waitUntil: enumStr('Completion condition', WAIT_UNTIL, { default: 'load' }),
      timeoutMs: num('Timeout in ms (500-120000)', { minimum: 500, maximum: 120_000 })
    }),
    'interactive',
    async ({ tabId, direction = 'back', waitUntil = 'load', timeoutMs }, ctx) => {
      return await ctx.manager.withLock(lockKey(ctx, tabId), () =>
        ctx.manager.history(direction, { tabId, waitUntil, timeoutMs: timeoutValue(timeoutMs) })
      );
    }
  );

  const locatorSchema = {
    tabId: tabIdSchema,
    selector: str('CSS selector', { maxLength: 2000 }),
    xpath: str('XPath expression', { maxLength: 2000 }),
    text: str('Visible text/aria-label/title contains', { maxLength: 1000 }),
    role: str('ARIA role or implicit role', { maxLength: 100 }),
    name: str('Accessible name contains (used with role/text)', { maxLength: 1000 }),
    testId: str('data-testid/data-test-id', { maxLength: 200 })
  };
  function pickLocator(args) {
    const locator = { selector: args.selector, xpath: args.xpath, text: args.text, role: args.role, name: args.name, testId: args.testId };
    const has = Object.values(locator).some(v => typeof v === 'string' && v.trim());
    if (!has) throw new Error('Provide selector, xpath, text, role, or testId');
    return locator.selector && !locator.xpath && !locator.text && !locator.role && !locator.testId ? locator.selector : locator;
  }

  add(
    'devtools_click',
    'Click an element by selector/xpath/text/role/testId using trusted Chrome Input events.',
    shape({
      ...locatorSchema,
      timeoutMs: num('Wait for visible element (500-30000)', { minimum: 500, maximum: 30_000 }),
      settleMs: num('Wait after click (0-10000)', { minimum: 0, maximum: 10_000 })
    }),
    'interactive',
    async (args, ctx) => {
      const locator = pickLocator(args);
      return await ctx.manager.withLock(lockKey(ctx, args.tabId), async () => {
        const session = await ctx.session(args.tabId);
        return { sessionId: session.tab?.id, ...(await session.click(locator, { timeoutMs: timeoutValue(args.timeoutMs, 10_000), settleMs: args.settleMs ?? 250 })) };
      });
    }
  );

  add(
    'devtools_type',
    'Focus an input/textarea/contenteditable (optional selector) and insert text, with optional clearing and Enter submission.',
    shape({
      tabId: tabIdSchema,
      selector: str('CSS selector. Omit to type into the focused element.', { maxLength: 2000 }),
      text: str('Text to insert', { maxLength: 20_000 }),
      clear: flag('Clear the field before typing (default true)'),
      submit: flag('Press Enter after typing'),
      timeoutMs: num('Wait for element (500-30000)', { minimum: 500, maximum: 30_000 }),
      settleMs: num('Wait after typing (0-10000)', { minimum: 0, maximum: 10_000 })
    }, ['text']),
    'interactive',
    async ({ tabId, selector = null, text, clear = true, submit = false, timeoutMs = 10_000, settleMs = 150 }, ctx) => {
      if (typeof text !== 'string') throw new Error('text is required');
      return await ctx.manager.withLock(lockKey(ctx, tabId), async () => {
        const session = await ctx.session(tabId);
        return { sessionId: session.tab?.id, ...(await session.typeText(selector, text, { clear, submit, timeoutMs, settleMs })) };
      });
    }
  );

  add(
    'devtools_press_key',
    'Dispatch a keyboard key such as Enter, Tab, Escape, Backspace or ArrowDown with optional modifiers.',
    shape({
      tabId: tabIdSchema,
      key: str('DOM key name', { minLength: 1 }),
      ctrl: flag('Hold Control'),
      shift: flag('Hold Shift'),
      alt: flag('Hold Alt'),
      meta: flag('Hold Meta/Command')
    }, ['key']),
    'interactive',
    async ({ tabId, key, ctrl = false, shift = false, alt = false, meta = false }, ctx) => {
      let modifiers = 0;
      if (alt) modifiers |= 1;
      if (ctrl) modifiers |= 2;
      if (meta) modifiers |= 4;
      if (shift) modifiers |= 8;
      return await ctx.manager.withLock(lockKey(ctx, tabId), async () => {
        const session = await ctx.session(tabId);
        return { sessionId: session.tab?.id, ...(await session.pressKey(key, { modifiers })), page: await session.pageInfo() };
      });
    }
  );

  add(
    'devtools_scroll',
    'Scroll the page with a trusted mouse-wheel event. Optionally scroll a selector into view first.',
    shape({
      tabId: tabIdSchema,
      selector: str('CSS selector to scroll into view', { maxLength: 2000 }),
      x: num('Viewport X coordinate (default center)', { minimum: 0, maximum: 20000 }),
      y: num('Viewport Y coordinate (default center)', { minimum: 0, maximum: 20000 }),
      deltaX: num('Horizontal scroll delta', { minimum: -100_000, maximum: 100_000 }),
      deltaY: num('Vertical scroll delta', { minimum: -100_000, maximum: 100_000 }),
      settleMs: num('Wait after scrolling (0-10000)', { minimum: 0, maximum: 10_000 })
    }),
    'interactive',
    async ({ tabId, selector = null, x, y, deltaX = 0, deltaY = 600, settleMs = 200 }, ctx) => {
      return await ctx.manager.withLock(lockKey(ctx, tabId), async () => {
        const session = await ctx.session(tabId);
        return { sessionId: session.tab?.id, ...(await session.scroll({ selector, x, y, deltaX, deltaY, settleMs })) };
      });
    }
  );

  add(
    'devtools_wait',
    'Wait for a selector/locator, a JavaScript condition, network idle or a fixed delay before continuing.',
    shape({
      tabId: tabIdSchema,
      action: enumStr('Wait type', ['selector', 'expression', 'networkidle', 'timeout'], { default: 'selector' }),
      selector: str('CSS selector for action=selector', { maxLength: 2000 }),
      xpath: str('XPath for action=selector', { maxLength: 2000 }),
      text: str('Text locator for action=selector', { maxLength: 1000 }),
      role: str('Role locator for action=selector', { maxLength: 100 }),
      name: str('Accessible name for role/text locator', { maxLength: 1000 }),
      testId: str('data-testid locator for action=selector', { maxLength: 200 }),
      expression: str('JavaScript expression for action=expression', { maxLength: 6000 }),
      timeoutMs: num('Maximum wait (100-120000)', { minimum: 100, maximum: 120_000 }),
      visible: flag('Require the selector to be visible'),
      idleMs: num('Network idle duration (100-30000)', { minimum: 100, maximum: 30_000 })
    }),
    'read-only',
    async (args, ctx) => {
      const session = await ctx.session(args.tabId);
      const timeout = Number.isInteger(args.timeoutMs) ? Math.max(100, Math.min(120_000, args.timeoutMs)) : 10_000;
      const action = args.action ?? 'selector';
      if (action === 'selector') {
        const locator = pickLocator(args);
        const matched = await session.waitForSelector(locator, timeout, { visible: args.visible === true });
        return { sessionId: session.tab?.id, action, locator, matched, timeoutMs: timeout, ...(await session.pageInfo()) };
      }
      if (action === 'expression') {
        if (!args.expression) throw new Error('expression is required for action=expression');
        return { sessionId: session.tab?.id, ...(await session.waitForExpression(args.expression, timeout)) };
      }
      if (action === 'networkidle') {
        const matched = await session.waitForNetworkIdle({ idleMs: args.idleMs ?? 600, timeoutMs: timeout });
        return { sessionId: session.tab?.id, action, matched, idleMs: args.idleMs ?? 600, pendingRequests: session.pendingRequestCount(), ...(await session.pageInfo()) };
      }
      await new Promise(resolve => setTimeout(resolve, timeout));
      return { sessionId: session.tab?.id, action, waitedMs: timeout, ...(await session.pageInfo()) };
    }
  );

  add(
    'devtools_evaluate',
    'Evaluate JavaScript in the page. Read-only by default (throwOnSideEffect); set allowSideEffects=true for mutations in interactive/full-debug mode.',
    shape({
      tabId: tabIdSchema,
      expression: str('JavaScript expression', { minLength: 1, maxLength: 20_000 }),
      allowSideEffects: flag('Permit mutations and await promises (requires interactive)'),
      awaitPromise: flag('Await a returned promise (only with allowSideEffects)'),
      maxChars: num('Maximum result characters (100-100000)', { minimum: 100, maximum: 100_000 })
    }, ['expression']),
    'read-only',
    async ({ tabId, expression, allowSideEffects = false, awaitPromise = false, maxChars = 20_000 }, ctx) => {
      if (typeof expression !== 'string' || !expression.trim()) throw new Error('expression is required');
      if (allowSideEffects) assertPermission(ctx.permission, 'interactive', 'Side-effectful JavaScript evaluation');
      const session = await ctx.session(tabId);
      const raw = await session.send('Runtime.evaluate', {
        expression,
        returnByValue: true,
        generatePreview: true,
        throwOnSideEffect: !allowSideEffects,
        awaitPromise: allowSideEffects && awaitPromise,
        timeout: 10_000
      }, 15_000);
      const value = raw.result?.value ?? raw.result?.description ?? null;
      const text = typeof value === 'string' ? value : JSON.stringify(value);
      return result({
        sessionId: session.tab?.id,
        type: raw.result?.type,
        result: redactJsonish(value),
        truncated: typeof text === 'string' && text.length > maxChars,
        exception: raw.exceptionDetails ? redactText(raw.exceptionDetails.exception?.description ?? raw.exceptionDetails.text, 4000) : null
      }, Math.min(120_000, maxChars + 4_000));
    }
  );

  add(
    'devtools_dom_inspect',
    'Inspect a CSS selector: HTML, attributes, text, box model and computed CSS styles.',
    shape({
      tabId: tabIdSchema,
      selector: str('CSS selector', { minLength: 1, maxLength: 2000 }),
      includeStyles: flag('Include computed CSS values (default true)'),
      includeBoxModel: flag('Include layout box model'),
      includeText: flag('Include visible text (default true)')
    }, ['selector']),
    'read-only',
    async ({ tabId, selector, includeStyles = true, includeBoxModel = false, includeText = true }, ctx) => {
      const session = await ctx.session(tabId);
      await session.send('DOM.enable');
      const { root } = await session.send('DOM.getDocument', { depth: 1 });
      const { nodeId } = await session.send('DOM.querySelector', { nodeId: root.nodeId, selector });
      if (!nodeId) return { found: false, selector };
      const [node, html] = await Promise.all([
        session.send('DOM.describeNode', { nodeId }),
        session.send('DOM.getOuterHTML', { nodeId })
      ]);
      const output = {
        found: true,
        selector,
        nodeName: node.node?.nodeName,
        nodeType: node.node?.nodeType,
        attributes: node.node?.attributes,
        html: redactText(html.outerHTML, 16_000)
      };
      if (includeText) {
        output.text = redactText(await session.evaluateValue(`document.querySelector(${JSON.stringify(selector)})?.innerText ?? ''`).catch(() => ''), 8000);
      }
      if (includeStyles) {
        try {
          await session.send('CSS.enable');
          const { computedStyle } = await session.send('CSS.getComputedStyleForNode', { nodeId });
          output.computedStyles = computedStyle?.slice(0, 200) ?? [];
        } catch (error) { output.styleError = String(error.message); }
      }
      if (includeBoxModel) {
        try {
          const { model } = await session.send('DOM.getBoxModel', { nodeId });
          output.boxModel = model;
        } catch (error) { output.boxModelError = String(error.message); }
      }
      return output;
    }
  );

  add(
    'devtools_dom_query',
    'Query all elements matching a CSS selector and return tag, id, classes, text preview and visibility.',
    shape({
      tabId: tabIdSchema,
      selector: str('CSS selector', { minLength: 1, maxLength: 2000 }),
      limit: num('Max 1-200', { minimum: 1, maximum: 200 }),
      includeAttributes: flag('Include element attributes')
    }, ['selector']),
    'read-only',
    async ({ tabId, selector, limit = 50, includeAttributes = false }, ctx) => {
      const session = await ctx.session(tabId);
      const expression = `(() => {
        const nodes = [...document.querySelectorAll(${JSON.stringify(selector)})].slice(0, ${Math.max(1, Math.min(200, limit))});
        return { total: document.querySelectorAll(${JSON.stringify(selector)}).length, elements: nodes.map(el => {
          const rect = el.getBoundingClientRect();
          return {
            tag: el.tagName?.toLowerCase(),
            id: el.id || undefined,
            classes: el.className && typeof el.className === 'string' ? el.className : undefined,
            text: (el.innerText ?? el.textContent ?? '').trim().slice(0, 300),
            visible: rect.width > 0 && rect.height > 0,
            attributes: ${includeAttributes ? 'Object.fromEntries([...el.attributes].map(a => [a.name, a.value]))' : 'undefined'}
          };
        }) };
      })()`;
      return { sessionId: session.tab?.id, selector, ...(await session.evaluateValue(expression)) };
    }
  );

  add(
    'devtools_hover',
    'Hover over an element by selector/xpath/text/role/testId.',
    shape({ ...locatorSchema, timeoutMs: num('Timeout in ms (500-30000)', { minimum: 500, maximum: 30000 }) }),
    'interactive',
    async (args, ctx) => {
      const locator = pickLocator(args);
      const session = await ctx.manager.sessionFor(args.tabId);
      return { sessionId: session.tab?.id, ...(await session.hover(locator, { timeoutMs: timeoutValue(args.timeoutMs, 10_000) })) };
    }
  );

  add(
    'devtools_dblclick',
    'Double-click an element by selector/xpath/text/role/testId.',
    shape({ ...locatorSchema, timeoutMs: num('Timeout in ms (500-30000)', { minimum: 500, maximum: 30000 }), settleMs: num('Wait after click (0-10000)', { minimum: 0, maximum: 10000 }) }),
    'interactive',
    async (args, ctx) => {
      const locator = pickLocator(args);
      const session = await ctx.manager.sessionFor(args.tabId);
      return { sessionId: session.tab?.id, ...(await session.dblclick(locator, { timeoutMs: timeoutValue(args.timeoutMs, 10_000), settleMs: args.settleMs ?? 250 })) };
    }
  );

  add(
    'devtools_focus',
    'Focus an element by selector/xpath/text/role/testId.',
    shape({ ...locatorSchema, timeoutMs: num('Timeout in ms (500-30000)', { minimum: 500, maximum: 30000 }) }),
    'interactive',
    async (args, ctx) => {
      const locator = pickLocator(args);
      const session = await ctx.manager.sessionFor(args.tabId);
      return { sessionId: session.tab?.id, ...(await session.focus(locator, { timeoutMs: timeoutValue(args.timeoutMs, 10_000) })) };
    }
  );

  add(
    'devtools_select',
    'Select option(s) in a <select> element by value/text/label.',
    shape({
      tabId: tabIdSchema,
      selector: str('CSS selector for a select element', { minLength: 1, maxLength: 2000 }),
      values: { type: 'array', description: 'Values, labels or visible texts to select', items: { type: 'string' } }
    }, ['selector', 'values']),
    'interactive',
    async ({ tabId, selector, values }, ctx) => {
      const session = await ctx.manager.sessionFor(tabId);
      return { sessionId: session.tab?.id, ...(await session.selectOption(selector, values)) };
    }
  );

  add(
    'devtools_drag',
    'Drag from a source element to a target element using trusted mouse events.',
    shape({
      tabId: tabIdSchema,
      source: str('Source CSS selector', { minLength: 1, maxLength: 2000 }),
      target: str('Target CSS selector', { minLength: 1, maxLength: 2000 }),
      timeoutMs: num('Timeout in ms (500-30000)', { minimum: 500, maximum: 30000 })
    }, ['source', 'target']),
    'interactive',
    async ({ tabId, source, target, timeoutMs = 10000 }, ctx) => {
      const session = await ctx.manager.sessionFor(tabId);
      return { sessionId: session.tab?.id, ...(await session.dragAndDrop(source, target, { timeoutMs: timeoutValue(timeoutMs, 10000) })) };
    }
  );

  add(
    'devtools_upload_file',
    'Set files on an <input type=file> element. Paths must be accessible to the Chrome process.',
    shape({
      tabId: tabIdSchema,
      selector: str('CSS selector for file input', { minLength: 1, maxLength: 2000 }),
      files: { type: 'array', description: 'Absolute file paths on the machine running Chrome', items: { type: 'string' } }
    }, ['selector', 'files']),
    'interactive',
    async ({ tabId, selector, files }, ctx) => {
      const session = await ctx.manager.sessionFor(tabId);
      return { sessionId: session.tab?.id, ...(await session.uploadFile(selector, files)) };
    }
  );

  add(
    'devtools_download',
    'Trigger a download by clicking a selector and configure browser download behavior. Files go to downloadPath (default /tmp/opencode/downloads).',
    shape({
      tabId: tabIdSchema,
      selector: str('CSS selector to click for download', { minLength: 1, maxLength: 2000 }),
      downloadPath: str('Directory for downloads on Chrome machine', { maxLength: 2000 }),
      timeoutMs: num('Click timeout ms (500-30000)', { minimum: 500, maximum: 30000 }),
      settleMs: num('Wait after click ms (0-10000)', { minimum: 0, maximum: 10000 })
    }, ['selector']),
    'interactive',
    async ({ tabId, selector, downloadPath, timeoutMs = 15000, settleMs = 1000 }, ctx) => {
      const session = await ctx.manager.sessionFor(tabId);
      return { sessionId: session.tab?.id, ...(await session.downloadViaClick(selector, { timeoutMs: timeoutValue(timeoutMs, 15000), settleMs, downloadPath })) };
    }
  );
}

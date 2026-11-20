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
    clearFirst: flag('Clear existing buffers before reusing a tab (default true)')
  }, ['url']);

  add(
    'devtools_navigate_and_capture',
    'Primary one-call F12 workflow for any HTTP/HTTPS URL. Fully automatic: ensures Chrome is available, creates a blank tab when needed, attaches CDP, enables Network/Runtime/Page/Log before navigation, navigates, then waits and returns captured console/network data with proof that Network was enabled before navigation. No manual tab opening or reload is required.',
    navigateAndCaptureSchema,
    'interactive',
    async ({ url, tabId, newTab = true, waitUntil = 'load', timeoutMs, settleMs = 400, clearFirst = true }, ctx) => {
      return await ctx.manager.navigateAndCapture(normalizePageUrl(url), {
        tabId,
        newTab,
        waitUntil,
        timeoutMs: timeoutValue(timeoutMs),
        settleMs,
        clearFirst
      });
    }
  );

  add(
    'devtools_open_url',
    'Open any HTTP/HTTPS URL with automatic full capture. Alias of devtools_navigate_and_capture: creates a blank tab, attaches CDP, enables Network/Runtime/Log/Page BEFORE navigating, then waits for the page so initial document/API requests are never missed.',
    navigateAndCaptureSchema,
    'interactive',
    async ({ url, tabId, newTab = true, waitUntil = 'load', timeoutMs, settleMs = 400, clearFirst = true }, ctx) => {
      return await ctx.manager.navigateAndCapture(normalizePageUrl(url), {
        tabId,
        newTab,
        waitUntil,
        timeoutMs: timeoutValue(timeoutMs),
        settleMs,
        clearFirst
      });
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
      timeoutMs: num('Timeout in ms (500-120000)', { minimum: 500, maximum: 120_000 })
    }, ['url']),
    'interactive',
    async ({ url, tabId, waitUntil = 'load', timeoutMs }, ctx) => {
      const target = normalizePageUrl(url);
      return await ctx.manager.withLock(lockKey(ctx, tabId), () =>
        ctx.manager.navigate(target, { tabId, waitUntil, timeoutMs: timeoutValue(timeoutMs) })
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

  add(
    'devtools_click',
    'Click a DOM element by CSS selector using trusted Chrome Input events. Returns the element position and page state.',
    shape({
      tabId: tabIdSchema,
      selector: str('CSS selector', { minLength: 1, maxLength: 2000 }),
      timeoutMs: num('Wait for visible element (500-30000)', { minimum: 500, maximum: 30_000 }),
      settleMs: num('Wait after click (0-10000)', { minimum: 0, maximum: 10_000 })
    }, ['selector']),
    'interactive',
    async ({ tabId, selector, timeoutMs = 10_000, settleMs = 250 }, ctx) => {
      return await ctx.manager.withLock(lockKey(ctx, tabId), async () => {
        const session = await ctx.session(tabId);
        return { sessionId: session.tab?.id, ...(await session.click(selector, { timeoutMs, settleMs })) };
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
    'Wait for a CSS selector, a JavaScript condition, network idle or a fixed delay before continuing.',
    shape({
      tabId: tabIdSchema,
      action: enumStr('Wait type', ['selector', 'expression', 'networkidle', 'timeout'], { default: 'selector' }),
      selector: str('CSS selector for action=selector', { maxLength: 2000 }),
      expression: str('JavaScript expression for action=expression', { maxLength: 6000 }),
      timeoutMs: num('Maximum wait (100-120000)', { minimum: 100, maximum: 120_000 }),
      visible: flag('Require the selector to be visible'),
      idleMs: num('Network idle duration (100-30000)', { minimum: 100, maximum: 30_000 })
    }),
    'read-only',
    async ({ tabId, action = 'selector', selector, expression, timeoutMs = 10_000, visible = false, idleMs = 600 }, ctx) => {
      const session = await ctx.session(tabId);
      const timeout = Number.isInteger(timeoutMs) ? Math.max(100, Math.min(120_000, timeoutMs)) : 10_000;
      if (action === 'selector') {
        if (!selector) throw new Error('selector is required for action=selector');
        const matched = await session.waitForSelector(selector, timeout, { visible });
        return { sessionId: session.tab?.id, action, selector, matched, timeoutMs: timeout, ...(await session.pageInfo()) };
      }
      if (action === 'expression') {
        if (!expression) throw new Error('expression is required for action=expression');
        return { sessionId: session.tab?.id, ...(await session.waitForExpression(expression, timeout)) };
      }
      if (action === 'networkidle') {
        const matched = await session.waitForNetworkIdle({ idleMs, timeoutMs: timeout });
        return { sessionId: session.tab?.id, action, matched, idleMs, pendingRequests: session.pendingRequestCount(), ...(await session.pageInfo()) };
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
}

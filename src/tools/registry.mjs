import {
  assertPermission,
  assertSensitiveAllowed,
  boundedInt,
  compactJson,
  permissionAtLeast,
  redactText
} from '../security.mjs';

export const str = (description, extras = {}) => ({ type: 'string', description, ...extras });
export const num = (description, extras = {}) => ({ type: 'integer', description, ...extras });
export const flag = (description) => ({ type: 'boolean', description });
export const enumStr = (description, values, extras = {}) => ({ type: 'string', description, enum: values, ...extras });
export const shape = (properties = {}, required = []) => ({
  type: 'object',
  properties,
  required,
  additionalProperties: false
});
export const tabIdSchema = str('Optional tab/session ID from devtools_tabs or devtools_open_url. Defaults to the active tab.');

export function result(value, maxChars = 40_000) {
  return { content: [{ type: 'text', text: compactJson(value, maxChars) }] };
}

export function clamp(value, min, max, fallback) {
  return boundedInt(value, min, max, fallback);
}

export function createRegistry({ manager, permission, allowSensitive = false, version = '0.4.0', logger = console }) {
  const tools = new Map();
  const ctx = {
    manager,
    permission,
    allowSensitive,
    version,
    logger,
    permissionAtLeast: required => permissionAtLeast(permission, required),
    sensitive(requested) {
      if (!requested) return false;
      assertSensitiveAllowed(permission, true, 'Sensitive data export');
      if (!allowSensitive) {
        throw new Error('Sensitive export is disabled in this server process. Set DEVTOOLS_ALLOW_SENSITIVE=1 and restart the MCP server.');
      }
      return true;
    },
    session(tabId = null) {
      return manager.sessionFor(tabId);
    }
  };

  function add(name, description, inputSchema, minPermission, handler) {
    if (tools.has(name)) throw new Error(`Duplicate tool ${name}`);
    if (!['read-only', 'interactive', 'full-debug'].includes(minPermission)) {
      throw new Error(`Invalid permission tier for ${name}`);
    }
    tools.set(name, { name, description, inputSchema, minPermission, handler });
  }

  async function call(name, args = {}) {
    const tool = tools.get(name);
    if (!tool) throw new Error(`Unknown tool: ${name}`);
    if (args == null || typeof args !== 'object' || Array.isArray(args)) {
      throw new Error('Tool arguments must be an object');
    }
    assertPermission(permission, tool.minPermission, `Tool ${name}`);
    const started = Date.now();
    try {
      const value = await tool.handler(args, ctx);
      if (process.env.DEVTOOLS_DEBUG === '1') logger.error?.(`[toolnet-devtools] ${name} ok ${Date.now() - started}ms`);
      return value;
    } catch (error) {
      logger.error?.(`[toolnet-devtools] ${name} failed: ${redactText(error?.message ?? String(error), 500)}`);
      throw error;
    }
  }

  function list() {
    return [...tools.values()].map(({ name, description, inputSchema, minPermission }) => ({
      name,
      description: `${description}${minPermission === 'read-only' ? '' : ` [permission: ${minPermission}]`}`,
      inputSchema
    }));
  }

  function get(name) {
    return tools.get(name);
  }

  return { tools, add, call, list, get, ctx };
}

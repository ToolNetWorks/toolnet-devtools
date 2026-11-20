import { registerActionTools } from './actions.mjs';
import { registerAdvancedTools } from './advanced.mjs';
import { registerObserveTools } from './observe.mjs';
import { registerSessionTools } from './session.mjs';

export function registerTools(registry) {
  registerSessionTools(registry);
  registerObserveTools(registry);
  registerActionTools(registry);
  registerAdvancedTools(registry);
  return registry;
}

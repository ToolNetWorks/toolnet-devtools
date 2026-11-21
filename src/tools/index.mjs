import { registerReverseTools } from './reverse.mjs';
import { registerProbeTools } from './probe.mjs';
import { registerSecurityProbeTools } from './security-probe.mjs';
import { registerDeepProbeTools } from './deep-probe.mjs';
import { registerActionTools } from './actions.mjs';
import { registerAdvancedTools } from './advanced.mjs';
import { registerObserveTools } from './observe.mjs';
import { registerSessionTools } from './session.mjs';

export function registerTools(registry) {
  // Put the one-call navigation workflow at the top of tools/list so an agent
  // discovers it before the low-level attach tools.
  registerActionTools(registry);
  registerSessionTools(registry);
  registerObserveTools(registry);
  registerAdvancedTools(registry);
  registerReverseTools(registry);
  registerProbeTools(registry);
  registerSecurityProbeTools(registry);
  registerDeepProbeTools(registry);
  return registry;
}

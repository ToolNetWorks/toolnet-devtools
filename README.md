# ToolNet DevTools MCP

[![npm](https://img.shields.io/npm/v/toolnet-devtools-mcp)](https://www.npmjs.com/package/toolnet-devtools-mcp)
[![CI](https://github.com/ToolNetWorks/toolnet-devtools/actions/workflows/ci.yml/badge.svg)](https://github.com/ToolNetWorks/toolnet-devtools/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22-brightgreen)](package.json)

A dependency-free **Chrome DevTools Protocol (CDP) MCP server** for AI coding agents. It gives agents full, automatic browser control over any `http://` or `https://` site — Console, Network, DOM, Debugger, Performance, Storage, and export — without Playwright, Puppeteer, or Selenium.

> **v0.4.0** · 57 MCP tools · Node.js ≥ 22 · Zero runtime dependencies

## Why ToolNet DevTools

| Capability | What it means |
|---|---|
| **One-call F12 capture** | `devtools_f12_check` creates a blank tab, attaches CDP, enables Network/Runtime/Page/Log *before* navigation, loads the URL, and returns console errors, failed/slow requests, WebSocket activity, and capture proof. No manual reload. |
| **Automatic browser lifecycle** | Connects to an existing CDP endpoint or auto-launches an isolated headless Chromium; reuses sessions; shuts down only browsers it launched. |
| **Full DevTools domains** | Console/stack traces, request/response bodies, redirects, timing, WebSocket frames, DOM/CSS, breakpoints, paused-frame eval, metrics, tracing, CPU profiles, cookies/storage. |
| **Real interaction** | Click, type, press keys, scroll, hover, drag, select, upload, download, dialog handling — with selector/xpath/text/role/testId locators. |
| **Reverse engineering & deep analysis** | API pattern/JSON-shape reports, GraphQL discovery + introspection, source-map metadata, Burp Repeater-lite request replay (authorized targets only). |
| **Security & LLM probes** | Passive credential-exposure/auth-gate/attack-surface scans; garak-style Opposite Day/BOM/AntiGPT/reversed-string jailbreak probing for authorized chat UIs. |
| **Safe by default** | Three permission tiers, loopback-only CDP, secret redaction, bounded buffers, confined export directory, sensitive-data gate. |

## Installation

### Requirements

- **Node.js 22+** (uses built-in global `WebSocket` and `fetch`)
- **Chrome or Chromium** installed locally (for auto-launch), or an existing Chrome with CDP enabled
- An **MCP-capable client** (OpenCode, Codex CLI, Claude Desktop, etc.)

### Option A — npm (recommended)

```bash
npm install -g toolnet-devtools-mcp
toolnet-devtools
```

Or run without installing globally:

```bash
npx -y toolnet-devtools-mcp
```

### Option B — from source

```bash
git clone https://github.com/ToolNetWorks/toolnet-devtools.git
cd toolnet-devtools
node src/index.mjs
```

## Quick Start

### 1. Configure your MCP client

**npm / npx (recommended):**

```json
{
  "mcpServers": {
    "toolnet-devtools": {
      "command": "npx",
      "args": ["-y", "toolnet-devtools-mcp"],
      "env": {
        "CDP_ENDPOINT": "http://127.0.0.1:9222",
        "DEVTOOLS_PERMISSION": "interactive"
      }
    }
  }
}
```

**From source:**

```json
{
  "mcpServers": {
    "toolnet-devtools": {
      "command": "node",
      "args": ["/absolute/path/to/toolnet-devtools/src/index.mjs"],
      "env": {
        "CDP_ENDPOINT": "http://127.0.0.1:9222",
        "DEVTOOLS_PERMISSION": "interactive"
      }
    }
  }
}
```

Ready-to-copy configs: [`examples/mcp.json`](examples/mcp.json) · [`examples/opencode.json`](examples/opencode.json) · [`examples/codex.config.toml`](examples/codex.config.toml)

### 2. Run a one-call F12 check

Ask your agent:

```text
Use devtools_f12_check on https://example.com.
```

The server automatically: checks/launches Chrome → creates a blank tab → attaches CDP → enables Network/Runtime/Page/Log **before navigation** → navigates → waits for load + network-quiet → returns capture proof, console errors, failed/slow requests, WebSocket activity, and performance metrics. No manual browser setup required.

## Browser lifecycle and auto-launch

| Behavior | Default |
|---|---|
| Connect to any browser at `CDP_ENDPOINT` | enabled |
| Auto-launch if no browser is reachable | enabled |
| Launched browser mode | headless |
| Reuse existing tabs/sessions | yes |
| Kill auto-launched Chrome when the MCP server exits | yes |
| Kill a Chrome the server did not launch | **never** |

Useful switches:

```json
"env": {
  "CDP_ENDPOINT": "http://127.0.0.1:9222",
  "DEVTOOLS_AUTO_LAUNCH": "0",
  "DEVTOOLS_HEADLESS": "0",
  "CHROME_PATH": "/usr/bin/google-chrome"
}
```

Auto-launch uses a per-port profile under the system temp directory and adds `--no-sandbox` automatically when running as root. Set `DEVTOOLS_PROFILE_DIR` to choose a different profile location.

<details>
<summary>Start Chrome manually with an isolated profile</summary>

Chrome 136+ rejects `--remote-debugging-port` for the ordinary default profile. Use a separate `--user-data-dir`:

```sh
# Linux
google-chrome --remote-debugging-address=127.0.0.1 --remote-debugging-port=9222 \
  --user-data-dir="$HOME/.toolnet-devtools-chrome" about:blank

# macOS
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --remote-debugging-address=127.0.0.1 --remote-debugging-port=9222 \
  --user-data-dir="$HOME/.toolnet-devtools-chrome" about:blank
```

For a headless Linux server add `--headless=new --disable-gpu`. Check `http://127.0.0.1:9222/json/version`.

</details>

## Permissions

Set the tier with `DEVTOOLS_PERMISSION`. The default is `interactive`.

| Tier | Allows |
|---|---|
| `read-only` | Observation, Console/Network/WebSocket reads, DOM queries, page info, screenshots, waits, redacted exports, side-effect-free JavaScript evaluation (`throwOnSideEffect`). |
| `interactive` | Everything in read-only, plus opening/navigating/closing tabs, reload/history, click/type/scroll, dialogs, side-effectful JavaScript, storage listing, capture windows. |
| `full-debug` | Everything, plus raw CDP calls, JavaScript breakpoints and paused-frame evaluation, Chrome tracing, CPU profiles, cookie/storage mutation and raw sensitive-data access. |

`ALLOW_UNSAFE_CDP=1` remains a backward-compatible alias for `full-debug`. `CDP_PERMISSION` is accepted as an alias for `DEVTOOLS_PERMISSION`.

Ordinary navigation and interaction do **not** require `ALLOW_UNSAFE_CDP` or `full-debug`; `interactive` is enough.

## Sensitive data policy

Headers, query parameters, request/response bodies and storage values are redacted by default. Raw values require **all three**:

1. `DEVTOOLS_PERMISSION=full-debug`
2. `DEVTOOLS_ALLOW_SENSITIVE=1` in the MCP process environment
3. The tool argument `includeSensitive=true` (or `confirmSensitive=true` for raw CDP)

```json
"env": {
  "DEVTOOLS_PERMISSION": "full-debug",
  "DEVTOOLS_ALLOW_SENSITIVE": "1"
}
```

Additional behavior:

- `devtools_storage scope=cookies` is scoped to the current tab's HTTP(S) URL unless explicit cookie URLs are supplied.
- Cookie values and localStorage/sessionStorage values are `[REDACTED]` unless the gate above is satisfied.
- `Authorization`, `Cookie`, `Set-Cookie`, API-key and token fields are hidden by default.
- Redaction is best-effort pattern matching, not a guarantee. Do not point this server at production accounts or sensitive data unless you accept that risk.
- Keep the CDP port bound to loopback. `CDP_ALLOW_REMOTE=1` is available but strongly discouraged.

## MCP tools (57)

Tools without a tier note are `read-only`. The current tier is shown in `devtools_status`.

### Sessions, tabs and page

| Tool | Tier | Purpose |
|---|---|---|
| `devtools_tabs` | | List page tabs and auto-start Chrome if needed. |
| `devtools_attach` | | Attach CDP and enable Network/Runtime/Log/Page capture. |
| `devtools_status` | | Browser, permission tier, active tab, buffer sizes and pending work. |
| `devtools_select_tab` | interactive | Make a tab the default target. |
| `devtools_close_tab` | interactive | Close a tab and release its session. |
| `devtools_page` | | URL, title, readyState, viewport, scroll position, element counts and layout metrics. |
| `devtools_screenshot` | | PNG/JPEG screenshot, viewport or full page. |
| `devtools_dialog` | interactive | List, accept or dismiss alert/confirm/prompt dialogs. |
| `devtools_clear` | interactive | Clear console, network, WebSocket, script or dialog buffers. |

### Navigation, input and DOM

| Tool | Tier | Purpose |
|---|---|---|
| `devtools_navigate_and_capture` | interactive | **Primary one-call capture tool**: ensure Chrome, create/attach a blank tab, enable Network/Runtime/Page/Log before navigation, navigate any HTTP/HTTPS URL, wait, and return capture proof/data. |
| `devtools_f12_check` | interactive | **Primary one-call F12 check**: same automatic workflow as `devtools_navigate_and_capture`, plus performance metrics and a ready-to-read diagnostics summary. |
| `devtools_open_url` | interactive | Alias of `devtools_navigate_and_capture` for compatibility and convenience. |
| `devtools_new_tab` | interactive | Create a blank attached tab. |
| `devtools_navigate` | interactive | Navigate the active or named tab (capture domains are ensured enabled). |
| `devtools_reload` | interactive | Reload, optionally bypassing cache. |
| `devtools_history` | interactive | Go back or forward. |
| `devtools_click` | interactive | Click by selector/xpath/text/role/testId with trusted Chrome input events. |
| `devtools_type` | interactive | Focus and type into inputs, optionally clear and submit. |
| `devtools_press_key` | interactive | Send Enter, Tab, Escape, arrows and modifiers. |
| `devtools_scroll` | interactive | Wheel scrolling, optionally after `scrollIntoView`. |
| `devtools_hover` | interactive | Hover by selector/xpath/text/role/testId. |
| `devtools_dblclick` | interactive | Double-click by selector/xpath/text/role/testId. |
| `devtools_focus` | interactive | Focus by selector/xpath/text/role/testId. |
| `devtools_select` | interactive | Select option(s) in a `<select>` by value/text/label. |
| `devtools_drag` | interactive | Drag-and-drop between two selectors. |
| `devtools_upload_file` | interactive | Set files on an `<input type=file>` (paths must be visible to Chrome). |
| `devtools_download` | interactive | Click a download trigger and capture completed files in a download directory. |
| `devtools_wait` | | Wait for a selector/locator, JS expression, network idle or delay. |
| `devtools_evaluate` | | Side-effect-free JS by default; `allowSideEffects=true` requires interactive. |
| `devtools_dom_inspect` | | HTML, attributes, text, computed CSS and box model. |
| `devtools_dom_query` | | Query matching elements with visibility and text previews. |

### Console, network and WebSocket

| Tool | Purpose |
|---|---|
| `devtools_console` | Console logs, warnings, errors, uncaught exceptions, stack traces, filters and sequence cursors. |
| `devtools_network` | Requests with status, type, failure/CORS, duration, bytes, redirects; optional body previews/search. |
| `devtools_network_search` | Search URL, headers and response bodies. |
| `devtools_request` | Full request/response metadata, headers, timing, security and redirect chain. |
| `devtools_request_body` | POST/PUT/PATCH payload on demand. |
| `devtools_response_body` | Completed response text on demand; binary bodies are summarized. |
| `devtools_websocket` | WebSocket/EventSource connections and sent/received frames. |
| `devtools_diagnose` | Fast summary of console errors, HTTP failures, CORS, slow requests, dialogs and pending activity. |

### Machine-level DevTools

| Tool | Tier | Purpose |
|---|---|---|
| `devtools_cdp` | full-debug | Raw CDP method with destructive browser commands blocked. |
| `devtools_debugger` | full-debug | Scripts, breakpoints, pause/resume/step, call stack, source and paused-frame evaluation. |
| `devtools_performance` | | Metrics; tracing and CPU profiling require full-debug. |
| `devtools_intercept` | interactive | Fetch interception rules: continue/block/mock requests. |
| `devtools_emulate` | interactive | Viewport/user-agent/locale/timezone/geolocation/media, network throttling/offline/cache/headers/blocking. |
| `devtools_accessibility` | | Accessibility tree snapshot for semantic discovery. |
| `devtools_snapshot` | | Agent-friendly page snapshot: page info, AX summary, interactive elements, console/network errors. |
| `devtools_pdf` | | Print current page to PDF (base64). |
| `devtools_storage` | interactive | Cookies/localStorage/sessionStorage list; raw values and mutations require full-debug. |
| `devtools_storage_state` | interactive | Export/restore cookies + local/session storage (restore requires sensitive gate). |
| `devtools_capture` | interactive | Mark a capture window, then stop and summarize its requests/errors. |
| `devtools_export` | | Write JSON, HAR 1.2, error report, trace or CPU profile. |
| `devtools_reverse_engineer` | | Client-observable reverse-engineering report: API patterns, JSON shapes, origins/assets, DOM inventory and script heuristics (navigation needs interactive; script source needs full-debug). |
| `devtools_llm_probe` | interactive | Garak-style jailbreak probe suite for authorized LLM chat UIs: Opposite Day, Boolean Opposite Machine (BOM), AntiGPT opposite persona, and reversed-string (FlipAttack-style) prompts; detects inverted boolean answers. |
| `devtools_security_probe` | | Authorized security probing: passive credential-exposure scan (URL tokens, secret-looking storage, JWTs — values stay redacted), paywall/auth-gate bypass detection, and attack-surface mapping (mixed content, credential-form risks, open-redirect params, sensitive paths, third-party scripts, dangerous inline JS). Navigation needs interactive. |
| `devtools_graphql` | | Discover GraphQL endpoints/operations from captured traffic; bounded introspection query from the page context (interactive). |
| `devtools_sourcemap` | full-debug | List scripts with source maps and fetch bounded .map metadata (sources inventory, sourcesContent coverage). |
| `devtools_replay` | interactive | Re-send a captured or explicit request from the page context with method/header/JSON overrides (Burp Repeater-lite, authorized targets). |

## Recommended workflows

### One-call F12 check

```text
devtools_f12_check { "url": "https://app.example.test/", "waitUntil": "load", "settleMs": 300, "networkIdleWaitMs": 1000 }
devtools_request   { "requestId": "<id>" }
devtools_response_body { "requestId": "<id>" }
devtools_export    { "format": "har", "includeBodies": true, "path": "app.har" }
```

`devtools_f12_check` (and `devtools_navigate_and_capture`/`devtools_open_url`) creates/attaches a blank tab and enables Network/Runtime/Page/Log before navigation, so document and early API/XHR calls are present. The result includes `captureReadiness`, `navigation.navigationStartedAt`, `verified.networkEnabledBeforeNavigation`, and `f12` diagnostics with console errors, failed/slow requests, WebSocket activity, and performance metrics. Use `devtools_network_search` or `devtools_network` with `bodyContains` when you only know a response value.

### Follow live activity

Every entry has a sequence number. Poll incrementally instead of re-reading everything:

```text
devtools_console { "afterSequence": 42 }
devtools_network { "afterSequence": 42, "onlyFailed": true }
devtools_websocket { "afterSequence": 42 }
```

The response's `latestSequence` is the cursor for the next poll.

### Reproduce and debug a client error

```text
devtools_navigate_and_capture { "url": "https://app.example.test/" }
devtools_click { "selector": "#checkout" }
devtools_type { "selector": "#email", "text": "user@example.test" }
devtools_console { "level": "error", "includeStack": true }
devtools_diagnose {}
devtools_dom_inspect { "selector": ".error-banner", "includeBoxModel": true }
devtools_screenshot { "fullPage": true }
```

### Breakpoints and paused frames (`full-debug`)

```text
devtools_debugger { "action": "enable" }
devtools_debugger { "action": "scripts", "contains": "/app.js" }
devtools_debugger { "action": "set_breakpoint", "urlRegex": "app\\.js$", "lineNumber": 42 }
# trigger the code path
devtools_debugger { "action": "state" }
devtools_debugger { "action": "evaluate", "callFrameId": "<frame>", "expression": "user.id" }
devtools_debugger { "action": "resume" }
```

Line numbers are 0-based, matching CDP.

### Performance and artifacts

```text
devtools_performance { "action": "metrics" }
devtools_performance { "action": "trace_start", "categories": "devtools.timeline,v8,blink.user_timing" }
# interact with the page
devtools_performance { "action": "trace_stop" }
devtools_export { "format": "trace", "path": "checkout-trace.json" }

devtools_performance { "action": "profile_start", "samplingInterval": 1000 }
# interact with the page
devtools_performance { "action": "profile_stop" }
devtools_export { "format": "profile", "path": "checkout.cpuprofile" }
```

Export formats: `json`, `har`, `report`, `trace`, `profile`. Files are written under `DEVTOOLS_EXPORT_DIR` (default: `<os tmpdir>/toolnet-devtools-exports`); requested paths must stay inside that directory. `includeBodies=true` adds bounded response bodies to JSON/HAR.

## Limits and safeguards

| Area | Limit |
|---|---|
| Console ring | 1,000 entries / 2 MB |
| Network ring | 2,000 requests / 6 MB |
| WebSocket ring | 1,000 frames / 2 MB |
| Debugger scripts | 4,000 tracked scripts |
| Dialogs | 50 |
| Trace | 80,000 events / 24 MB by default, configurable up to 64 MB |
| Auto-cached response bodies | 8 MB aggregate; 200,000 chars per body |
| Post data | 40,000 chars |
| Default MCP tool response | 60,000 chars (`DEVTOOLS_MAX_RESPONSE_CHARS`, max 500,000) |
| CDP input line | 8 MB maximum |

Operational caveats:

- Capture starts when CDP attaches. Console/Network history from before attachment cannot be recovered.
- `devtools_open_url` avoids that gap for the initial navigation; attaching to an already-loaded tab does not.
- Response bodies may be unavailable after Chrome evicts them. Failed/unfinished requests have no response body.
- Tracing and CPU profiling are full-debug operations and keep data in memory until exported or replaced.
- Worker/service-worker/iframe sub-targets are not enumerated as separate sessions.
- Redaction and path confinement are defensive measures, not a sandbox. Run the browser with a dedicated profile.

## Configuration reference

| Variable | Default | Meaning |
|---|---|---|
| `CDP_ENDPOINT` | `http://127.0.0.1:9222` | Browser CDP HTTP endpoint. Loopback only unless explicitly overridden. |
| `CDP_ALLOW_REMOTE` | unset | `1` allows a non-loopback endpoint. Not recommended. |
| `DEVTOOLS_PERMISSION` | `interactive` | `read-only`, `interactive` or `full-debug`. |
| `DEVTOOLS_AUTO_LAUNCH` | `1` | `0` disables launching Chrome. |
| `DEVTOOLS_HEADLESS` | `1` | `0` launches a visible Chrome window. |
| `DEVTOOLS_ALLOW_SENSITIVE` | unset | `1` enables the raw-data gate together with `full-debug`. |
| `CHROME_PATH` / `CHROME_BIN` | auto-detect | Explicit Chrome/Chromium executable. |
| `DEVTOOLS_PROFILE_DIR` | temp dir | Profile used by auto-launched Chrome. |
| `DEVTOOLS_CHROME_ARGS` | unset | Extra Chrome flags, shell-like quoted string. |
| `DEVTOOLS_LAUNCH_TIMEOUT` | `20000` | Auto-launch timeout in milliseconds. |
| `DEVTOOLS_EXPORT_DIR` | temp dir | Confined destination for exports. |
| `DEVTOOLS_CAPTURE_BODIES` | `1` | `0` disables automatic text-body caching. |
| `DEVTOOLS_AUTO_DISMISS_DIALOGS` | unset | `1` auto-dismisses JavaScript dialogs. |
| `DEVTOOLS_MAX_RESPONSE_CHARS` | `60000` | Maximum serialized tool response size. |
| `DEVTOOLS_DEBUG` | unset | `1` logs tool timings and Chrome launch diagnostics to stderr. |
| `ALLOW_UNSAFE_CDP` | unset | Backward-compatible alias for `DEVTOOLS_PERMISSION=full-debug`. |

## Testing

Unit tests do not need a browser:

```sh
npm test
```

Integration tests use a real Chromium at `http://127.0.0.1:9222` plus a separate auto-launch port `9333`. The npm script sets the required permission and sensitive-data environment:

```sh
npm run test:integration
npm run test:all
```

CI runs on GitHub Actions (`.github/workflows/ci.yml`) on push/PR to `main`: installs Chrome, runs unit tests and real-Chromium integration tests. A separate `publish.yml` publishes to npm with OIDC provenance when the package version is not already on npm.

### Verified results

This version was exercised against **real Chromium, Chrome/157.0.8103.38 on Linux x86_64**:

- **Unit tests:** 38 passed, 0 failed.
- **Integration tests:** 28 passed, 0 failed (including auto-launch and read-only/interactive permission flows).
- Coverage includes: first-byte F12 capture, console/errors/exceptions, API bodies, redirects, WebSocket frames, DOM/CSS, click/type/scroll/screenshot, debugger breakpoints and paused-frame evaluation, dialogs, performance metrics, tracing, CPU profiles, cookies/storage redaction, capture windows, HAR/JSON/report/trace/profile exports, history navigation, multi-tab isolation, public domains, auto headless launch/cleanup, **GraphQL discovery/introspection, source-map fetch, request replay, security findings, reverse-engineering reports, and LLM probe susceptibility**.

To run the same suite, start Chrome on `127.0.0.1:9222` (or let the auto-launch test start a browser on `9333`) and run `npm run test:all`.

## Security

This server grants browser control to the connected agent. Use a dedicated Chrome profile and test accounts.

- **VPS / remote host**: bind CDP to loopback only (`127.0.0.1`); **never expose port 9222 to the Internet**. Do not use `CDP_ALLOW_REMOTE=1` on public hosts.
- **Isolated profile**: run Chrome with a dedicated `--user-data-dir`/`DEVTOOLS_PROFILE_DIR`. Do not attach to or auto-launch against a profile containing sensitive logged-in sessions (email, banking, cloud admin, etc.).
- **Permission tiers**: use `read-only` for inspection; `interactive` for controlled reproduction (allows click/type/side-effectful JS/navigation); `full-debug` only when you need debugger/raw CDP/sensitive exports.
- **Sensitive data**: leave `DEVTOOLS_ALLOW_SENSITIVE` unset unless raw cookies/tokens are genuinely required. Treat exports as sensitive.
- **Authorized testing only**: `devtools_reverse_engineer`, `devtools_security_probe`, `devtools_graphql` introspection, `devtools_sourcemap`, `devtools_replay`, and `devtools_llm_probe` are intended for targets you own or are explicitly authorized to test. Do not use them for unauthorized access, credential stealing, paywall bypass, or intrusion.
- **CDP safeguards**: destructive browser commands (browser close/crash, target close, storage clearing) are blocked through `devtools_cdp`. Dedicated storage clear operations require `confirm=true`.

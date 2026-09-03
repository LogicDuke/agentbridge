# Cockpit Read-Only Dashboard Host (Cockpit D3)

Status: V1 defaults, Stage A. Superseded only by an explicit architecture decision.

## Scope

D3 is the first *visible* Cockpit surface: a local HTTP host that renders one
deterministic fixture snapshot, validated through the existing D1/D2 contracts,
as a read-only browser page.

    Stage-A fixture (unknown)
      -> readCockpitSnapshot()          (D1: hostile-input validation)
      -> projectCockpitEvidenceFreshness()  (D2: freshness projection)
      -> server-side HTML (every value escaped)
      -> 127.0.0.1 GET-only browser view

D3 is **presentation and observability only**. It is not authority, not policy,
not a collector, not persistence, and not an agent-control interface.

## Why the host lives outside `src/cockpit/`

D1 and D2 are pure: `tests/cockpit/architecture-invariants.test.ts` fails the
build if any file in `src/cockpit/` references `node:fs`, `node:http`,
`child_process`, `fetch(`, `process.<x>`, Git, or an import outside the domain
kernel. A dashboard host needs `node:http`. Placing it in `src/cockpit/` would
break that invariant, so D3 is a **separate sibling module**, `src/cockpit-host/`,
that *imports* the pure Cockpit boundary and never modifies it. The host keeps
its own narrower purity invariant (`tests/cockpit-host/purity.test.ts`): no
subprocess, no environment access, no Git, and imports only Node builtins,
itself, or `../cockpit/`.

## Ingestion boundary

- **D1 is the only hostile-input normalizer.** The Stage-A fixture is typed
  `unknown` and passes through `readCockpitSnapshot()` before any value is
  rendered. If validation fails, the host **fails closed** — it throws and
  refuses to serve rather than falling back to raw fixture data.
- **D2 is the only freshness projection.** Freshness state/reason/counts come
  verbatim from `projectCockpitEvidenceFreshness()`; the host never re-derives
  `CURRENT`/`STALE`/`INVALID`.
- The renderer accepts a validated `CockpitSnapshot`, never `unknown`, so a raw
  caller object can never reach the page unvalidated.

## Authority: none

D3 has zero authority and no mutation surface of any kind:

- **No repository write** — no filesystem write to the repo, no Git.
- **No GitHub write** — no adapter imported.
- **Networking surface (source-bounded)** — the authored D3 executable closure
  imports no networking capability beyond the single loopback `node:http` server
  required by the host (bound to `127.0.0.1`, `GET`-only). Behavioral/literal
  no-egress is *not* proven by this source guard; it belongs to a separate
  future runtime/process isolation boundary.
- **No agent invocation, ExecutionPermit, or merge capability** — C1 authority
  and the provider adapters are not imported and are unreachable.

The absence is structural: there is no field, route, or imported function
through which a mutation could flow. The V1 read-only boundary is preserved and
**human merge authority remains external**. A reviewer recommendation is
rendered as a *claim*, never as permission.

## Honest gap panels

The dashboard shows only what the current read models project:

- **Tree SHA — not projected.** D1 carries the observed HEAD only; there is no
  tree SHA field. The host renders a capability notice, never an invented value.
- **Autoflow — not projected yet.** `WorkflowState` (status, revision, sequence,
  invocations, human gate) has no Cockpit projection. Rendering a fixture
  `WorkflowState` would manufacture orchestration state, so the Autoflow panel
  shows an honest "not projected yet" notice. A real Autoflow view requires a
  future **pure Cockpit D4 projection**; D3 does not import `WorkflowState`,
  `workflow-transitions`, or `applyWorkflowEvent`.

## HTTP security boundary

- **Loopback only** — binds the literal `127.0.0.1`, never `0.0.0.0`, `::`, or a
  resolvable hostname.
- **GET-only** — any other method returns `405 Method Not Allowed` with
  `Allow: GET`; unknown routes return `404`. No mutation route, no request body,
  no cookie, no session.
- **Strict headers on every response** —
  `Content-Security-Policy: default-src 'none'; style-src 'self'; script-src 'none'; …`
  and `X-Content-Type-Options: nosniff`. The page ships no client-side
  JavaScript and no inline `style` attribute, so the policy needs no
  `'unsafe-inline'` and no script source.
- **Untrusted text is always escaped** — every dynamic value (reviewer/finding
  prose included) is HTML-entity-escaped before it enters the markup. No
  `innerHTML`, no `document.write`, no inline event handler. Adversarial tests
  assert that `<script>` and `onerror` payloads render only as inert text.
- **No secrets, paths, or shell** — no `process.env` read, no filesystem path in
  the page, no subprocess, no Git command.

## Stage A explicitly, and what it is not

Stage A renders **deterministic local fixture data only**. It is explicitly
**not live**: not GitHub, not agent output, not the real repository HEAD. The
fixture SHAs are obvious placeholders and the page is banner-labelled
`READ ONLY · STAGE A · FIXTURE DATA` so it cannot be mistaken for a live
observation. Later stages (real domain read-model state; read-only GitHub
adapter observations) are out of D3's scope.

## Boundaries preserved

- No dependency on the open PR #10 process-transport stack; D3 starts from
  verified `main` only.
- No PR008 (Autoflow/Policy roadmap) scope consumed.
- Zero mutation endpoints, loopback-only, GET-only, no external assets, no
  telemetry, no analytics, no new runtime dependency.

## Modules

| Module | Responsibility |
| --- | --- |
| `src/cockpit-host/server.ts` | `node:http` host: routing, security headers, fail-closed page build |
| `src/cockpit-host/render.ts` | Pure snapshot + projection → escaped HTML |
| `src/cockpit-host/escape.ts` | HTML-entity escaping |
| `src/cockpit-host/styles.ts` | Compiled-in stylesheet served at `/styles.css` |
| `src/cockpit-host/fixtures/stage-a.ts` | Deterministic Stage-A fixture (typed `unknown`) |

## Launch

    npm run cockpit

builds `src/**` to `dist/` and starts the host, printing the exact loopback URL.
The user opens it manually; the host starts no browser and holds no shell.

## Tests

`tests/cockpit-host/` covers fixture-passes-D1, fail-closed on malformed input,
adversarial escaping of hostile prose, read-only self-identification, honest
Autoflow/tree-SHA notices, GET/405/404 routing, loopback binding, security
headers, the absence of any mutation route, and host import purity.

# Cockpit Read-Only Dashboard Host (Cockpit D3)

Status: V1 defaults, Stage A. Superseded only by an explicit architecture decision.

## Scope

D3 is the first *visible* Cockpit surface: a local HTTP host that renders one
deterministic fixture snapshot, validated through the existing D1/D2 contracts,
as a read-only browser page.

    Stage-A fixture (unknown)
      -> readCockpitSnapshot()          (D1: hostile-input validation)
      -> projectCockpitEvidenceFreshness()  (D2: freshness projection)
      -> projectCockpitAutoflow()           (D4: Autoflow observation projection)
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
that *imports* the pure Cockpit boundary and never modifies it. The host holds
its own narrower boundary **by construction**: no subprocess, no environment
access, no Git, and it imports only the Node builtins it actually needs
(`node:http`, `node:url`), itself, or `../cockpit/`. These are finite facts
about the current authored source; they are not enforced by a source analyzer.

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
- **Networking surface (source-bounded)** — the authored host imports no
  networking capability beyond the single loopback `node:http` server it needs
  (bound to `127.0.0.1`, `GET`-only). Behavioral/literal **no-egress is not
  claimed here**: a source module cannot bound what `node:http`'s client API,
  global `fetch`, or `WebSocket` do at run time. That guarantee belongs to a
  separate future runtime/process/OS isolation boundary.
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
- **Autoflow — projected (D4).** The snapshot's D1-validated `autoflow`
  observation (a reconstructed PR 007 `WorkflowState`, or `null`) is projected by
  the pure Cockpit **D4** `projectCockpitAutoflow`. The host renders a populated
  Autoflow panel (status, revision, sequence, invocations, human gate) when the
  observation is non-null, and an honest absence panel when it is `null`. The
  panel is a read-only projection of an already-validated observation: D3 runs no
  workflow transition and imports neither `workflow-transitions` nor
  `applyWorkflowEvent`.

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

### Clean Windows checkout / first use (live runtime + control)

Read-only Cockpit (`npm run cockpit`) needs **neither** the control anchor
**nor** helper provisioning; the prerequisites below apply only when the control
channel is wanted.

The control channel has **two** distinct prerequisites, in this order:

    externally provisioned hardened control anchor   (external prerequisite)
      -> npm run control:provision                    (native owner-helper/provenance pair)
      -> npm run cockpit:live                          (one-shot control-startup attempt)
      -> npm run control

**1. The hardened control anchor is an external prerequisite.** Before control
can start, the deployment-anchored control directory must already exist **and**
already satisfy the runtime's hardened-anchor trust policy. On Windows that
directory is:

    %LOCALAPPDATA%\AgentBridge\control

`verifyControlAnchor` (`src/control/control-store.ts`) reads this anchor
**read-only and fail-closed**. The trust policy it enforces
(`evaluateAnchorSnapshot`) is decided over canonical SIDs only, and **every** one
of the following must hold — any single failure disables the control channel:

| Requirement | Rejection when unmet |
| --- | --- |
| OWNER is the exact runtime operator SID | `OWNER_MISMATCH` |
| OWNER is **not** SYSTEM — SYSTEM may own a directory and then rewrite its DACL, so it can never substitute for operator ownership | `OWNER_IS_SYSTEM` |
| The DACL is **PRESENT** (neither absent nor NULL) | `DACL_ABSENT` |
| The DACL is **PROTECTED** — it does not inherit from the parent | `DACL_UNPROTECTED` |
| The DACL is **non-empty** | `NO_ENTRIES` |
| **No** ACE is inherited (no ACE carries `INHERITED_ACE`) | `INHERITED_PRINCIPAL` |
| Every ACE principal is the operator or SYSTEM, by canonical SID — no third principal, however narrow | `FOREIGN_PRINCIPAL` |
| **Every** ACE is file-inheritable (each carries `OBJECT_INHERIT_ACE`), so the descriptor created inside the anchor inherits the same closed principal set | `FILE_INHERITANCE_ABSENT` |
| An ACE for the operator SID is present | `RUNTIME_PRINCIPAL_ABSENT` |

Two of these are easy to miss because a directory can look correct in Explorer
and still fail: the DACL must be **PROTECTED**, and every ACE must be
**file-inheritable** (`OBJECT_INHERIT_ACE`). An anchor that merely lists
operator + SYSTEM as direct, non-inherited entries does **not** satisfy the
policy.

Two further details, so the table is read exactly as the code behaves. SYSTEM is
*permitted*, not *required*: an operator-only DACL that meets every other
requirement is accepted, while any principal beyond operator and SYSTEM is not.
And the allow/deny type and the access mask are carried in the snapshot but do
**not** gate authorization — a DENY operator ACE still counts as the operator
being present — because token possession (mutual HMAC) remains the actual
authenticator; this policy governs anchor trust, not per-call permission.

It never creates the directory and never mutates ACLs.
AgentBridge V1 — the current control flow — does **not** create or harden this
anchor; there is no anchor provisioner in the codebase. A plain `mkdir` is
therefore insufficient on two counts: a freshly created directory inherits its
parent's ACLs (rejected as `DACL_UNPROTECTED` / `INHERITED_PRINCIPAL`), and
nothing has established the file-inheritable operator + SYSTEM entries the policy
requires. Establishing an anchor that satisfies the trust policy is a separate
operator/deployment responsibility, outside the scope of these npm scripts — this
document deliberately prescribes no setup command, because no anchor-provisioning
mechanism is part of the adopted architecture.

**2. `control:provision` provisions only the native artifacts.**
`control:provision` runs the existing validated gate
(`node tools/control-owner/ensure-helper.mjs`) and nothing else: it provisions
the native owner-helper and descriptor-creator binaries with their generated
provenance. It does **not** create, harden, or verify the control anchor — the
anchor above remains an external prerequisite it neither checks nor satisfies.

The gate accepts an artifact pair only when the on-disk provenance is the exact
canonical encoding of **both** that binary's SHA-256 and the SHA-256 of the
reviewed C source it was compiled from. A pair that is internally self-consistent
but was built from an older reviewed source — the state a rollback or a
mixed-cache restore leaves behind — is therefore **rebuilt**, not skipped, so a
stale helper can never leave provisioning reporting success while the runtime
rejects that helper's snapshot output as malformed.

If immediate control availability is required, the control anchor must already
satisfy the runtime's trust policy **before** `cockpit:live` starts. The live
runtime makes exactly **one** control-startup attempt at launch; if either
prerequisite is unmet — the hardened anchor is missing or non-compliant, or the
helper/provenance pair is not yet provisioned — that attempt fails closed and —
by design — there is no automatic or background retry, no polling, and no
watcher. Satisfying the prerequisites *after* the runtime is already running
does not dynamically start the control channel: restart `cockpit:live` to make a
new one-shot control-startup attempt.

Provisioning is **not** required for read-only Cockpit use, and a provisioning
failure never prevents the Cockpit from launching or serving
(`CONTROL_PROVISION_FAILURE ⇏ COCKPIT_FAILURE`): the gate is on the
`control:provision` and `npm run control` paths only, never on `cockpit` or
`cockpit:live`.

## Tests

`tests/cockpit-host/` covers fixture-passes-D1, fail-closed on malformed input,
adversarial escaping of hostile prose, read-only self-identification, the
Autoflow panel (populated projection and honest absence) and the tree-SHA
capability notice, GET/405/404 routing, loopback binding, security headers, and
the absence of any mutation route. These are **behaviour tests**
over the running host — there is no source-scanning purity analyzer.

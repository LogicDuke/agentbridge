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
      -> npm run control:provision                    (two native artifact/provenance pairs)
      -> npm run cockpit:live                          (one-shot control-startup attempt)
      -> npm run control

**1. The hardened control anchor is an external prerequisite.** Before control
can start, the deployment-anchored control directory must already exist **and**
already satisfy the runtime's hardened-anchor trust policy. On Windows that
directory is:

    %LOCALAPPDATA%\AgentBridge\control

`verifyControlAnchor` (`src/control/control-store.ts`) reads this anchor
**read-only and fail-closed**. The trust policy it enforces
(`evaluateAnchorSnapshot`) is decided over canonical SIDs only, from one native
OWNER + DACL snapshot, and **every** one of the following must hold — any single
failure disables the control channel:

| Requirement | Rejection when unmet |
| --- | --- |
| OWNER is the exact runtime operator SID | `OWNER_MISMATCH` |
| OWNER is **not** SYSTEM — an owner can rewrite the DACL, so SYSTEM ownership can never substitute for operator ownership | `OWNER_IS_SYSTEM` |
| The DACL is **PRESENT** (neither NULL nor absent) | `DACL_ABSENT` |
| The DACL is **PROTECTED** — `SE_DACL_PROTECTED`; it does not inherit from its parent, so a later-widened parent can never enter it | `DACL_UNPROTECTED` |
| The DACL is **non-empty** | `NO_ENTRIES` |
| **No** ACE is inherited (no ACE carries `INHERITED_ACE`) | `INHERITED_PRINCIPAL` |
| Every ACE principal is the operator or SYSTEM, by canonical SID — no third principal, however narrow | `FOREIGN_PRINCIPAL` |
| An ACE for the operator SID is present | `RUNTIME_PRINCIPAL_ABSENT` |

Details, so the table is read exactly as the code behaves. SYSTEM is
*permitted*, not *required*, on the anchor: an operator-only DACL that meets
every other requirement is accepted. The allow/deny type and the access mask are
carried in the snapshot but do **not** gate authorization — a DENY operator ACE
still counts as the operator being present — because this policy governs anchor
trust, not per-call permission. The anchor owner/DACL gate, together with the
held-handle descriptor read, **is** the authority: it is what decides which
descriptor, and therefore which runtime `verifyKey`, may be believed against a
cross-principal adversary. It is not defence-in-depth. No file-inheritance (`OBJECT_INHERIT_ACE`) requirement is
placed on the anchor's ACEs: nothing relies on a descriptor inheriting the
anchor's entries, because every descriptor is created with its own explicit
protected DACL (below).

The runtime is **read-only** with respect to anchor ACLs. It never creates the
directory and never mutates ACLs. AgentBridge V1 does **not** create or harden
this anchor; there is no anchor provisioner in the codebase. A plain `mkdir` is
therefore insufficient: a freshly created directory inherits its parent's ACLs,
which the policy rejects as `DACL_UNPROTECTED` / `INHERITED_PRINCIPAL`.
Establishing an anchor that satisfies the trust policy is a separate
operator/deployment responsibility, outside the scope of these npm scripts.

**2. `control:provision` provisions only the native artifacts.**
`control:provision` runs the existing validated gate
(`node tools/control-owner/ensure-helper.mjs`) and nothing else: it provisions
the two build-provenanced native artifacts — the read-only owner/DACL snapshot
helper (`agentbridge-win-owner.exe`) and the create-only descriptor creator
(`agentbridge-win-descriptor-create.exe`) — each with its own generated
provenance module. It does **not** create, harden, or verify the control anchor.

The gate accepts an artifact pair only when the on-disk provenance is the exact
canonical encoding of **both** that binary's SHA-256 and the SHA-256 of the
reviewed C source it was compiled from (`sourceId`). A pair that is internally
self-consistent but was built from an older reviewed source — the state a
rollback or a mixed-cache restore leaves behind — is therefore **rebuilt**, not
skipped: `SUPPORTED_PROVISIONING_SUCCESS ⇒ NATIVE_ARTIFACT_RUNTIME_COMPATIBLE`.
The runtime reads only the filename and the binary hash from a provenance module
and hash-verifies each binary before executing it; `sourceId` is lifecycle
metadata that grants no trust the runtime would otherwise deny.

If immediate control availability is required, the control anchor must already
satisfy the runtime's trust policy **before** `cockpit:live` starts. The live
runtime makes exactly **one** control-startup attempt at launch, and only
**after** its fixed loopback Cockpit bind has succeeded (the bind is the
process-level single-runtime gate, so a bind loser never publishes a descriptor);
if either prerequisite is unmet — the hardened anchor is missing or
non-compliant, or an artifact pair is not yet provisioned — that attempt fails
closed and — by design — there is no automatic or background retry, no polling,
and no watcher. Satisfying the prerequisites *after* the runtime is already
running does not dynamically start the control channel: restart `cockpit:live`
to make a new one-shot control-startup attempt.

Provisioning is **not** required for read-only Cockpit use, and neither a
provisioning failure nor a control-startup failure prevents the Cockpit from
launching or serving (`CONTROL_PROVISION_FAILURE ⇏ COCKPIT_FAILURE`,
`CONTROL_STARTUP_FAILURE ⇏ COCKPIT_FAILURE`): the gate is on the
`control:provision` and `npm run control` paths only, never on `cockpit` or
`cockpit:live`, and control is started from the Cockpit's `listening` event with
every failure contained.

### Descriptor lifecycle (identity-named, listen-before-publish)

There is **no shared fixed descriptor pathname**. Each runtime mints a 128-bit
random runtime id — the hex suffix of its unpredictable pipe name
`agentbridge-control-<id>` — and publishes exactly one file inside the anchor:

    runtime-descriptor-<id>.json        (<id> = exactly 32 lowercase hex characters)

The id is whitelisted character-by-character everywhere it enters a filename (the
runtime, the CLI, and the native creator), so no caller-controlled path,
separator, or traversal can reach the filesystem. The descriptor holds exactly

    { version: 3, pipeName, token, verifyKey }

and no PID. `token` is the 256-bit client-to-server command authorizer. `verifyKey`
is the raw 32-byte Ed25519 **public** key whose private half is generated fresh at
every start and lives only in that runtime's process memory — it is never written
to the descriptor, a log, argv, an environment variable, or a subprocess.

A version-2 descriptor (`{ version, pipeName, token }`, or one carrying the
withdrawn anchor-secret `proof` field) is **malformed** and can never be a live
candidate. There is no dual-accept, no negotiation, no compatibility window, and
no downgrade path: a single attacker-supplied v2 artifact would otherwise erase
the guarantee. No migration is required, because descriptors and tokens are
process-lifetime only and both peers ship from one build.

The per-anchor reserved secret file and the descriptor `proof` binding are
**removed**. They were an attempt to prove a descriptor's trusted origin from its
contents, and that cannot work: a descriptor's current owner and DACL say nothing
about its history, so no predicate over file state at time *t* can decide whether
those bytes were copied earlier. The v3 schema check subsumes the only thing the
proof actually achieved — rejecting pre-hardening files — at zero cost, and the
anchor no longer holds any durable secret beyond each runtime's own
process-lifetime descriptor.

Startup order, structurally: verify the anchor → sweep foreign descriptors whose
pipe the kernel reports absent → mint the identity → **listen** on the pipe (the
kernel-owned exclusivity/liveness claim; a collision fails closed with nothing
published) → **then** create the descriptor through the creator (`CREATE_NEW`,
owner = the creator's own token user, a PROTECTED DACL of exactly operator +
SYSTEM, bytes on stdin only) → verify that exact file (owner, DACL present +
protected, direct operator + SYSTEM only, via the read-only helper; then contents
by read-back against what was minted) → expose the handle. The descriptor-file
policy (`evaluateDescriptorSnapshot`) is the anchor policy plus a required
SYSTEM ACE, because that is precisely what the creator produces
(`SYSTEM_PRINCIPAL_ABSENT` otherwise).

Liveness and cleanup use the kernel pipe namespace, never a PID, a timestamp, or
file order. A descriptor whose pipe answers `ENOENT` is dead; that — and only
that — authorizes removing exactly that one file. A pipe that exists but does not
authenticate is never treated as dead. A runtime removes its own file on orderly
close (descriptor first, then the pipe) and on a post-publication startup
failure; it never overwrites or rotates another runtime's file.

Discovery (`npm run control`) enumerates a bounded set of identity-named
candidates, parses each safely (a file whose name and contents disagree is
malformed and ignored, never deleted), probes each valid candidate's pipe, and
proceeds only with **exactly one** live candidate — the handshake is then
attempted against that runtime alone, because the protocol's only message is the
authoritative command. Zero live candidates is unavailable; two or more is
ambiguous and fails closed. The CLI never deletes.

### Wire protocol v2 and server-result authentication

    S->C  hello    { v: 2, nonceS }
    C->S  request  { v: 2, nonceC, command, mac }
            mac = HMAC(token, T("C", runtimeId, pipeName, nonceS, nonceC, command))
    S->C  result   { v: 2, result, sig }
            sig = Ed25519(sk, T("S", runtimeId, pipeName, nonceS, nonceC, command, result))

The two directions use different primitives because they answer different
questions. The client proves it could read the descriptor inside the hardened
anchor (command authorization). The server proves it is a process **alive right
now** holding the ephemeral private key matching the `verifyKey` the client read
(runtime authentication). A protocol-version-1 result body carries `mac`, not
`sig`, and is rejected outright — again with no downgrade branch.

Both transcripts are the canonical length-framed form, and both bind `runtimeId`
and `pipeName`, so one runtime's signature can never be relayed as another's. The
result signature also covers the exact command and result bytes, so it is never a
reusable coupon for an arbitrary outcome. Freshness rests on `nonceC`:
client-generated, 256-bit, CSPRNG, fresh per connection.

The property this buys, exactly: **copying or replaying serialized descriptor
bytes alone is never sufficient to authenticate an `APPLIED` result.** A party
serving a squatted pipe with a byte-identical copy of a genuine descriptor holds
`verifyKey` but no signing capability, so the CLI exits non-zero. That holds
unconditionally, because no signing capability exists anywhere in the serialized
state.

What it does **not** buy: a descriptor rewritten with an adversary's *own*
`verifyKey` is not defeated by the protocol — the descriptor is the trust root and
anchor write access is the adversary's defining capability. That is defeated for
cross-principal adversaries by the anchor DACL above, and it is explicitly **out
of scope** for same-SID, Administrator and SYSTEM principals, whether the genuine
runtime is alive or dead. Windows provides no intra-SID isolation, so a same-SID
process can equally read a live runtime's key out of process memory; claiming
protection there would be a claim the mechanism cannot support. A post-crash pipe
squatter can still degrade availability — discovery may return a candidate whose
handshake then fails loudly — but never integrity.

## Tests

`tests/cockpit-host/` covers fixture-passes-D1, fail-closed on malformed input,
adversarial escaping of hostile prose, read-only self-identification, the
Autoflow panel (populated projection and honest absence) and the tree-SHA
capability notice, GET/405/404 routing, loopback binding, security headers, and
the absence of any mutation route. These are **behaviour tests**
over the running host — there is no source-scanning purity analyzer.

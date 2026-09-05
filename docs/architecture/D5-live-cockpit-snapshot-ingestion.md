# Live Cockpit Snapshot Ingestion (Cockpit D5)

Status: V1 defaults. Adopted from `AGENTBRIDGE_LIVE_SNAPSHOT_DDR_RESPONSE`
(Option A). Baseline `main` = `068a523be52b5fa1036cb362f443d59a1ae46b80`.

## Scope

Replace the Cockpit host's hard dependence on `STAGE_A_FIXTURE` as its runtime
source with a **read-only serialized snapshot producer**, while preserving every
existing security, hostile-input, read-only, workflow-truth, and human-authority
boundary.

    Autoflow authoritative state (sole workflow truth)
      -> produceCockpitSnapshot(observation)     (D5: pure serializer, this milestone)
      -> JSON round-trip (serialization firewall)
      -> readCockpitSnapshot(unknown)            (D1: unchanged hostile boundary)
      -> projectCockpitEvidenceFreshness()       (D2: unchanged)
      -> projectCockpitAutoflow()                (D4: unchanged)
      -> renderDashboard(..., provenance)        (D3: provenance-derived labels)
      -> GET-only 127.0.0.1 host                 (D3: unchanged transport/authority)

## What was added

### 1. Producer — `src/cockpit-snapshot/producer.ts`

`produceCockpitSnapshot(observation): unknown` turns one authoritative,
in-process observation (repository identity, observed HEAD, provenance, the four
read-model lists, and one PR 007 `WorkflowState` or `null`) into a serialized,
JSON-shaped schema-v2 envelope.

- **Read-only.** No workflow transition (imports neither `openWorkflow` nor
  `applyWorkflowEvent`), no repository mutation, no provider execution, no I/O,
  no clock, no environment, no filesystem, network, subprocess, persistence, or
  identifier generation.
- **Serialization firewall.** The finished envelope passes through one
  `JSON.parse(JSON.stringify(...))` before return, so no live `WorkflowState`
  reference, frozen identity, engine handle, callback, getter, or Proxy can cross
  into the Cockpit — only plain JSON data does, exactly as external collector
  bytes would.
- **Owns no validation.** Bounds, vocabulary folding, hostile-input rejection,
  and the repository-binding cross-check remain solely `readCockpitSnapshot`'s
  job. The return type is `unknown` precisely because it has *not* been
  validated; D1 is still the only trust boundary.

### 2. Source seam — `src/cockpit-host/server.ts`

`CockpitSource = { mode: 'fixture' | 'live'; read: () => unknown }`.
`buildDashboardHtml(source = FIXTURE_SOURCE)` and
`createCockpitServer(source = FIXTURE_SOURCE)` now accept an explicit source; the
default is the Stage-A fixture, so the historical zero-argument behavior is
byte-preserved.

- **Fail closed, no silent fallback.** A source that throws (live unavailable) or
  whose snapshot fails D1 propagates the failure; the host refuses to serve. A
  failed `live` source is **never** replaced by the fixture.
- The seam adds **no new import** to the host and **no `process.env`** read, so
  the D3 Stage-A frozen-source pin (`tests/cockpit-host/stage-a-invariants.test.ts`)
  holds unchanged. Selecting `live` at runtime is a caller/entrypoint concern
  (inject a live `CockpitSource`); it is deliberately not an env switch.

### 3. Provenance-derived labeling — `src/cockpit-host/render.ts`

`renderDashboard(..., provenance = 'fixture')` derives the page title, mode/data
badges, and footer note from the source mode. A `live` page shows
`LIVE` / `LIVE OBSERVATION` / "live observation"; a `fixture` page keeps
`STAGE A` / `FIXTURE DATA` / "Stage A fixture data · not live". The two are
mutually exclusive: a live snapshot can never be falsely labeled fixture, nor a
fixture as live. The mode is an out-of-band signal from the seam, not read from
snapshot content, so a snapshot cannot relabel itself.

## Boundaries preserved (unchanged files)

`src/cockpit/read-model.ts` (D1), `src/cockpit/evidence-freshness-projection.ts`
(D2), `src/cockpit/autoflow-projection.ts` (D4), `src/domain/workflow.ts`,
`src/domain/workflow-transitions.ts`, the HTTP loopback binding, GET-only
routing, CSP/security headers, and HTML escaping are all unchanged.

## Freshness

Schema v2 is unchanged. `provenance.observedAt` remains observation data; no
`CURRENT`/`STALE`-as-now verdict is added to the envelope. Wall-clock staleness,
if ever presented, is a pure projection over `observedAt` against a
caller-supplied reference time — deferred here, as it is not required to ingest a
live snapshot.

## Authority: none added

The Cockpit gains no Autoflow transition, policy, provider execution, repository
edit, commit, push, PR, Ready, review-trigger, thread-resolution, or merge
authority. Autoflow remains the sole workflow source of truth; the producer
serializes an *observation* of it and nothing reads a snapshot back into a
transition. Human protected-merge authority remains external.

## Tests

- `tests/cockpit-snapshot/producer.test.ts` — D1 acceptance of valid live
  snapshots, repository binding, mismatch/malformed/oversized rejection by D1,
  the serialization firewall (no live reference; JSON round-trip; determinism;
  post-ingestion mutation isolation), and producer authority/purity source scan.
- `tests/cockpit-host/live-source.test.ts` — live ingestion + render, `autoflow`
  null absence, fixture/live provenance labeling and separation, fail-closed on
  malformed/unavailable live source with no fixture fallback, determinism, and a
  live page served over an ephemeral loopback port (never 4317).
- Existing D1/D2/D3/D4 suites remain green (regression).

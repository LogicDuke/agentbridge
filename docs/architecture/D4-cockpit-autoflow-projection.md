# Cockpit Autoflow Projection (D4, Stage A)

Status: V1, Stage A. Superseded only by an explicit architecture decision.

## Purpose

D4 removes the D3 "Autoflow — not projected yet" gap honestly. It projects one
**already-valid, in-process** PR 007 `WorkflowState` into an immutable Cockpit
presentation value:

    valid WorkflowState
        -> verbatim orchestration facts + derived presentation counts
        -> read-only Cockpit display

D4 is **observability, not orchestration authority**. It never advances,
transitions, closes, or reopens a workflow, and it fabricates no workflow state.

## Frozen Stage-A design decision

D4 Stage A consumes an already-valid **in-process** `WorkflowState` (the value
returned by `openWorkflow` / `applyWorkflowEvent`). It does **not**:

- modify the D1 `CockpitSnapshot` envelope;
- add a `readAutoflowState(unknown)` hostile reader;
- add persistence or a collector;
- add WF1/WF2/WF3 escalation, finding-family, or reviewer-budget state;
- add next-action / current-gate policy;
- add authority.

The serialized/collector provenance boundary — re-reading a workflow state from
hostile JSON — has since **landed in the D1 Cockpit snapshot reader**, exactly
where this Stage-A note anticipated it belongs, not in D4. Under Cockpit snapshot
**schema version 2** the D1 envelope carries a **required** `autoflow` field: a
non-null Autoflow observation is a serialized `WorkflowState` that D1 (not D4)
reconstructs and validates through the domain's own hostile `readWorkflowState`
reader, and binds to the snapshot's `repositoryId`, before any consumer sees it.
D4 still consumes only that already-validated, in-process value: the D4
projection does not own or run the D1 envelope reader, does not mutate the
`CockpitSnapshot` envelope, adds no hostile reader of its own, executes no
workflow transition, and gains no authority.

## Trust boundary (D2 "Option A")

The input is a `WorkflowState` produced by the PR 007 state machine, which
returns only deeply-frozen, self-consistent, JSON-round-trippable values. D4
mirrors D2: it consumes an already-validated domain value, accepts no `unknown`,
adds no `invalidFields` envelope, and re-validates nothing. It is not a second
reader.

For realm robustness (the JavaScript realm may be mutated between the domain
transition and the projection) D4 captures its intrinsics at load, avoids every
`Array.prototype` method / spread / iterator on the path, gives returned records
a `null` prototype, and shadows `toJSON` on returned lists — the same technique
D2 uses. This is realm robustness, not input validation.

## What D4 projects (verbatim) — the truthful facts

Direct workflow facts, echoed unchanged: `workflowId`, `repositoryId`,
`pullRequestId`, `boundCommitSha`, `revision`, `sequence`, `status`,
`closureReason`, `humanGateOpenedAtRevision`.

Per tracked invocation, echoed in `state.invocations` order (never sorted,
filtered, or deduplicated): `invocationId`, `targetCommitSha`, `purpose`,
`providerId`, `agentId`, `requestedAtRevision`, `requestedAtSequence`, `state`,
`reportedStatus`, `reportedAtRevision`, `reportedAtSequence`. `purpose`,
`providerId`, `agentId`, and `reportedStatus` are **inert** — echoed for audit,
read by no branch, granting nothing (PR 007's provider neutrality preserved).

Mechanically derived presentation counts: `invocationsTotal`, `requested`,
`reported` (the `InvocationState` split), `evidenceAdmissions`,
`reviewAdmissions` (the admission-list lengths). PR 007 keeps "work outstanding"
out of domain state precisely because it is derivable; a **presentation** count
is exactly where such a derivation belongs.

## What D4 must not project

- **No `humanGateOpen` boolean.** `status` (which encodes
  `AWAITING_HUMAN_DECISION`) plus `humanGateOpenedAtRevision` are the truthful
  human-gate facts. PR 007 stores no boolean and nothing derivable is stored
  twice; D4 will not reintroduce one.
- **No invocation stale / superseded verdict.** Comparing `targetCommitSha`
  against `boundCommitSha` is PR 007's deliberately-refused second freshness
  answer. Both SHAs are shown; no verdict is derived.
- **No evidence `CURRENT`/`STALE`.** That is PR 004's answer, projected by **D2**
  over the D1 snapshot's evidence, never over the workflow's admission pointers.
- **No review sufficiency, current gate, next permitted transition, ready state,
  merge readiness, approval, authorization, permit, convergence, escalation
  level/reason, or reviewer budget.** Those belong to other layers or do not
  exist yet, so a truthful projection cannot show them.

## Purity / authority argument

`src/cockpit/autoflow-projection.ts` performs no I/O, reads no clock or
environment, uses no filesystem, network, or subprocess, invokes no provider,
calls no forge, persists nothing, mutates no `WorkflowState`, and generates no
identifiers. It imports **neither** `openWorkflow` **nor** `applyWorkflowEvent`
and performs no workflow transition. Its output type carries no authority-,
readiness-, freshness-, next-action-, or escalation-shaped field, so an
authority value has nowhere to land. Cockpit remains presentation only.

## Module boundary

| Module | Responsibility |
| --- | --- |
| `src/cockpit/autoflow-projection.ts` | D4 read-model types + `projectCockpitAutoflow` |
| `src/cockpit/index.ts` | re-exports D4 **types** only (barrel keeps its single non-reader function, `projectCockpitEvidenceFreshness`; D4's function is imported directly from its module) |
| `src/cockpit-host/render.ts` | renders the Autoflow panel from a supplied projection, or an honest absence state |

## Host integration

`renderDashboard` gains an optional `autoflow` projection argument (default
`null`). When supplied, the Autoflow panel renders the projected facts; when
omitted, it shows an honest absence state and invents nothing. The Stage-A host
supplies no workflow — it must not execute Autoflow transitions merely to
manufacture display state — so the panel is absent there. Tests build a real
`WorkflowState` through the domain transitions and pass its projection to the
renderer to exercise the populated panel.

## Recommended next gate

A WF2 mechanism-design gate deciding the D4 input-provenance/serialization
contract — how a real `WorkflowState` crosses into Cockpit beyond an in-process
value (D1-envelope extension with a `schemaVersion` policy, or an Evidence-Store
source). Escalation (WF1/WF2/WF3), finding-family, and reviewer-budget
projection remain deferred until the domain state they describe exists.

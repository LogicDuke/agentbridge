# Cockpit Snapshot / Read-Model Contract (Cockpit D1)

Status: V1 defaults. Superseded only by an explicit architecture decision.

## Scope

D1 adds the pure TypeScript contract for future read-only Cockpit data:

    collector observation -> CockpitSnapshot -> read-only presentation

**Contract only. Nothing is collected, persisted, served, or executed.** D1
contains no filesystem access, no Evidence Store implementation, no collectors,
no Git or GitHub access, no subprocess, no HTTP/REST/WebSocket/SSE, no
frontend, and no Autoflow integration. Every value in a snapshot — including
the observation timestamp — is caller-supplied data.

## Authority model

**The Cockpit is presentation and observability, never authority.**

AgentBridge V1 remains read-only against managed repositories, and D1 grants
nothing. A snapshot is a *derived echo* of domain truth for display. No field
in the envelope is typed to carry a decision, permit, approval, or
authorization, so an authority-shaped value has nowhere to land, and the
reader's accepted output is a frozen copy that carries no stray input fields.

Domain/evidence truth and the Cockpit view model are distinct by construction:

- The frozen kernel layers (PR 002–006, C1) remain the only sources of domain
  truth and are imported, never re-declared.
- Any future durable snapshot storage belongs to the Evidence Store boundary.
  D1 defines only the serializable envelope such storage would carry.

## Modules

| Module | Responsibility |
| --- | --- |
| `src/cockpit/read-model.ts` | Snapshot envelope, provenance, read models, fail-closed reader |
| `src/cockpit/index.ts` | Public re-exports of the D1 contract |

## The envelope

One `CockpitSnapshot` describes exactly one repository at one observed HEAD:

- `repository` — repository identity, observed HEAD SHA, optional canonical
  default-branch ref (C1's `refs/heads/<name>` spelling).
- `provenance` — collector/source identity and the externally supplied
  observation timestamp. Audit metadata, inert as authority.
- `pullRequests`, `evidence`, `findings`, `repairJobs` — bounded, all-or-nothing
  lists of frozen read models.

Every accepted field is a primitive, `null`, or a frozen array of frozen
records, so a snapshot survives a plain-JSON round trip unchanged.

## Reused domain vocabulary (never duplicated)

| Reused | From |
| --- | --- |
| `EvidenceKind`, `EvidenceSource` + guards | PR 004 `evidence.ts` |
| `FreshnessState` (`CURRENT`/`STALE`/`INVALID`) | PR 004 `evidence-freshness.ts` |
| `ReviewSeverity`, `ReviewClassification`, `ReviewFindingStatus` + readers, `REVIEW_BOUNDS`, `readText` | PR 005 `review.ts` |
| `readExactIdentifier`, `readOwnProperty`, `readCanonicalBranchRef`, `append`, `containsValue` | C1 `repair-job.ts` |

## Freshness versus disposition

The formal finding freshness vocabulary is PR 004's and is not extended. A
finding read model may carry `advisoryFreshness` — a *recomputable echo* of a
freshness evaluation — but it is never authority: the envelope carries the
finding's `reviewedCommitSha` and the repository's `observedHeadSha`, so a
consumer that needs the truth recomputes with the domain kernel. An
unrecognised advisory value folds to `null` ("no claim"), never to a state.

Presentation triage categories (`maintenance-observation`,
`future-layer-obligation`, `optional-cleanup`, `deferred`, `unspecified`) are a
separate `CockpitFindingDisposition` axis. A disposition is not a finding
classification, not a freshness state, and adds no member to any domain
vocabulary; the two axes share no member and a value from one folds fail-closed
in the other.

## Hostile-data discipline

A snapshot is re-read from JSON-shaped, unknown-provenance data, so
`readCockpitSnapshot` follows the boundary discipline already established in
PR 004–006 and C1:

- intrinsics captured at module load; imported domain readers capture their own
- own-properties only — inherited and `__proto__`-planted values never become
  fields
- every value read exactly once into a local; guarded reads that fail closed on
  throwing getters, Proxy traps, and revoked Proxies
- identity-shaped fields exact-or-rejected (never trimmed or truncated);
  descriptive vocabulary folded to its fail-closed member; prose bounded
- bounded, all-or-nothing lists — sparse holes, inherited elements, lying
  lengths, and oversize reject the whole snapshot
- deterministic invalid-field reporting in `COCKPIT_SNAPSHOT_FIELD_ORDER`
- the accepted snapshot is a deep-frozen copy built from validated locals,
  never the caller's objects

## Tests

`tests/cockpit/` covers valid construction, deterministic rejection,
inherited-property refusal, unstable-getter single-read discipline, snapshot
immutability, JSON round-trip stability, domain-vocabulary reuse,
freshness/disposition separation, and a bounded source-purity invariant that
proves `src/cockpit/` references no filesystem, subprocess, network, process
execution, or Git/GitHub operation and imports only the domain kernel.

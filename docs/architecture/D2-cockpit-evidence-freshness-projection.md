# Cockpit Evidence Freshness Projection (Cockpit D2)

Status: V1 defaults. Superseded only by an explicit architecture decision.

## Scope

D2 adds exactly one responsibility to the Cockpit layer: project PR 004's
evidence-freshness answers for the evidence records contained in one
**already-validated** `CockpitSnapshot`.

    validated CockpitSnapshot
      -> snapshot evidence read models
      -> minimal EvidenceRecord reconstruction
      -> EvidenceTarget derived from the enclosing snapshot
      -> PR 004 evaluateEvidenceSet()
      -> immutable Cockpit presentation projection

There is no reverse arrow. D2 is presentation and observability only.

D2 is **not**: hostile JSON validation, evidence authority, policy, merge
readiness, reviewer quorum, execution authority, repair authority, a collector,
persistence, or any Git/GitHub, filesystem, network, or subprocess I/O.

## Trust boundary (Option A)

D2 accepts only an already-valid D1 `CockpitSnapshot`.

- **D1 owns hostile `unknown` input.** JSON-shaped, unknown-provenance data goes
  through `readCockpitSnapshot()`, which validates or rejects it.
- **D2 owns the projection of a valid snapshot.** Its public API takes a
  `CockpitSnapshot`, never `unknown`.
- **D2 does not duplicate `readCockpitSnapshot`.** It adds no second
  `invalidFields` envelope, no malformed-snapshot handling, no null/primitive
  input semantics, no non-array evidence semantics, and no throwing-getter
  validation. Those belong to D1.

Consequently a zero-result projection means exactly one thing: the valid
snapshot contains zero evidence records. Malformed input never projects as a
legitimate empty evidence set, because malformed input never reaches D2.

For a contract-valid snapshot, `projectCockpitEvidenceFreshness` is pure,
deterministic, synchronous, non-mutating, side-effect free, and returns a
deeply immutable value. Behaviour for values forced through an unsafe TypeScript
cast is intentionally undefined — that is separation of responsibilities, not a
missing defence, and no validation branch is added to support it.

## Freshness authority

PR 004 (`src/domain/evidence-freshness.ts`) is the freshness authority. D2 only
projects freshness:

- it never compares SHAs and never decides `CURRENT` / `STALE` / `INVALID`;
- it copies PR 004's `state`, `reason`, and `invalidFields` verbatim;
- it reuses `EvidenceRecord`, `EvidenceKind`, `EvidenceSource` from
  `evidence.ts` and `EvidenceTarget`, `evaluateEvidenceSet`, `FreshnessState`,
  `FreshnessReason`, and `FRESHNESS` from `evidence-freshness.ts` (the
  `FRESHNESS_REASON` vocabulary reaches the projection verbatim through the
  kernel's answers), and re-declares none of them.

## Evidence and target reconstruction

For every `CockpitEvidenceReadModel` the minimum `EvidenceRecord` is rebuilt:

    { evidenceId, repositoryId, commitSha, kind, source, reference, observedAt }

**`repositoryId` is injected from the enclosing snapshot**
(`snapshot.repository.repositoryId`). A D1 snapshot describes exactly one
repository, so per-element repository fields are neither present nor added to
the D1 read model. No metadata is attached.

Exactly one `EvidenceTarget` is built from snapshot identity:

    { repositoryId: snapshot.repository.repositoryId,
      currentHeadSha: snapshot.repository.observedHeadSha }

**`observedHeadSha` is the only target HEAD.** Both identity values are read
once into locals and every record is evaluated against the same target. HEAD is
never inferred from an evidence `commitSha`, an `advisoryFreshness` echo,
finding data, a pull-request observation, reviewer output, or metadata.

## Finding freshness is out of scope

D2 neither reads nor recomputes `snapshot.findings[*].advisoryFreshness`, and
fabricates no evidence provenance from findings. D2 is evidence-record
freshness projection only; finding freshness remains a separate concern.

## Output

    projectCockpitEvidenceFreshness(snapshot: CockpitSnapshot)
      : CockpitEvidenceFreshnessProjection

| Type | Fields |
| --- | --- |
| `CockpitEvidenceFreshnessItem` | `evidenceId`, `kind`, `source`, `commitSha`, `state`, `reason`, `invalidFields` |
| `CockpitEvidenceFreshnessCounts` | `current`, `stale`, `invalid`, `total` |
| `CockpitEvidenceFreshnessProjection` | `repositoryId`, `observedHeadSha`, `results`, `counts` |

- `results[i]` corresponds to `snapshot.evidence[i]`: input order preserved,
  nothing sorted, deduplicated, filtered, or dropped.
- `counts.total === results.length` and
  `counts.current + counts.stale + counts.invalid === counts.total`.
- No `current[]` / `stale[]` / `invalid[]` buckets: they would duplicate
  derivable presentation data.
- **`INVALID` is part of the domain vocabulary** and `counts.invalid` keeps the
  projection structurally faithful to PR 004, **but it is not expected from a
  valid D1 snapshot under the current schema**: D1 guarantees non-null identity
  and structurally valid evidence, and repository identity is injected from the
  same snapshot, so `REPOSITORY_MISMATCH`, `EVALUATION_TARGET_INVALID`, and
  `EVIDENCE_MALFORMED` are unreachable through contractual D2 input. D2 still
  copies whatever PR 004 returns without reinterpretation.

## Authority model

The projection is immutable presentation state. It carries no decision,
permit, approval, authority, merge-readiness, quorum, or repair field, and the
Cockpit architecture invariant admits exactly one non-`read*` public function —
`projectCockpitEvidenceFreshness` — without granting a general `project*`
namespace. No collector, persistence, or I/O is introduced.

## Bounds and immutability

- **No new bound beyond D1.** D2 is bounded by D1's
  `COCKPIT_BOUNDS.MAX_EVIDENCE_RECORDS` (1,000) and projects every record.
- The returned projection is deeply frozen, detached from the caller's
  snapshot, and contains only primitives and frozen records/lists; it survives
  `JSON.parse(JSON.stringify(projection))` with its enumerable data unchanged.
- Although the input is trusted, the realm may be mutated between D1
  validation and D2 projection. D2 captures the intrinsics it relies on
  (`Object.freeze`, `Object.defineProperty`, `Object.setPrototypeOf`) at module
  load, builds lists by own-element definition (no `push`, `map`, `filter`,
  spread, or iterator), gives its descriptors a `null` prototype before
  `defineProperty` consumes them, gives returned records a `null` prototype, and
  shadows `toJSON` on returned lists — so a poisoned `Object.prototype` or
  `Array.prototype` cannot reach the projection or its JSON form. This is realm
  robustness, not input validation: no D1 field is re-validated.

## Modules

| Module | Responsibility |
| --- | --- |
| `src/cockpit/evidence-freshness-projection.ts` | D2 projection types and `projectCockpitEvidenceFreshness` |
| `src/cockpit/index.ts` | Public re-export of the D2 contract |

## Tests

`tests/cockpit/evidence-freshness-projection.test.ts` covers CURRENT / STALE
projection, exact ordering and counts, parity with a direct
`evaluateEvidenceSet()` call, repository-identity injection, `observedHeadSha`
as the only target HEAD, evidence-as-HEAD refusal, finding independence, the
empty and D1-maximum cases, the no-INVALID-from-reconstruction property, deep
immutability, input non-mutation, determinism, JSON round trip, ambient
`Object.prototype` / `Array.prototype` / intrinsic-replacement robustness, and
absence of authority-shaped keys. `tests/cockpit/architecture-invariants.test.ts`
keeps the source-purity and single-exception export rules.

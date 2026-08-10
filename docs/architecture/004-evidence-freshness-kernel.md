# Commit-Bound Evidence & Freshness Kernel (PR 004)

Status: V1. Superseded only by an explicit architecture decision.

## Scope

PR 004 implements the frozen V1 invariant from `001-v1-architecture.md`:

> Repository and review evidence must be bound to the relevant commit SHA. When
> HEAD changes, stale evidence must not silently authorize a decision.

    Evidence -> SHA binding -> freshness evaluation -> evidence status

**PR 004 performs no I/O.** It does not fetch evidence, call GitHub, invoke
agents, persist records, execute commands or Git, read the filesystem or
network, read a clock, poll, or make a merge decision. Both exported evaluators
are pure functions of their arguments.

## Evidence is not authority

An evidence record states *what was observed for repository R at commit S*. It
never states what AgentBridge may do. This kernel answers exactly one question:

> Is this evidence valid and current for this repository at this HEAD?

It does **not** answer "may AgentBridge execute this action?" — PR 003's policy
gate remains the only authority boundary. There is deliberately no
`approvedForMerge`, `authorized`, or `mayExecute` field anywhere in this kernel,
and a test asserts the result object exposes no boolean field at all, so nothing
here can be misread as permission.

## Modules

| Module | Responsibility |
| --- | --- |
| `src/domain/evidence.ts` | Evidence record, kind/source vocabularies, identifier narrowing |
| `src/domain/evidence-freshness.ts` | Freshness states, evaluator, set partitioning |

## The freshness binding

**Repository ID + commit SHA together form the binding.** Both must match the
evaluation target. Neither alone is sufficient: evidence from repository A must
not become current when evaluating repository B even if the SHA strings are
byte-identical, which is the cross-repository replay case.

| State | Meaning |
| --- | --- |
| `CURRENT` | Structurally valid, and repository + commit both match the target. |
| `STALE` | Well-formed and about this repository, but bound to a different commit. |
| `INVALID` | Malformed, missing provenance, or otherwise unable to take part in reconciliation for this target. |

Cross-repository evidence is `INVALID`, not `STALE`. `STALE` carries the
implication "this was current once and could be refreshed for this target",
which is false for evidence that was never about this repository at all.

## The central invariant

    evidence.commitSha !== currentHeadSha  =>  never CURRENT

A new commit automatically makes evidence tied to the old HEAD stale. This holds
regardless of provider, actor, review verdict, CI status, metadata, claimed
confidence, rationale, evidence kind, or evidence source. Nothing inside the
record can override a SHA mismatch, because nothing inside the record is
consulted: the evaluator reads only `evidenceId`, `repositoryId`, `commitSha`,
`kind`, and `source`, and compares the first three against a separately supplied
target.

`evaluateEvidenceFreshness` is a sequence of guard clauses, each returning a
non-`CURRENT` state, with `CURRENT` as the single final return. It is reached
only after the target validates, every required field validates, the repository
matches, and `commitSha === currentHeadSha`.

There is no notion of "latest review", "recent CI", or "current enough" anywhere
in this kernel. Freshness is only ever an exact comparison.

### Exact comparison, no normalisation

SHA comparison is exact and case-sensitive, with no trimming. A SHA differing by
case, padding, or truncation does not match, and therefore fails closed.
Normalising an identifier before comparison would let `" abc"` match `"abc"`,
which is a bypass vector on a security boundary — the same reasoning that keeps
PR 002's action matching exact.

SHA *format* is deliberately not validated. A malformed SHA cannot equal a
trusted HEAD, so it fails closed on its own; adding a hex-shape check would be
extra surface that buys no additional safety.

## Stale evidence still matters

`STALE` is not a synonym for "worthless". A review of commit A remains a true
historical record of commit A, and later PRs may present it as history. What it
may never do is masquerade as current evidence for commit B. The kernel keeps
the distinction explicit rather than discarding the record.

## Malformed evidence fails closed

Every incoming record is untrusted runtime data. Each field is read as `unknown`
and narrowed before use, so absent properties, `undefined`, `null`, non-string
values, whitespace-only identifiers, hostile metadata, prototype-like keys, and
unsupported kind/source values all produce a deterministic `INVALID` rather than
throwing. This is the same class of defect found in PR 003: **never call a
string method on an unvalidated runtime value.**

Echoed evidence values in the result are `null` unless they validated as
non-blank strings, so a malformed record cannot place a non-string into the
result.

## HEAD is supplied, never inferred

`EvidenceTarget` is a **trusted** argument, separate from the evidence. PR 004
does not discover repository HEAD and has no way to: it performs no Git
execution and no network access. A GitHub adapter will eventually supply trusted
repository state. HEAD must never be inferred from agent-controlled metadata,
and because the target is a distinct parameter, there is no field on the record
through which an agent could try.

## Set evaluation

`evaluateEvidenceSet` partitions records into `current` / `stale` / `invalid`,
preserving input order in `results`. Each record is evaluated independently, so
a record's neighbours cannot change its state and no set operation can promote a
stale record to current. `currentEvidenceOfKind` filters the already-partitioned
current bucket.

This is partitioning only. There are no quorum rules, required-review policies,
merge readiness, or reviewer requirements — those belong to a later PR.

## Immutability

Results, their invalid-field lists, set evaluations, and all four buckets are
frozen. A caller cannot mutate `STALE` into `CURRENT`, reassign a bucket, or
push a stale result into the current bucket.

## Still not the Policy Engine

This kernel supplies one input to a future reconciliation step. It contains no
repository configuration, no evidence store, no approval workflow, no merge
logic, and no orchestration.

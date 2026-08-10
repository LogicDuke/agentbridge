# Review Ingestion (PR 005)

Status: V1. Superseded only by an explicit architecture decision.

## Purpose

PR 005 implements the Review Ingestion layer of the frozen V1 architecture:
the step that converts untrusted reviewer output into normalized, commit-bound
AgentBridge review findings.

    trusted binding context + untrusted reviewer content -> ReviewResult

It answers exactly one question:

> What review findings were reported for this exact repository, pull request,
> and commit?

**PR 005 performs no I/O.** No GitHub, Claude, OpenAI, or CodeRabbit calls; no
network, filesystem, subprocess, database, or Evidence Store persistence; no
clock, timer, retry loop, or environment access; no Autoflow state machine,
repair dispatch, reviewer selection, or review polling. `ingestReview` is a pure
function of its two arguments.

## Review evidence is not authority

A finding records what a reviewer said. It never states whether the finding
should be fixed, whether a pull request is safe to merge, whether an agent may
act, or whether a repair should be dispatched. PR 003's policy gate remains the
only authority boundary.

The normalized model deliberately contains no `decision`, `mayExecute`,
`approved`, `approvedForMerge`, `authorized`, or `mergeable` field, and a test
asserts that no `ALLOW`, `DENY`, `ESCALATE`, or `AUTONOMOUS` value can appear
anywhere in a serialized result — even when the reviewer payload tries to plant
one.

## Trust boundary

Two inputs meet here and are kept strictly apart.

| Input | Trust | Contributes |
| --- | --- | --- |
| `ReviewContext` | **Trusted for binding** | repository, pull request, reviewed commit SHA, provider, reviewer, review id |
| `ReviewSubmission` | **Untrusted** | finding text, severity, classification, status, location, provider-side ids |

**Reviewer content can never set a binding field.** The normalizer never reads
`repositoryId`, `pullRequestId`, `reviewedCommitSha`, `provider`, `reviewerId`,
or `reviewId` from a candidate finding — those values come from the context
argument only. A finding whose prose or fields claim a different repository or
SHA is normalized against the trusted binding regardless.

Properties are read **own-only**. An inherited value — including one planted on
`Object.prototype` through a `__proto__` payload — is treated as absent, so
prototype pollution cannot supply content the reviewer never sent.

## Input contract

`ReviewContext` requires `repositoryId`, `pullRequestId`, `reviewedCommitSha`,
`provider`, and `reviewerId` as non-blank strings; `reviewId` is optional.
`pullRequestId` is a string so every binding field validates uniformly; a caller
holding a numeric PR number stringifies it.

If any required binding field is missing or blank, ingestion returns
`CONTEXT_INVALID` with the offending field names and **no findings at all**.
Oversized repository, pull-request, and reviewed-SHA identifiers are likewise
invalid rather than truncated, preserving their exact trusted binding. A review
that cannot be bound exactly is not ingested.

`ReviewSubmission` carries `findings`, an array of candidate objects. Anything
else — absent, `null`, a non-array, a Proxy, a revoked Proxy — yields an empty
finding list rather than an error.

## Normalized finding model

Each finding carries `findingId`, `ordinal`, the six binding fields, `severity`,
`classification`, `status`, `title`, `message`, `filePath`, `startLine`,
`endLine`, `sourceId`, `providerFindingId`, and `truncated`. Every field is a
primitive or `null`, so results are JSON-serializable and round-trip unchanged.

`title` and `message` are required; a candidate missing either is rejected with
`REQUIRED_FIELD_MISSING`. A candidate that is not an object — including an array
— is rejected with `FINDING_UNREADABLE`. Rejections are reported, not silently
dropped, so a caller can see what a reviewer sent that could not be normalized.

### Vocabularies fail closed

Severity is `blocking | major | minor | info | unknown`. Classification is
`security | correctness | performance | maintainability | other | unknown`.
Status is `open | resolved | unknown`.

Matching is exact and case-sensitive. Anything unrecognised — `P1`, `BLOCKING`,
`critical`, `nit`, a number, `null` — becomes `unknown`.

**`unknown` is not a low-risk value.** It means "the reviewer said something we
do not understand", which deserves at least as much attention as a recognised
finding. Malformed severity must never decay into `info` or `minor`, and
malformed classification must never decay into `other`; tests assert both.

## Provider neutrality

Nothing here interprets a provider's own language. There is no rule that "Codex
P1 means blocking" or "CodeRabbit warning means minor". Provider-specific
adapters will translate their payloads into this contract later.

Provider names are metadata. Normalization is byte-identical across provider
labels, including privileged-sounding ones such as `system` or
`agentbridge-internal`.

## SHA binding and the relationship to PR 004

Every finding permanently retains the `reviewedCommitSha` from the trusted
context. **A review of SHA A remains bound to SHA A forever** — ingestion never
rewrites a finding to a newer HEAD.

Ingestion does **not** decide `CURRENT` versus `STALE`. That is PR 004's
freshness kernel, and duplicating it here would create a second, divergent
answer. Downstream code carries a finding's `repositoryId` and
`reviewedCommitSha` into `evaluateEvidenceFreshness` against the current HEAD to
learn whether the review still applies.

## Duplicate semantics

Duplicates are **preserved, not merged**. Two byte-identical candidates become
two findings with distinct stable `findingId`s (`f0`, `f1`) derived from payload
position. Output is therefore deterministic without any similarity matching, and
no reviewer output is silently discarded.

Fuzzy or semantic reconciliation is explicitly *not* done here; it belongs to a
later reconciliation layer that can see findings across reviews and commits.

## Bounds

Reviewer payloads are hostile input, so every unbounded dimension is capped
**before** iteration.

| Bound | Value | Rationale |
| --- | --- | --- |
| `MAX_FINDINGS` | 1 000 | A real review does not exceed this; caps synchronous work and memory |
| `MAX_TITLE_LENGTH` | 512 | A title is a single line |
| `MAX_MESSAGE_LENGTH` | 8 192 | Generous for prose plus a code excerpt |
| `MAX_PATH_LENGTH` | 1 024 | Beyond any real repository path |
| `MAX_IDENTIFIER_LENGTH` | 256 | Binding and provider identifiers; exact trusted repository/PR/SHA bindings over this size are rejected |

Excess findings are dropped and untrusted finding text is cut, and in both cases
`truncated` is set on the result — deliberately, so a bounded payload can never
be mistaken for a clean review. A per-finding `truncated` flag marks which
findings lost text. Blankness is checked only after each text field is bounded.

Note this differs from PR 004's evidence-set bound, which collapses an
over-length collection to zero. Here, silently reporting "no findings" would be
the dangerous outcome, so ingestion keeps the first `MAX_FINDINGS` and flags the
truncation instead.

## Determinism

Given identical context and submission, ingestion produces byte-equivalent
output: no clock, no randomness, no filesystem, no network, no environment, no
mutable global state. `findingId` derives from payload position, so no hashing
dependency is required.

Intrinsics (`Object.freeze`, `Object.defineProperty`, `Object.hasOwn`,
`Array.isArray`, `Number.isInteger`, `String.prototype.trim`/`slice`,
`Reflect.apply`) are captured at module load, before any untrusted property
access, following the pattern established in PR 004. Array building avoids
`push`, `filter`, spread, and ordinary indexed assignment, so neither poisoned
prototype methods nor inherited index setters are on the path.

Results, finding objects, and both lists are frozen; a finding cannot be rebound
to another commit after ingestion.

## Non-goals

No GitHub/Claude/OpenAI/CodeRabbit integration, network, filesystem,
subprocesses, database or Evidence Store persistence, Autoflow state machine,
repair dispatch, reviewer selection, review polling, PR comment parsing, branch
creation, commits, merge logic, approval logic, deployment, clocks, retry loops,
or fuzzy duplicate reconciliation.

This is one layer of the frozen V1 pipeline, not the pipeline.

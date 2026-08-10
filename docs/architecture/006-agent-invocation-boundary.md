# Agent Invocation Boundary (PR 006)

Status: V1. Superseded only by an explicit architecture decision.

## Purpose

PR 006 implements the provider-neutral agent invocation boundary of the frozen
V1 architecture: the commit-bound record of what AgentBridge asked an external
agent to do, and the normalization of what that agent reported back.

    trusted invocation binding + untrusted agent report -> InvocationReportResult

It answers exactly one question:

> What did AgentBridge ask which agent to do, against which exact repository and
> commit, and what did that agent *claim* resulted?

**PR 006 performs no I/O and invokes nothing.** No agent execution, dispatch, or
transport; no provider adapters; no GitHub, Claude, OpenAI, or CodeRabbit calls;
no network, filesystem, subprocess, database, or Evidence Store persistence; no
clock, timer, retry, backoff, timeout, polling, or scheduling; no Promises or
async of any kind; no Autoflow state machine or lifecycle transitions; no
artifact verification, integration detection, freshness decision, authority
decision, or merge logic; no identifier generation.
`ingestInvocationReport` is a pure function of its two arguments.

## An invocation is not authority

An invocation record says AgentBridge *asked*. It never says an agent may act,
that a pull request may merge, that a repair should be dispatched, or that
anything happened. PR 003's policy gate remains the only authority boundary.

`purpose: 'repair'` grants AgentBridge **no write authority whatsoever**.
Managed repositories remain read-only from AgentBridge in V1. An external agent
that implements or repairs acts under its own credentials in its own workspace;
AgentBridge records only that it asked, and what was claimed.

Dispatching an agent is already modelled by PR 002/003 as the read-only action
`agent.communicate`. PR 006 deliberately does not re-derive that: it contains no
gate call, no `GateDecision` field, no `mayInvoke`, and no `requestId` — a field
naming the gate would invite readers to treat its presence as authorization. The
intended caller sequence, which belongs to a later PR, is to evaluate an
`ActionRequest` through the gate *before* constructing an `AgentInvocation`.

## The evidence ladder

The distinction this boundary exists to preserve:

> "agent says done" is not "artifact exists remotely" is not "artifact is
> integrated" is not "artifact is validated" is not "artifact is authorized to
> merge".

| Rung | Assertion | Owner | PR 006 |
| --- | --- | --- | --- |
| 1 requested | AgentBridge asked agent X to do Y at SHA S | PR 006 `AgentInvocation` | **models** |
| 2 reported complete | the provider says the invocation finished | PR 006 `reportedStatus` | **models** |
| 3 artifact claimed | the provider says it produced artifact R | PR 006 `ClaimedArtifact` | **models** |
| 4 remotely observed | an adapter independently verified R exists | GitHub adapter, recorded as PR 004 evidence | delegates |
| 5 integrated | R is reachable from the target branch; HEAD moved | PR 004 freshness against a new trusted HEAD | delegates |
| 6 validated | CI, tests, or a fresh review pass at the new HEAD | PR 004 + PR 005 | delegates |
| 7 authorized | this may merge or mutate | PR 003 gate + human approval | delegates |

PR 006 introduces exactly one new epistemic tier — **claimed** — and makes rungs
4 through 7 structurally inexpressible. There is no code path that promotes a
claim: reaching rung 4 requires a *new record built from an independent
observation*, never a transformation of provider output.

The normalized model deliberately contains no `exists`, `verified`,
`integrated`, `merged`, `applied`, `validated`, `authorized`, `mergeable`,
`approved`, `state`, `freshness`, `current`, `stale`, `nextAction`, `attempt`,
`retries`, `deadline`, `parentInvocationId`, or `supersedes` field, and a test
asserts that none of them can appear — even when the provider payload plants
every one of them. A second test asserts that no `ALLOW`, `DENY`, `ESCALATE`,
`AUTONOMOUS`, or `CURRENT` value reaches a serialized result.

## Trust boundary

Two inputs meet here and are kept strictly apart.

| Input | Trust | Contributes |
| --- | --- | --- |
| `AgentInvocation` | **Trusted for binding** | invocation identity, repository, pull request, target commit, provider, agent, purpose, requested-at |
| `AgentReport` | **Untrusted** | reported status, diagnostic prose, artifact claims |

**Provider output can never set a binding field.** The normalizer never reads
`invocationId`, `repositoryId`, `pullRequestId`, `targetCommitSha`,
`providerId`, `agentId`, or `purpose` from a candidate claim — those values come
from the invocation argument only. A claim whose fields assert a different
repository, invocation, or commit is normalized against the trusted binding
regardless, and produces a byte-identical result to a claim that does not.

`providerId` and `agentId` are trusted for *binding* — they record which adapter
and which agent were asked — and are entirely **inert as authority**.

Properties are read **own-only**. An inherited value, including one planted on
`Object.prototype` through a `__proto__` payload, is treated as absent.

## Input contract

`AgentInvocation` requires `invocationId`, `repositoryId`, `targetCommitSha`,
`providerId`, `agentId`, `purpose`, and `requestedAt`. `pullRequestId` is
optional because an implementation invocation may precede any pull request; it
is a string so every binding field validates uniformly, and a caller holding a
numeric pull-request number stringifies it.

**Trusted context is all-or-nothing.** A *present* field that does not validate
— including `pullRequestId` — invalidates the whole invocation. There is no
partially accepted invocation and no trusted field that degrades silently. When
the binding is unusable the result is `INVOCATION_INVALID` with the offending
field names, **no claims at all**, and the report is not read at all: a claim
that cannot be attributed to an exact invocation is not worth recording.

`AgentReport` carries `status`, `detail`, and `artifacts`. Anything else —
absent, `null`, a non-array, a Proxy, a revoked Proxy — yields an empty claim
list rather than an error.

`AgentReport` carries **no review findings**. Findings continue to travel
through PR 005's `ingestReview`, so there is exactly one ingestion path per kind
of content and no second, divergent normalizer.

## Vocabularies fail closed

`InvocationPurpose` is `review | implement | repair | audit`. It is **trusted
caller input and has no `unknown` member**: an unrecognised value invalidates
the invocation rather than silently reclassifying what AgentBridge asked for.

`AgentReportStatus` is `reported-complete | reported-failed |
reported-cancelled | unknown`, and is **untrusted**, so it degrades rather than
rejects. The `reported-` prefix is load-bearing: no member asserts that anything
exists or is correct. The vocabulary is **terminal only** — there is no
`queued`, `started`, `running`, or `waiting`, because a non-terminal state
requires something to transition it.

`ArtifactType` is `commit | branch | change-request | patch | report | unknown`.
`change-request` is the provider-neutral name for what a given forge calls a
pull or merge request. **Zero behaviour attaches to any member**: no
branch-naming rule, no child-pull-request convention, no forge semantics, no
merge implication.

Matching is exact and case-sensitive. Anything unrecognised — `complete`,
`COMPLETE`, `'reported-complete '`, `success`, `done`, `pull-request`, a number,
`null` — becomes `unknown`.

**`unknown` is not a low-risk value.** It means "the provider said something we
do not understand", which deserves at least as much attention as
`reported-failed`. Tests assert that a malformed status never decays into
`reported-complete`.

## Diagnostic prose is inert

`reportedDetail` is diagnostic prose only. It is bounded, echoed, and **never
parsed**. No status, artifact identity, routing, authority, policy, retry
behaviour, freshness, or lifecycle transition may ever be derived from it. A
test pins this by asserting that a report whose detail says
`status: reported-complete`, `integrated: true`, or `ALLOW` produces a result
identical in every other field to one whose detail says `ok`.

## Provider neutrality

Nothing here interprets a provider's own language. There is no rule that one
provider implements and another reviews, and no rule that a given provider's
`success` means complete or that its child pull request means anything at all.
Roles are configuration, not domain facts, and a provider may implement, review,
repair, or audit depending on policy.

Normalization is byte-identical across provider and agent labels, including
privileged-sounding ones such as `system`, `root`, `admin`, `human`, and
`agentbridge-internal`. **The domain never infers authority from provider
identity.** Purpose is equally inert: a `repair` invocation produces no field
that a `review` invocation lacks.

## Identifiers reject; only prose truncates

Every identifier-shaped field is exact. None is trimmed, case-folded,
normalised, or truncated, and an oversized value is **rejected** so that its
prefix never reaches the output.

A truncated identifier is strictly worse than no identifier. Git resolves commit
prefixes, so a cut SHA can falsely match a real object, and a cut reference can
name a different object entirely. `reportedDetail` is the only field that is
ever cut, and cutting it always sets `truncated`.

| Field | Trust | Oversize behaviour |
| --- | --- | --- |
| `invocationId`, `repositoryId`, `pullRequestId`, `targetCommitSha`, `providerId`, `agentId`, `requestedAt` | trusted | invocation rejected |
| `reference` | untrusted | claim rejected `REFERENCE_OVERSIZED` |
| `commitSha` | untrusted | dropped to `null`, `truncated` set |
| `detail` | untrusted | cut, `truncated` set |

## Invocation identity

`invocationId` is caller-minted and opaque. **PR 006 generates no identifiers**
— no UUID, no hash, no counter — which is part of what keeps the layer pure and
dependency-free. Uniqueness is the caller's obligation; this layer has no store
and detects no collisions.

There are no relationships between invocations. No parent, supersession,
replacement, or ordering field exists. A fresh review after HEAD moves is simply
a **new invocation with a new `targetCommitSha`**, unlinked to the old one.
Relating invocations to one another is orchestration, and orchestration is a
later PR.

## Artifact claim identity

`claimId` is `c<ordinal>`, where `ordinal` is the candidate's index in the
submitted payload **counting rejected neighbours**. Identity is therefore
positional and deterministic, with no hashing dependency.

A `claimId` is scoped to one report: global identity is the pair
(`invocationId`, `claimId`).

Duplicates are **preserved, not merged**. Two byte-identical candidates become
two claims, `c0` and `c1`. Fuzzy or semantic reconciliation is explicitly not
done here.

`reference` is opaque provider text. It is stored and echoed, and never parsed,
resolved, or dereferenced — any resolution is a separate adapter action under
its own policy and gating.

## Commit binding and the relationship to PR 004

`targetCommitSha` binds an invocation to a commit exactly as PR 004's
`commitSha` binds an evidence record. **An invocation of SHA A stays bound to
SHA A forever**; nothing rewrites it to a newer HEAD.

Ingestion does **not** decide `CURRENT` versus `STALE`. That is PR 004's
freshness kernel, and duplicating it here would create a second, divergent
answer. Downstream code carries an invocation's `repositoryId` and
`targetCommitSha` into `evaluateEvidenceFreshness` against a trusted HEAD to
learn whether the invocation's result still applies.

`claimedCommitSha` is a **provider claim, never a binding**. It may never be
substituted for a trusted SHA: it may not become an `EvidenceRecord.commitSha`
or an `EvidenceTarget.currentHeadSha`. PR 006 also never compares it to
`targetCommitSha` — that comparison is a freshness judgment, and there is no
`claimsTargetCommit` or `matchesHead` field. A test demonstrates that a claim
passed to `evaluateEvidenceFreshness` is `INVALID`, because a claim carries no
evidence identity, kind, source, or bound commit.

## Correlation with PR 005

PR 005 normalizes *what a reviewer said*; PR 006 records *that AgentBridge
asked, and what was claimed*. They are complementary and share no code.

The V1 correlation convention, documentation only:

| PR 005 `ReviewContext` | PR 006 `AgentInvocation` |
| --- | --- |
| `reviewId` | `invocationId` |
| `provider` | `providerId` |
| `reviewerId` | `agentId` |
| `repositoryId` | `repositoryId` |
| `pullRequestId` | `pullRequestId` |
| `reviewedCommitSha` | `targetCommitSha` |

**There is no runtime dependency between the two boundaries in either
direction**, and no `toReviewContext()` helper. PR 006 imports nothing from
PR 005 and PR 005 is unchanged.

### Independent readers, pinned by parity

`agent-invocation.ts` defines its own `clampText`, `readText`,
`readExactIdentifier`, `readOwnProperty`, `containsValue`, and `append` rather
than importing the equivalents from `review.ts`. This is deliberate: the
architectural independence of the two hostile-input boundaries takes precedence
over deduplicating six small readers. A defect, refactor, or export change on
one side cannot alter the other's validation, and each module captures its own
intrinsics at its own load time.

Three of those six are module-private on the PR 005 side and would have to be
copied under any arrangement. Extracting a shared `untrusted-input.ts` remains
deferred until there is enough reuse pressure to justify changing an already
hardened boundary.

The cost of duplication is drift, so drift is made mechanically detectable.
`tests/domain/reader-parity.test.ts` runs one shared hostile-input corpus
through both copies of every reader whose contract overlaps and asserts
identical results. It is the only place the two modules meet, and it is a test,
so it introduces no production dependency. Where the boundaries intentionally
differ — PR 005 shortens an oversized `provider`, PR 006 rejects an oversized
`providerId` — the divergence is pinned explicitly rather than omitted.

PR 005's ingestion truncates `provider`, `reviewerId`, and `reviewId` at the
identifier bound rather than rejecting them. Under this convention `reviewId`
carries an `invocationId`, which makes it a **join key**, and silent truncation
of a join key would be an attribution hazard: two invocation ids sharing a
256-character prefix would collapse, letting one invocation's findings be
attributed to another.

PR 006 makes that path **unreachable by construction**: an `invocationId` over
`MAX_IDENTIFIER_LENGTH` is rejected, so no id AgentBridge mints can ever be
truncated downstream. A test pins `INVOCATION_BOUNDS.MAX_IDENTIFIER_LENGTH ===
REVIEW_BOUNDS.MAX_IDENTIFIER_LENGTH`, and a second test carries a
maximum-length id through both boundaries unchanged.

**Recorded trigger:** if a later PR ever accepts a *provider-supplied*
invocation id as the join key, promoting `provider`, `reviewerId`, and
`reviewId` in `review-ingestion.ts` from truncate to reject-on-oversize becomes
mandatory. Until then it is defence in depth on a hardened merged boundary, not
a fix for a reachable gap.

## Bounds

Provider reports are hostile input, so every unbounded dimension is capped
**before** iteration.

| Bound | Value | Rationale |
| --- | --- | --- |
| `MAX_CLAIMS` | 64 | one invocation produces a handful of artifacts; caps synchronous work and memory |
| `MAX_IDENTIFIER_LENGTH` | 256 | must equal PR 005's identifier bound; oversize rejects |
| `MAX_DETAIL_LENGTH` | 2 048 | generous for a failure reason; the only field ever cut |

Excess claims are dropped and `truncated` is set — deliberately, so a bounded
payload can never be mistaken for a complete report. This follows PR 005 rather
than PR 004's collapse-to-zero, because silently discarding a claimed artifact
is the more dangerous outcome.

## Determinism

Given identical arguments, ingestion produces byte-equivalent output: no clock,
no randomness, no filesystem, no network, no environment, no mutable global
state, no identifier generation. `claimId` derives from payload position, so no
hashing dependency is required. Claims, rejections, and invalid-field names all
preserve deterministic order, and nothing is sorted, grouped, or deduplicated.

Intrinsics (`Object.freeze`, `Object.defineProperty`, `Object.hasOwn`,
`Array.isArray`, `Number.isInteger`, `String`, `String.prototype.trim`/`slice`,
`Reflect.apply`) are captured at module load, before any untrusted property
access, following the pattern established in PR 004 and PR 005. Array building
avoids `push`, `filter`, spread, and ordinary indexed assignment, so neither
poisoned prototype methods nor inherited index setters are on the path. Every
field is read exactly once into a local, so a getter that returns a different
value on each read cannot validate one value and store another.

Results, claims, rejections, and all lists are frozen; a claim cannot be rebound
to another invocation or commit after ingestion.

## Non-goals

No agent execution, dispatch, or transport. No callable adapter port, Promise,
or async. No Claude, OpenAI, Codex, CodeRabbit, or GitHub API calls. No network,
filesystem, subprocess, database, Evidence Store, or persistence. No clock,
timestamp generation, or identifier generation. No polling, retries, backoff,
timeouts, deadlines, or termination logic. No Autoflow state machine,
transitions, non-terminal states, queues, scheduling, or concurrency control. No
provider, reviewer, or repair-loop selection. No GitHub mutations: no branch
creation, commits, pushes, pull-request creation, comments, or merges. No
child-pull-request conventions or branch-naming rules. No artifact
verification, existence checking, or dereferencing of a reference. No
integration detection. No freshness or staleness judgment. No merge decisions.
No approval or authority logic. No prompt or instruction payloads, credentials,
tokens, or secrets. No cost or token accounting. No fuzzy claim reconciliation
or cross-invocation deduplication.

This is one layer of the frozen V1 pipeline, not the pipeline.

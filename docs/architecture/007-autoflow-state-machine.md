# Autoflow State Machine (PR 007)

Status: V1. Superseded only by an explicit architecture decision.

## Purpose

PR 007 implements the Autoflow engine's state model: the commit-bound record of
what has been requested and what has been independently established for one unit
of work.

    trusted workflow binding + one already-normalized event
        -> immutable WorkflowState | rejection

It answers exactly one question:

> Given everything recorded so far for this repository at this exact commit, is
> this event a legal thing to record, and what is the resulting state?

It does **not** answer what should happen next. Legality is domain; selection is
policy, and policy is a later PR. There is deliberately no projection,
recommendation, ranking, or next-action API — not even a `legalEventKinds`
helper, because a public enumeration of what is permitted is one refactor away
from being read as advice.

**PR 007 performs no I/O and invokes nothing.** No agent execution, dispatch, or
transport; no provider adapters; no GitHub, Claude, OpenAI, Gemini, or CodeRabbit
calls; no network, filesystem, subprocess, database, or Evidence Store
persistence; no clock, timer, retry, backoff, timeout, polling, queue,
scheduling, or concurrency control; no Promises or async of any kind; no
artifact verification, integration detection, freshness decision, authority
decision, or merge logic; no identifier generation. Both exported functions are
pure functions of their arguments.

## State is not authority

A workflow state records that something was asked for and that something was
observed. It never states that an agent may act, that a pull request may merge,
that a repair should be dispatched, or that enough has been established. PR 003's
policy gate plus a human remain the only authority boundary.

The model deliberately contains no `exists`, `verified`, `observed`,
`integrated`, `merged`, `applied`, `validated`, `authorized`, `mergeable`,
`approved`, `mayMerge`, `ready`, `readyForMerge`, `blocking`, `findingCount`,
`freshness`, `current`, `stale`, `nextAction`, `attempt`, `retries`,
`maxAttempts`, `budget`, `deadline`, `timeout`, `backoff`, `cost`, or `converged`
field, and a test asserts that none can appear even when every event payload
plants all of them. A second test asserts no `ALLOW`, `DENY`, `ESCALATE`,
`AUTONOMOUS`, `CURRENT`, or `STALE` value reaches a serialized state, and a third
asserts the state exposes no boolean field at all.

## Fact, state, evidence, authority

The distinction the layer exists to preserve:

| Category | Definition | Owner |
| --- | --- | --- |
| **Claim** | an agent said something | PR 006 |
| **Observation** | an adapter independently observed something at an exact SHA | PR 004 evidence, produced by an adapter |
| **Derived judgment** | a pure verdict from evidence plus a trusted target | PR 004 freshness |
| **Orchestration state** | what was requested and what was admitted, in order, for one bound commit | **PR 007** |
| **Authority** | permission to act | PR 003 gate plus a human |
| **Policy** | how much, how long, how many times, whether to stop | a later PR |

Read against the lifecycle a real AgentBridge pull request goes through, only
six of eighteen distinctions are orchestration state:

| Lifecycle distinction | Category | PR 007 |
| --- | --- | --- |
| implementation requested | orchestration state | tracked invocation, `REQUESTED` |
| implementation artifact produced | claim | recorded by PR 006; never promoted |
| artifact exists remotely | observation | admitted as PR 004 evidence |
| review requested | orchestration state | tracked invocation |
| findings ingested | orchestration state | review admission |
| findings CURRENT / STALE / INVALID | derived judgment | **PR 004 only** |
| bounded repair requested | state plus policy | invocation tracked here; "bounded" is a later PR |
| repair artifact produced | claim | recorded; never promoted |
| repair integrated | observation | evidence plus `HEAD_OBSERVED` |
| HEAD changed | observation | the one event that advances a revision |
| old evidence became stale | derived judgment | implied by revision; never recomputed |
| audit / fresh review requested and completed | orchestration state | invocation `REQUESTED` then `REPORTED` |
| CI passed | observation | PR 004 evidence, `kind: 'ci-result'` |
| ready for human merge | authority plus policy | **deliberately not a state** |
| human merge executed | observation | evidence; the workflow simply closes |

## Modules

| Module | Responsibility |
| --- | --- |
| `src/domain/workflow.ts` | vocabularies, bounds, domain types, hardened readers |
| `src/domain/workflow-transitions.ts` | `openWorkflow`, `applyWorkflowEvent` |

## Vocabularies

`WorkflowStatus` is `OPEN | AWAITING_HUMAN_DECISION | CLOSED`. Three members,
deliberately: any addition such as `AWAITING_REVIEW`, `REPAIR_IN_PROGRESS`, or
`READY_FOR_MERGE` would encode either routing (repository policy) or sufficiency
(termination policy). `AWAITING_HUMAN_DECISION` states only *that* a human was
asked, never what they were asked or what an answer would permit.

`InvocationState` is `REQUESTED | REPORTED`. PR 006's `AgentReportStatus` is
terminal-only and says why: "a non-terminal state requires something to
transition it." This is that state and nothing more. There is no `CANCELLED`,
`TIMED_OUT`, `ABANDONED`, or `SUPERSEDED` — cancellation and deadlines are
termination policy, and supersession is derivable from `targetCommitSha` against
the bound commit, so deriving it here would be a second freshness answer.

`WorkflowClosure` is `HUMAN_DECISION_RECORDED | CALLER_CLOSED`. No `MERGED`,
`COMPLETED`, or `SUCCEEDED`: a merge is an observation, not a closure semantic.

`TransitionOutcome` is `APPLIED | REJECTED`. Binary on purpose — a three-valued
outcome with a "benign no-op" member would invite a caller to treat some
rejections as harmless. The nuance lives in the rejection reason, where it
cannot be skipped.

Nothing derivable is stored twice. "Work outstanding" is
`invocations.some(state === REQUESTED)` and is computed by the caller: two fields
that can disagree are a defect waiting to happen.

## Transition table

The governing principle: **recording a fact is legal whenever the workflow is not
closed; initiating work is not.**

| Event | `OPEN` | `AWAITING_HUMAN_DECISION` | `CLOSED` |
| --- | --- | --- | --- |
| `INVOCATION_REQUESTED` | applied | `WORKFLOW_AWAITING_HUMAN` | `WORKFLOW_CLOSED` |
| `INVOCATION_REPORTED` | applied | applied | `WORKFLOW_CLOSED` |
| `REVIEW_ADMITTED` | applied | applied | `WORKFLOW_CLOSED` |
| `EVIDENCE_ADMITTED`, kind ≠ `human-decision` | applied | applied, status unchanged | `WORKFLOW_CLOSED` |
| `EVIDENCE_ADMITTED`, kind = `human-decision` | applied, stays `OPEN` | applied, clears the gate → `OPEN` | `WORKFLOW_CLOSED` |
| `HEAD_OBSERVED`, different commit | applied, `revision + 1` | applied, `revision + 1`, clears the gate → `OPEN` | `WORKFLOW_CLOSED` |
| `HEAD_OBSERVED`, same commit | `HEAD_UNCHANGED` | `HEAD_UNCHANGED` | `WORKFLOW_CLOSED` |
| `HUMAN_GATE_OPENED` | applied → `AWAITING_HUMAN_DECISION` | `HUMAN_GATE_ALREADY_OPEN` | `WORKFLOW_CLOSED` |
| `CLOSE_REQUESTED` | applied → `CLOSED` | applied → `CLOSED` | `WORKFLOW_CLOSED` |

`CLOSED` is absolutely terminal: no reopen, no resurrection, no exception. A new
unit of work is a new workflow.

There is deliberately **no `HUMAN_DECISION_RECORDED` event**. A human decision is
PR 004 evidence of kind `human-decision`, arriving through `EVIDENCE_ADMITTED`.
`EvidenceFreshness` carries no verdict field, so this layer records *that* a
human decided and is structurally unable to learn *what* they decided.

### Evaluation precedence

Determinism requires one ordering. The first failure returns, and the order never
varies:

1. state readable — `WORKFLOW_UNREADABLE`
2. event readable — `EVENT_UNREADABLE`
3. kind recognised — `EVENT_KIND_UNKNOWN`
4. status is not `CLOSED` — `WORKFLOW_CLOSED`
5. payload slot well-formed — `EVENT_PAYLOAD_INVALID`
6. status posture — `WORKFLOW_AWAITING_HUMAN` / `HUMAN_GATE_ALREADY_OPEN`
7. upstream outcome — `INPUT_NOT_INGESTED` / `EVIDENCE_NOT_CURRENT`
8. payload fields — `EVENT_PAYLOAD_INVALID`
9. binding — `BINDING_MISMATCH` / `HEAD_UNCHANGED`
10. identity and replay — `DUPLICATE_*` / `UNKNOWN_INVOCATION` / `INVOCATION_ALREADY_REPORTED`
11. capacity — `CAPACITY_EXCEEDED`
12. apply

`INVOCATION_REPORTED` is the one event whose binding check follows its identity
check, because the commit it compares against comes from the tracked invocation
rather than from the workflow.

## Revision and sequence

`sequence` starts at 0 and advances by exactly one on every applied transition.
It is the total ordering and the natural optimistic-concurrency token for a later
persistence layer. It is the deliberate substitute for a clock: **this layer
reads no clock and generates no timestamp.**

`revision` starts at 0 and advances **only** on an applied `HEAD_OBSERVED`. It is
the admission key.

The two remain distinct and are never collapsed. They answer different questions:
which commit generation, versus which transition.

## HEAD is supplied, never inferred

`HEAD_OBSERVED` carries a trusted `observedCommitSha`, exactly as PR 004's
`EvidenceTarget.currentHeadSha` is a trusted argument separate from the evidence.
There is no field on any agent-controlled payload through which HEAD could be
supplied, and it cannot be an `EvidenceFreshness` because a new HEAD evaluated
against the old target is by definition `STALE`.

On an applied `HEAD_OBSERVED` the workflow rebinds, `revision` advances, prior
admissions and outstanding invocations are **retained unchanged**, and the status
becomes `OPEN` with no gate open.

**Commit ordering is never inferred.** A SHA is opaque: there is no parent check,
no ancestry test, and no "is this newer". A HEAD that returns to a previous
commit still advances the revision, so evidence admitted earlier cannot
resurrect. **Revision, not SHA alone, is the admission key**, which is what
defends against a hostile or buggy adapter replaying a HEAD.

Retained admissions from earlier revisions are not worthless — they remain true
at their own revision and commit, following PR 004's reasoning that `STALE` is
not a synonym for discarded. They simply stop counting.

### A human gate clears on a HEAD advance

A human gate is commit-bound orchestration state, not authority. It is opened
against the bound commit, so once that binding moves the gate is as stale as any
old-revision fact, and it is cleared.

Clearing removes no human authority. PR 003's gate plus the human remain the only
authority boundary, no approval is inferred, nothing is cancelled, and a decision
recorded against the superseded commit is subsequently refused as not current. A
later PR may open a new gate at the new revision when its policy requires one.

The consequence is a pinned invariant: `humanGateOpenedAtRevision` is always
`null` or exactly `revision`. Its only non-derivable content is whether a gate was
open at closure, which is why it is retained when a workflow closes. The
relationship is enforced when a state is read back and asserted by a test, so the
two values cannot disagree.

## Admission semantics

### Pull-request binding: absent and unreadable are not the same

A workflow with no pull request never consults an input's pull-request field —
there is nothing to bind against. A workflow that has one accepts an **absent**
field, because an implementation invocation may precede any pull request, and
requires an exact match otherwise.

A field that is present but **unreadable** — oversized, blank, non-string, or
behind a throwing getter — is not "absent". Treating it as absent would skip the
comparison and silently discard the exact pull-request binding, so it rejects:
`EVENT_PAYLOAD_INVALID` on the trusted invocation path, where trusted context is
all-or-nothing, and `BINDING_MISMATCH` on the report and review paths.

### Evidence — the anti-duplication mechanism

`EVIDENCE_ADMITTED` takes a PR 004 `EvidenceFreshness`, not an `EvidenceRecord`.
Freshness is never re-derived here; PR 004 already answered the question, and its
result carries the target it was answered against. The only thing left to check
is that the answer is about *this* workflow's binding:

- `state` is `CURRENT` and `reason` is `BOUND_TO_CURRENT_HEAD`;
- `targetRepositoryId` equals the workflow's repository;
- `targetHeadSha` equals the bound commit.

A caller therefore cannot launder stale evidence by judging it against a
convenient target and handing over the verdict. **No change to PR 004 was
required**: its result shape already carries everything this check needs.

Admissions are unique per `(id, revision)`. The same evidence can legitimately be
current again at a later revision, and is then a fresh admission.

### Reviews — pointers only, and unsolicited ones count as facts

`REVIEW_ADMITTED` takes a PR 005 `ReviewResult` and reads only its `outcome`,
`reviewId`, `repositoryId`, `pullRequestId`, and `reviewedCommitSha`. **Findings
are never read** — no text, no severity, no classification, and no count. A
derived summary would be a second answer that can drift from PR 005's, and a
severity reaching this layer would make findings look like policy. Findings
remain evidence.

`reviewId` is optional in PR 005 and required here: an admission nobody can
attribute is not worth recording. That is a documented caller obligation.

A review need **not** correspond to a tracked invocation. Automated forge
reviewers and human reviewers produce real reviews AgentBridge did not request,
and refusing them would make those invisible to orchestration. Admitting one:

- does not transition any invocation — only `INVOCATION_REPORTED` does that;
- does not imply it was requested, and records nothing that distinguishes the two;
- does not imply sufficiency, policy satisfaction, or authority;
- does not trigger repair, escalation, or any subsequent action.

Whether a *requested*, *attributable*, *independent*, or *specific* review is
required for a given orchestration decision is a policy question owned by a later
PR, which can determine attribution itself by cross-referencing `reviewId`
against tracked invocation ids.

### Reports bind to their own invocation

`INVOCATION_REPORTED` compares `targetCommitSha` against the **tracked
invocation's** commit, not the workflow's current one. A report arriving after
HEAD moved is a true historical fact and is recorded; discarding it would be
worse than recording it. It admits no evidence, because admission is keyed on the
current revision and runs through a different event entirely.

`reportedStatus` is carried verbatim and re-narrowed defensively, failing closed
to `unknown`. It is recorded, never branched on.

## The claim ladder is unchanged

| Rung | Assertion | Owner | PR 007 |
| --- | --- | --- | --- |
| 1 requested | AgentBridge asked agent X to do Y at SHA S | PR 006 | tracks |
| 2 reported complete | the provider says it finished | PR 006 | carries, never reads |
| 3 artifact claimed | the provider says it produced R | PR 006 | never reads |
| 4 remotely observed | an adapter verified R exists | adapter, as PR 004 evidence | admits, as a separate event |
| 5 integrated | HEAD moved | PR 004 against a new trusted HEAD | records the HEAD advance |
| 6 validated | CI, tests, or a fresh review at the new HEAD | PR 004 + PR 005 | admits |
| 7 authorized | this may merge or mutate | PR 003 gate + human | delegates |

**PR 007 adds no rung.** There is no code path from `INVOCATION_REPORTED` into
any admission list — a test slices the handler out of the source and asserts it
never mentions the admission lists or their types. Reaching rung 4 still requires
a *new record built from an independent observation*, arriving as a separate
event.

## Trust boundary

| Input | Trust | Contributes |
| --- | --- | --- |
| `WorkflowBinding` | **trusted for binding** | the identity of the run |
| `HEAD_OBSERVED.observedCommitSha` | **trusted** adapter observation | the only thing that advances a revision |
| `HUMAN_GATE_OPENED.atCommitSha` | **trusted** | which commit the gate is about |
| `CLOSE_REQUESTED.closureReason` | **trusted, inert** | an audit label that grants nothing |
| `AgentInvocation` | **trusted for binding, inert as authority** | identity, target commit, provider, agent, purpose |
| `InvocationReportResult` | pre-normalized, re-validated | reported status only |
| `ReviewResult` | pre-normalized, re-validated | that an attributable review exists |
| `EvidenceFreshness` | pre-judged, re-validated | that a CURRENT observation exists at this binding |
| `WorkflowState` argument | pre-produced, re-validated | prior state |
| `AgentReport`, `ReviewSubmission`, `EvidenceRecord` | **never accepted** | — |

Two structural rules make this enforceable:

1. **PR 007 consumes only the outputs of PR 004, PR 005, and PR 006.** There is
   no signature that accepts a raw agent payload, so a second normalizer is a
   compile-time impossibility rather than a review comment.
2. **Trusting the type is not trusting the value.** Every pre-normalized input is
   still read as hostile at runtime — own-only property access, one read per
   field into a local, guarded dereference — because a caller can hand this layer
   a hand-built object shaped like a PR 006 result.

Properties are read **own-only**. An inherited value, including one planted on
`Object.prototype` through a `__proto__` payload, is treated as absent.

A state is rebuilt from its validated snapshot on every applied transition, so
any extra property a caller attached is dropped rather than carried forward.

## Provider neutrality

**Legality never depends on `providerId`, `agentId`, `purpose`, or
`reportedStatus`.** They are recorded for audit and read by no branch. No
provider is permanently an implementer or a reviewer, no purpose grants
authority, and a provider saying it finished is not a fact: `reported-complete`
and `reported-failed` produce indistinguishable transitions.

A parametrized test runs all 128 combinations of eight provider labels —
including `system`, `root`, `admin`, and `agentbridge-internal` — four purposes,
and four reported statuses, and asserts the resulting states are identical once
the three recorded label fields are normalized. A `repair` invocation produces no
field a `review` invocation lacks.

## Identifiers reject; nothing truncates

Every identifier is exact: never trimmed, case-folded, normalised, or truncated.
Comparison is exact and case-sensitive, so a commit differing by case or padding
does not match, which fails closed — the same reasoning that keeps PR 002's
action matching and PR 004's SHA comparison exact.

There is no `truncated` flag on any PR 007 type, because there is nothing it
could describe. This layer stores no prose. `clampText` and `readText` exist only
so the reader set stays byte-equivalent to PR 005's and PR 006's and can be
pinned by the parity guard; every stored field goes through
`readExactIdentifier`.

## Bounds

| Bound | Value | Rationale |
| --- | --- | --- |
| `MAX_IDENTIFIER_LENGTH` | 256 | must equal PR 005's and PR 006's; oversize rejects |
| `MAX_TRACKED_INVOCATIONS` | 256 | caps synchronous work and memory per workflow |
| `MAX_ADMITTED_EVIDENCE` | 1 024 | as above |
| `MAX_ADMITTED_REVIEWS` | 256 | as above |
| `MAX_REVISION` | 1 000 000 | far beyond any real pull request's HEAD churn |
| `MAX_SEQUENCE` | 1 000 000 | as above |

Exceeding a bound **rejects the transition** with `CAPACITY_EXCEEDED` and returns
the identical prior state. This is a deliberate third convention: PR 004 collapses
an over-length evidence set to zero and PR 005/006 truncate and flag, but both
operate on elements of a single hostile payload. A transition instead carries
**one discrete fact**, so refusing it visibly at the call site is the only outcome
that loses nothing — silently dropping orchestration history would be the
dangerous result. A workflow that reaches a bound is an escalation signal for a
later PR, not a concern of this one.

A state whose list exceeds its own bound could not have been produced here and is
`WORKFLOW_UNREADABLE`.

## Determinism

Given identical arguments, a transition produces byte-equivalent output: no
clock, no randomness, no filesystem, no network, no environment, no mutable
global state, no identifier generation, no hashing, no async. Ordering comes from
`sequence` and `revision`. Nothing is sorted, grouped, deduplicated, or
reordered; append order is preserved, and invalid-field lists and the rejection
precedence follow fixed declaration orders.

Intrinsics (`Object.freeze`, `Object.defineProperty`, `Object.hasOwn`,
`Object.is`, `Array.isArray`, `Number.isInteger`, `String.prototype.trim`/`slice`,
`Reflect.apply`) are captured at module load, before any untrusted property
access, following the pattern established in PR 004, PR 005, and PR 006. Array
building avoids `push`, `filter`, `map`, spread over untrusted values, and
ordinary indexed assignment, so neither poisoned prototype methods nor inherited
index setters are on the path. Every field is read exactly once into a local, so
a getter that returns a different value on each read cannot validate one value
and store another.

`-0` is rejected wherever a count is read: it compares equal to `0` but does not
survive a JSON round trip as the same value, which would break byte identity.

## Immutability and fail-closed behaviour

The input state is never mutated. An applied transition returns a deeply frozen
state — the object, all three lists, and every element. A rejection returns the
**identical prior reference**, which is testable proof that nothing was partially
applied: no counter moved, no list grew, no status changed.

Every malformed input fails closed rather than throwing. `applyWorkflowEvent` is
total for every runtime input of every type: non-objects, arrays, revoked
Proxies, throwing getters, unstable getters, and prototype-polluted payloads all
produce a deterministic rejection.

## Reader independence

`workflow.ts` defines its own `clampText`, `readText`, `readExactIdentifier`,
`readOwnProperty`, `readCount`, `containsValue`, and `append` rather than
importing the equivalents from `review.ts` or `agent-invocation.ts`. This is the
same trade PR 006 recorded: the architectural independence of the hostile-input
boundaries takes precedence over deduplicating a handful of small readers, and
each module captures its own intrinsics at its own load time.

The cost of duplication is drift, so drift stays mechanically detectable.
`tests/domain/reader-parity.test.ts` now runs one shared hostile-input corpus
through **three** copies of every reader whose contract overlaps and asserts
identical results. It is the only place the three modules meet, and it is a test,
so it introduces no production dependency.

PR 007 does import frozen **vocabulary constants** from PR 004, PR 005, and
PR 006 — `FRESHNESS`, `FRESHNESS_REASON`, `EVIDENCE_KIND(S)`,
`INGESTION_OUTCOME`, `REPORT_OUTCOME`, `AGENT_REPORT_STATUSES`,
`INVOCATION_PURPOSES`. Redeclaring them would create a divergent second answer to
a question those layers own. It imports no reader, normalizer, or validator
function from any of them; in particular it does not reuse PR 006's
`findInvalidInvocationFields`, because that returns field *names* and reusing it
would force a second read of each field, reintroducing the very double-read
hazard a hostile getter exploits.

**Extracting a shared `untrusted-input.ts` remains deferred.** Doing it here
would mean modifying two already-hardened, security-reviewed boundaries inside a
PR whose scope is a state machine, and it would trade per-module intrinsic
capture — an independence property — for a single point of failure. The natural
moment to revisit it is a dedicated refactor before adapters land.

## Non-goals

No agent execution, dispatch, or transport. No callable adapter port, Promise, or
async. No Claude, OpenAI, Gemini, Codex, CodeRabbit, or GitHub API calls. No
network, filesystem, subprocess, database, Evidence Store, or persistence. No
clock, timestamp generation, or identifier generation. No polling, queues,
schedulers, retries, backoff, timeouts, deadlines, attempt limits, repair
budgets, cost or token ceilings, cancellation policy, loop termination,
convergence detection, or escalation policy. No provider, reviewer, or repair
routing — roles remain configuration resolved before an invocation is
constructed. No GitHub mutations. No artifact verification, existence checking,
or reference dereferencing. No integration detection. No freshness or staleness
judgment. No merge-readiness policy, approval logic, or authority logic. No
human-approval UI, notifications, dashboards, or metrics. No commit ancestry or
ordering inference. No invocation graph: no parent, supersession, replacement, or
causal field. Revision containment is the only relationship, and any future
causal field must be caller-supplied, optional, and inert.

This is one layer of the frozen V1 pipeline, not the pipeline.

# Action Request Envelope & Policy Gate (PR 003)

Status: V1 defaults. Superseded only by an explicit architecture decision.

## Scope

PR 003 adds the layer between an external agent and the PR 002 kernel:

    Agent request -> ActionRequest -> PolicyGate -> GateDecision

**Evaluation only. No operation is executed.** No subprocess or shell
execution, no Git invocation, no repository mutation, no GitHub API, no model
adapters, no persistence, no network calls, no configuration loading, and no
clock reads. `evaluateActionRequest` is a pure function of its arguments.

## Authority model

**Agents request actions. They do not authorize them.**

The request envelope is entirely agent-controlled, so nothing in it may grant
authority. An agent may explain why it wants something, attach evidence, or
state its confidence — none of that is authority. The gate reads exactly one
field for policy purposes, `action`, and hands it to PR 002.

Agent identity and provider cannot increase authority. A request from a model
labelled `system`, `root`, or `agentbridge-internal` gets the same answer as one
from any other label, because the gate never reads those fields when deciding.

## Modules

| Module | Responsibility |
| --- | --- |
| `src/domain/action-request.ts` | The request envelope and its traceability check |
| `src/domain/approval.ts` | Human approval state, as data |
| `src/domain/policy-gate.ts` | Gate vocabulary, `GateDecision`, `evaluateActionRequest` |

The gate reuses the PR 002 kernel and does not reimplement its policy table.
Classification travels into the result unmodified.

## The one question

`GateDecision.mayExecuteAutonomously` is the single reliable answer to:

> May AgentBridge execute this without human approval?

It is true only when both of these hold:

1. PR 002 classified the action as `ALLOW`, and
2. the envelope is traceable.

It is computed as the conjunction of exactly those two terms, one of which is
literally `decision === ALLOW`. There is no third term, no override, and no
branch that sets it true any other way. `requiresHumanApproval` is its exact
inverse, so the two can never disagree.

`ESCALATE` and unknown actions both require human review. Because PR 002 gives
unrecognized actions the same `ESCALATE` decision as dangerous ones, there is a
single fail-closed path through the gate as well.

## Gate outcomes

| Outcome | Meaning |
| --- | --- |
| `AUTONOMOUS` | Classified `ALLOW` and traceable. Autonomy granted. |
| `HUMAN_REVIEW_REQUIRED` | Classified non-`ALLOW`. A human must decide. |
| `INVALID_REQUEST` | Envelope not traceable. Fails closed regardless of action. |

This vocabulary does not restate `ALLOW` / `ESCALATE` / `DENY` — the
classifier's decision travels intact inside `classification`. It records the
gate's own conclusion, adding the envelope dimension the classifier cannot see.

### Why envelope validity can block but never grant

`requestId`, `action`, `actorId`, `repositoryId`, and `requestedAt` must be
present and non-blank. This is an *auditability* check, not an authority check.
An action nobody can trace to a requester and a repository must not run
autonomously, even when the action is on the read-only allowlist. Validity is a
second condition that can only ever remove autonomy, never add it.

## Human approval is a separate trust boundary

`ApprovalRecord` is a distinct input to the gate, not a field on the request.
An agent has no channel through which to approve its own request, because the
envelope type has no approval field at all — forgery is prevented structurally
rather than by validation.

Approval state is **recorded, not acted upon**. An `approved` record on a
non-allowed action still leaves `mayExecuteAutonomously` false. A record whose
`requestId` does not match the request is ignored, so an approval granted for a
harmless request cannot be replayed onto a dangerous one.

PR 003 deliberately does not implement the boundary that produces these records:
no approval UI, no persistence, no GitHub review integration, and no execution
after approval. Those belong to a later PR.

## What the envelope must never carry

Credentials, secrets, tokens, executable callbacks, streams, file handles, and
mutable service objects. The envelope is data. `metadata` is constrained to
string values so a caller cannot smuggle a function or a live object through it.

`rationale` and `metadata` are deliberately not echoed into `GateDecision`. They
carry no authority, and reproducing them in the decision record would suggest
they were weighed. `requestId` links the decision back to the full request.

## Result shape

`GateDecision` carries the request id, action, actor, provider, repository,
session, timestamp, the embedded PR 002 classification, the gate outcome, the
two authority booleans, the recorded approval state, a stable reason code, and
the list of invalid envelope fields.

Optional values are echoed as `null` rather than omitted, so `JSON.stringify`
cannot silently drop an authorization-relevant field. Decisions and their nested
classification are frozen, so a refusal cannot be upgraded by mutating a
returned object.

## Still not the full Policy Engine

This is a gate, not the Policy Engine. It has no rules DSL, no per-repository
policy overrides, no evidence binding to commit SHAs, no approval workflow, no
audit sink, and no execution path.

These remain **V1 defaults**. A later PR makes policy repository-configurable,
at which point the unknown-action behaviour stays non-overridable: configuration
may narrow authority, never widen it to allow the unmodeled.

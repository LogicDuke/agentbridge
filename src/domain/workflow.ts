/**
 * Autoflow workflow state: the commit-bound record of what has been requested
 * and what has been independently established for one unit of work.
 *
 *     trusted workflow binding + one already-normalized event
 *         -> immutable WorkflowState | rejection
 *
 * PR 007 scope: state and vocabulary only. This module declares the domain
 * types; `workflow-transitions.ts` holds the two pure entry points. Nothing in
 * either file invokes an agent, calls a forge, opens a socket, reads a clock,
 * touches the filesystem, spawns a process, persists anything, verifies an
 * artifact, detects integration, judges freshness, selects a provider, retries,
 * schedules, or makes a merge decision.
 *
 * The layer answers exactly one question:
 *
 *     Given everything recorded so far for this repository at this exact
 *     commit, is this event a legal thing to record, and what is the result?
 *
 * It does not answer what should happen next. Legality is domain; selection is
 * policy, and policy is a later PR. There is deliberately no projection,
 * recommendation, ranking, or next-action API.
 *
 * **PR 007 consumes only the outputs of PR 004, PR 005, and PR 006.** There is
 * no signature here that accepts an `AgentReport`, a `ReviewSubmission`, or an
 * `EvidenceRecord`, so a second normalizer is structurally impossible rather
 * than merely discouraged. Frozen vocabulary constants are imported from those
 * layers — redeclaring `FRESHNESS.CURRENT` would create a divergent second
 * answer — but no reader, normalizer, or validator function is.
 *
 * Deliberately absent, and never to be added: credentials, tokens, secrets,
 * prompt or instruction payloads, callbacks, streams, file handles, API
 * clients, mutable service objects, clocks, and metadata bags. There is no
 * field typed to accept one.
 */

import type { EvidenceKind } from './evidence.js';
import type { EvidenceFreshness } from './evidence-freshness.js';
import type { ReviewResult } from './review.js';
import type {
  AgentInvocation,
  AgentReportStatus,
  InvocationPurpose,
} from './agent-invocation.js';
import type { InvocationReportResult } from './agent-invocation-report.js';

/**
 * Intrinsics captured at module load.
 *
 * Caller-supplied state and event payloads are read through getters and Proxy
 * traps that execute *during* evaluation. Such a trap can repoint
 * `String.prototype.trim`, `Object.freeze`, and the `Array.prototype` methods
 * the evaluator would otherwise rely on afterwards — turning validation into
 * attacker-controlled code. Capturing the intrinsics here, before any untrusted
 * property access is possible, removes that lever.
 *
 * Everything downstream either uses one of these references or is written so it
 * depends on no prototype method at all. Same pattern as `evidence.ts`,
 * `review.ts`, and `agent-invocation.ts`.
 */
const objectFreeze = Object.freeze;
const objectDefineProperty = Object.defineProperty;
const objectHasOwn = Object.hasOwn;
const objectIs = Object.is;
const numberIsInteger = Number.isInteger;
const reflectApply = Reflect.apply;
// Captured unbound on purpose and invoked through `Reflect.apply`, so neither a
// poisoned prototype method nor a poisoned `Function.prototype.call` is on the
// path. `this` is supplied explicitly at every call site.
/* eslint-disable @typescript-eslint/unbound-method */
const stringTrim = String.prototype.trim;
const stringSlice = String.prototype.slice;
/* eslint-enable @typescript-eslint/unbound-method */

/**
 * Membership test that touches no prototype method.
 *
 * A plain indexed scan over a frozen list uses only `===` and own-property
 * reads, so poisoning `Set.prototype.has`, `Array.prototype.includes`,
 * `indexOf`, or the array iterator cannot influence vocabulary validation.
 */
function containsValue(list: readonly string[], value: unknown): boolean {
  for (let index = 0; index < list.length; index += 1) {
    if (list[index] === value) {
      return true;
    }
  }
  return false;
}

/** Append by defining an own element, bypassing inherited index setters. */
export function append<T>(list: T[], value: T): void {
  objectDefineProperty(list, list.length, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

/**
 * Where a unit of work stands.
 *
 * Three members, deliberately. Any additional member — `AWAITING_REVIEW`,
 * `REPAIR_IN_PROGRESS`, `READY_FOR_MERGE` — would encode either routing
 * (repository policy) or sufficiency (a later PR's termination policy).
 *
 * `AWAITING_HUMAN_DECISION` states only *that* a human was asked. It never
 * states what they were asked, what they answered, or what an answer would
 * permit: there is no field anywhere in this layer through which that could be
 * expressed. PR 003's policy gate plus the human remain the only authority.
 *
 * Anything derivable is deliberately not a status. "Work outstanding" is
 * `invocations.some(state === REQUESTED)` and is computed by the caller, never
 * stored — two fields that can disagree are a defect waiting to happen.
 */
export const WORKFLOW_STATUS = objectFreeze({
  /** Bound to a commit; work may be initiated and facts recorded. */
  OPEN: 'OPEN',
  /** A human decision has been requested and not yet recorded. */
  AWAITING_HUMAN_DECISION: 'AWAITING_HUMAN_DECISION',
  /** Terminal. No transition is legal, ever. */
  CLOSED: 'CLOSED',
} as const);

export type WorkflowStatus = (typeof WORKFLOW_STATUS)[keyof typeof WORKFLOW_STATUS];

/** Every member of the {@link WorkflowStatus} union. Frozen: validation reads it. */
export const WORKFLOW_STATUSES: readonly WorkflowStatus[] = objectFreeze([
  WORKFLOW_STATUS.OPEN,
  WORKFLOW_STATUS.AWAITING_HUMAN_DECISION,
  WORKFLOW_STATUS.CLOSED,
]);

/**
 * Where one tracked invocation stands.
 *
 * Two members, deliberately. PR 006's `AgentReportStatus` is terminal-only and
 * says so: "a non-terminal state requires something to transition it". This is
 * that state, and nothing more.
 *
 * There is no `CANCELLED`, `TIMED_OUT`, `ABANDONED`, or `SUPERSEDED`.
 * Cancellation and deadlines are termination policy, which belongs to a later
 * PR; supersession is derivable from `targetCommitSha` against the workflow's
 * bound commit, and deriving it here would be a second freshness answer.
 */
export const INVOCATION_STATE = objectFreeze({
  /** Registered against a workflow revision; no report applied. */
  REQUESTED: 'REQUESTED',
  /** A PR 006 report with outcome `INGESTED` has been applied. */
  REPORTED: 'REPORTED',
} as const);

export type InvocationState = (typeof INVOCATION_STATE)[keyof typeof INVOCATION_STATE];

/** Every member of the {@link InvocationState} union. */
export const INVOCATION_STATES: readonly InvocationState[] = objectFreeze([
  INVOCATION_STATE.REQUESTED,
  INVOCATION_STATE.REPORTED,
]);

/**
 * Why a workflow ended.
 *
 * Deliberately no `MERGED`, `COMPLETED`, `SUCCEEDED`, or `ABANDONED` member. A
 * merge is an observation recorded as evidence, never a closure semantic, and
 * "completed" would be a sufficiency claim this layer cannot make.
 *
 * Both members are trusted, inert labels. `HUMAN_DECISION_RECORDED` is *not*
 * verified against an admitted human-decision record: this layer asserts
 * nothing about why a caller closed a workflow, and the label grants nothing.
 */
export const WORKFLOW_CLOSURE = objectFreeze({
  HUMAN_DECISION_RECORDED: 'HUMAN_DECISION_RECORDED',
  CALLER_CLOSED: 'CALLER_CLOSED',
} as const);

export type WorkflowClosure = (typeof WORKFLOW_CLOSURE)[keyof typeof WORKFLOW_CLOSURE];

/** Every member of the {@link WorkflowClosure} union. */
export const WORKFLOW_CLOSURES: readonly WorkflowClosure[] = objectFreeze([
  WORKFLOW_CLOSURE.HUMAN_DECISION_RECORDED,
  WORKFLOW_CLOSURE.CALLER_CLOSED,
]);

/**
 * Outcome of one transition attempt.
 *
 * Binary on purpose. A three-valued outcome with a "benign no-op" member would
 * invite a caller to treat some rejections as harmless; the nuance lives in the
 * rejection reason instead, where it cannot be skipped.
 */
export const TRANSITION_OUTCOME = objectFreeze({
  /** Legal; a new frozen state is returned. */
  APPLIED: 'APPLIED',
  /** Not legal; the identical prior state reference is returned. */
  REJECTED: 'REJECTED',
} as const);

export type TransitionOutcome = (typeof TRANSITION_OUTCOME)[keyof typeof TRANSITION_OUTCOME];

/** Every member of the {@link TransitionOutcome} union. */
export const TRANSITION_OUTCOMES: readonly TransitionOutcome[] = objectFreeze([
  TRANSITION_OUTCOME.APPLIED,
  TRANSITION_OUTCOME.REJECTED,
]);

/**
 * The seven things that can be recorded.
 *
 * There is deliberately no `HUMAN_DECISION_RECORDED` event. A human decision is
 * PR 004 evidence of kind `human-decision`, arriving through
 * `EVIDENCE_ADMITTED`. `EvidenceFreshness` carries no verdict field, so this
 * layer records *that* a human decided and is structurally unable to learn
 * *what* they decided.
 */
export const WORKFLOW_EVENT_KIND = objectFreeze({
  INVOCATION_REQUESTED: 'INVOCATION_REQUESTED',
  INVOCATION_REPORTED: 'INVOCATION_REPORTED',
  REVIEW_ADMITTED: 'REVIEW_ADMITTED',
  EVIDENCE_ADMITTED: 'EVIDENCE_ADMITTED',
  HEAD_OBSERVED: 'HEAD_OBSERVED',
  HUMAN_GATE_OPENED: 'HUMAN_GATE_OPENED',
  CLOSE_REQUESTED: 'CLOSE_REQUESTED',
} as const);

export type WorkflowEventKind =
  (typeof WORKFLOW_EVENT_KIND)[keyof typeof WORKFLOW_EVENT_KIND];

/** Every member of the {@link WorkflowEventKind} union. */
export const WORKFLOW_EVENT_KINDS: readonly WorkflowEventKind[] = objectFreeze([
  WORKFLOW_EVENT_KIND.INVOCATION_REQUESTED,
  WORKFLOW_EVENT_KIND.INVOCATION_REPORTED,
  WORKFLOW_EVENT_KIND.REVIEW_ADMITTED,
  WORKFLOW_EVENT_KIND.EVIDENCE_ADMITTED,
  WORKFLOW_EVENT_KIND.HEAD_OBSERVED,
  WORKFLOW_EVENT_KIND.HUMAN_GATE_OPENED,
  WORKFLOW_EVENT_KIND.CLOSE_REQUESTED,
]);

/**
 * Why a transition was refused. Every member fails closed.
 *
 * A rejection never partially applies: no counter moves, no list grows, no
 * status changes, and the caller receives the identical prior state reference.
 */
export const TRANSITION_REJECTION = objectFreeze({
  /** State is not a readable, self-consistent workflow. */
  WORKFLOW_UNREADABLE: 'WORKFLOW_UNREADABLE',
  /** Event is not an object, is an array, or a read threw. */
  EVENT_UNREADABLE: 'EVENT_UNREADABLE',
  /** `kind` is absent or unrecognised. Never defaulted, never inferred. */
  EVENT_KIND_UNKNOWN: 'EVENT_KIND_UNKNOWN',
  /** Kind is known but its payload is missing or malformed. */
  EVENT_PAYLOAD_INVALID: 'EVENT_PAYLOAD_INVALID',
  /** The workflow is terminal. Every event, unconditionally. */
  WORKFLOW_CLOSED: 'WORKFLOW_CLOSED',
  /** A work-initiating event while a human gate is open. */
  WORKFLOW_AWAITING_HUMAN: 'WORKFLOW_AWAITING_HUMAN',
  /** A human gate was requested while one is already open. */
  HUMAN_GATE_ALREADY_OPEN: 'HUMAN_GATE_ALREADY_OPEN',
  /** Repository, pull request, or commit binding failed exact comparison. */
  BINDING_MISMATCH: 'BINDING_MISMATCH',
  /** A PR 005 or PR 006 result whose outcome was not `INGESTED`. */
  INPUT_NOT_INGESTED: 'INPUT_NOT_INGESTED',
  /** A PR 004 verdict that was not CURRENT, or not judged against this binding. */
  EVIDENCE_NOT_CURRENT: 'EVIDENCE_NOT_CURRENT',
  /** The invocation id is already tracked, at any revision. */
  DUPLICATE_INVOCATION_ID: 'DUPLICATE_INVOCATION_ID',
  /** A report for an invocation this workflow never requested. */
  UNKNOWN_INVOCATION: 'UNKNOWN_INVOCATION',
  /** Replay of a report against an already-reported invocation. */
  INVOCATION_ALREADY_REPORTED: 'INVOCATION_ALREADY_REPORTED',
  /** Same evidence or review id already admitted at the current revision. */
  DUPLICATE_ADMISSION: 'DUPLICATE_ADMISSION',
  /** Observed HEAD equals the bound commit. */
  HEAD_UNCHANGED: 'HEAD_UNCHANGED',
  /** A bound would be exceeded. The fact is refused, never silently dropped. */
  CAPACITY_EXCEEDED: 'CAPACITY_EXCEEDED',
} as const);

export type TransitionRejection =
  (typeof TRANSITION_REJECTION)[keyof typeof TRANSITION_REJECTION];

/** Every member of the {@link TransitionRejection} union, in declaration order. */
export const TRANSITION_REJECTIONS: readonly TransitionRejection[] = objectFreeze([
  TRANSITION_REJECTION.WORKFLOW_UNREADABLE,
  TRANSITION_REJECTION.EVENT_UNREADABLE,
  TRANSITION_REJECTION.EVENT_KIND_UNKNOWN,
  TRANSITION_REJECTION.EVENT_PAYLOAD_INVALID,
  TRANSITION_REJECTION.WORKFLOW_CLOSED,
  TRANSITION_REJECTION.WORKFLOW_AWAITING_HUMAN,
  TRANSITION_REJECTION.HUMAN_GATE_ALREADY_OPEN,
  TRANSITION_REJECTION.BINDING_MISMATCH,
  TRANSITION_REJECTION.INPUT_NOT_INGESTED,
  TRANSITION_REJECTION.EVIDENCE_NOT_CURRENT,
  TRANSITION_REJECTION.DUPLICATE_INVOCATION_ID,
  TRANSITION_REJECTION.UNKNOWN_INVOCATION,
  TRANSITION_REJECTION.INVOCATION_ALREADY_REPORTED,
  TRANSITION_REJECTION.DUPLICATE_ADMISSION,
  TRANSITION_REJECTION.HEAD_UNCHANGED,
  TRANSITION_REJECTION.CAPACITY_EXCEEDED,
]);

/**
 * V1 bounds.
 *
 * Every unbounded dimension is capped before iteration. Exceeding a cap
 * **rejects the transition**; nothing here truncates.
 *
 * This is a deliberate third convention. PR 004 collapses an over-length
 * evidence set to zero; PR 005 and PR 006 truncate and flag. Both operate on
 * elements of a single hostile payload. A transition instead carries **one
 * discrete fact**, so refusing it visibly at the call site is the only outcome
 * that loses nothing — silently dropping orchestration history would be the
 * dangerous result.
 *
 * `MAX_IDENTIFIER_LENGTH` must equal PR 005's `REVIEW_BOUNDS` and PR 006's
 * `INVOCATION_BOUNDS` identifier bound. The three boundaries share no code, so
 * the invariant is pinned by a test rather than by an import.
 */
export const WORKFLOW_BOUNDS = objectFreeze({
  /** Characters permitted in any identifier-shaped field. Oversize rejects. */
  MAX_IDENTIFIER_LENGTH: 256,
  /** Invocations tracked in one workflow, across all revisions. */
  MAX_TRACKED_INVOCATIONS: 256,
  /** Evidence admissions retained, across all revisions. */
  MAX_ADMITTED_EVIDENCE: 1_024,
  /** Review admissions retained, across all revisions. */
  MAX_ADMITTED_REVIEWS: 256,
  /** Highest reachable revision. */
  MAX_REVISION: 1_000_000,
  /** Highest reachable sequence. */
  MAX_SEQUENCE: 1_000_000,
} as const);

/**
 * Trusted binding, supplied by the caller.
 *
 * This is the **only** source of workflow identity, repository, pull request,
 * and initial commit. `pullRequestId` is a string so every binding field
 * validates uniformly; a caller holding a numeric pull-request number
 * stringifies it. It is optional because a unit of work may precede any pull
 * request.
 */
export interface WorkflowBinding {
  /** Caller-minted identity. Exact; never generated here, never truncated. */
  readonly workflowId: string;
  /** Repository this unit of work is about. */
  readonly repositoryId: string;
  /** Pull request, where one exists. Absent is not a mismatch. */
  readonly pullRequestId?: string;
  /** The commit the workflow is initially bound to. */
  readonly boundCommitSha: string;
}

/**
 * Every binding field, in declaration order.
 *
 * Invalid-field reporting walks this list, so the order of `invalidFields` is
 * deterministic and stable.
 */
export const WORKFLOW_BINDING_FIELD_ORDER = objectFreeze([
  'workflowId',
  'repositoryId',
  'pullRequestId',
  'boundCommitSha',
] as const);

/**
 * Binding fields that must always be present and valid.
 *
 * `pullRequestId` is absent because it is optional. When it *is* present it
 * must still validate: trusted context is all-or-nothing, so there is no
 * partially accepted binding and no field that degrades silently.
 */
export const REQUIRED_BINDING_FIELDS = objectFreeze([
  'workflowId',
  'repositoryId',
  'boundCommitSha',
] as const);

/**
 * One invocation this workflow asked for.
 *
 * `purpose`, `providerId`, and `agentId` are recorded for audit and are
 * **inert**: no transition's legality depends on any of them. Roles are not
 * permanently assigned to providers, and no purpose grants authority. A test
 * pins byte-identical behaviour across every provider label and purpose.
 *
 * `reportedStatus` is carried verbatim from PR 006 and is equally inert.
 * `reported-complete` and `reported-failed` produce indistinguishable
 * transitions; interpreting them is termination policy, not domain.
 */
export interface TrackedInvocation {
  readonly invocationId: string;
  /** From the trusted PR 006 binding. Permanent; never rewritten to a newer HEAD. */
  readonly targetCommitSha: string;
  /** PR 006 label. Inert: never read for legality. */
  readonly purpose: InvocationPurpose;
  /** Inert: never read for legality. */
  readonly providerId: string;
  /** Inert: never read for legality. */
  readonly agentId: string;
  readonly requestedAtRevision: number;
  readonly requestedAtSequence: number;
  readonly state: InvocationState;
  /** Carried verbatim from PR 006. Inert. `null` while `REQUESTED`. */
  readonly reportedStatus: AgentReportStatus | null;
  readonly reportedAtRevision: number | null;
  readonly reportedAtSequence: number | null;
}

/**
 * A PR 004 observation admitted at one revision.
 *
 * A pointer plus its exact commit binding — never a copy of the record, never a
 * verdict, never a summary. Admission at revision *n* is a permanent historical
 * fact: it is retained when HEAD advances, and it stops counting, because
 * admission is keyed on revision rather than on SHA alone.
 *
 * `admittedAtCommitSha` is retained so a persisted state is independently
 * auditable without a companion history table. Past bound commits are not
 * otherwise recoverable from the aggregate.
 */
export interface AdmittedEvidence {
  readonly evidenceId: string;
  /** Echoed from the PR 004 verdict. */
  readonly kind: EvidenceKind;
  /** `boundCommitSha` at the moment of admission. Permanent. */
  readonly admittedAtCommitSha: string;
  readonly admittedAtRevision: number;
  readonly admittedAtSequence: number;
}

/**
 * A PR 005 review admitted at one revision.
 *
 * A stable admission pointer and nothing more. There is deliberately no finding
 * count, severity breakdown, or finding text: a derived summary would be a
 * second answer that can drift from PR 005's, and a severity reaching this
 * layer would make findings look like policy. Findings remain evidence.
 *
 * An admitted review is not necessarily one AgentBridge requested, and carries
 * no implication of sufficiency, policy satisfaction, or authority.
 */
export interface AdmittedReview {
  readonly reviewId: string;
  /** `boundCommitSha` at the moment of admission. Permanent. */
  readonly admittedAtCommitSha: string;
  readonly admittedAtRevision: number;
  readonly admittedAtSequence: number;
}

/**
 * The aggregate.
 *
 * Every field is a primitive, `null`, or a frozen list of objects whose fields
 * are primitives or `null`, so the state is JSON-serializable and survives a
 * round trip unchanged.
 *
 * There is deliberately no `exists`, `verified`, `observed`, `integrated`,
 * `merged`, `applied`, `validated`, `authorized`, `mergeable`, `approved`,
 * `ready`, `freshness`, `current`, `stale`, `nextAction`, `attempt`, `retries`,
 * `budget`, `deadline`, `timeout`, `backoff`, `cost`, or `converged` field, and
 * a test asserts none can appear even when every event payload plants them.
 */
export interface WorkflowState {
  readonly workflowId: string;
  readonly repositoryId: string;
  readonly pullRequestId: string | null;
  /** Changes only through `HEAD_OBSERVED`. */
  readonly boundCommitSha: string;
  /** Monotonic. +1 per HEAD change. The admission key. */
  readonly revision: number;
  /** Monotonic. +1 per applied transition. The ordering primitive. */
  readonly sequence: number;
  readonly status: WorkflowStatus;
  /** Non-null exactly when `status` is `CLOSED`. */
  readonly closureReason: WorkflowClosure | null;
  /**
   * Revision at which the current human gate was opened.
   *
   * Always `null` or exactly `revision`: a HEAD advance clears the gate, so a
   * gate can never outlive the revision it was opened at. Its only
   * non-derivable content is whether a gate was open at closure. The
   * relationship is enforced when a state is read back and pinned by a test, so
   * the two values cannot disagree.
   */
  readonly humanGateOpenedAtRevision: number | null;
  readonly invocations: readonly TrackedInvocation[];
  readonly evidence: readonly AdmittedEvidence[];
  readonly reviews: readonly AdmittedReview[];
}

/** Register an invocation this workflow is asking for. Work-initiating. */
export interface InvocationRequestedEvent {
  readonly kind: typeof WORKFLOW_EVENT_KIND.INVOCATION_REQUESTED;
  /** PR 006 trusted binding. Trusted for binding, inert as authority. */
  readonly invocation: AgentInvocation;
}

/** Record that a provider reported. Fact-recording. */
export interface InvocationReportedEvent {
  readonly kind: typeof WORKFLOW_EVENT_KIND.INVOCATION_REPORTED;
  /** PR 006 output. Pre-normalized, re-validated, never re-normalized. */
  readonly report: InvocationReportResult;
}

/** Record that a review exists at the bound commit. Fact-recording. */
export interface ReviewAdmittedEvent {
  readonly kind: typeof WORKFLOW_EVENT_KIND.REVIEW_ADMITTED;
  /** PR 005 output. Pre-normalized, re-validated, never re-normalized. */
  readonly review: ReviewResult;
}

/** Record an independent observation at the bound commit. Fact-recording. */
export interface EvidenceAdmittedEvent {
  readonly kind: typeof WORKFLOW_EVENT_KIND.EVIDENCE_ADMITTED;
  /** PR 004 output. Pre-judged; freshness is never re-derived here. */
  readonly verdict: EvidenceFreshness;
}

/**
 * Rebind the workflow to a newly observed commit.
 *
 * `observedCommitSha` is **trusted** adapter input, exactly as PR 004's
 * `EvidenceTarget.currentHeadSha` is. HEAD is supplied, never inferred, and
 * never derived from agent-controlled data — there is no field on any payload
 * through which an agent could try.
 */
export interface HeadObservedEvent {
  readonly kind: typeof WORKFLOW_EVENT_KIND.HEAD_OBSERVED;
  readonly observedCommitSha: string;
}

/** Record that a human decision has been requested at the bound commit. */
export interface HumanGateOpenedEvent {
  readonly kind: typeof WORKFLOW_EVENT_KIND.HUMAN_GATE_OPENED;
  readonly atCommitSha: string;
}

/** End the workflow. Terminal; there is no reopen. */
export interface CloseRequestedEvent {
  readonly kind: typeof WORKFLOW_EVENT_KIND.CLOSE_REQUESTED;
  /** Trusted, inert label. Grants nothing and is verified against nothing. */
  readonly closureReason: WorkflowClosure;
}

/** Everything that can be recorded. */
export type WorkflowEvent =
  | InvocationRequestedEvent
  | InvocationReportedEvent
  | ReviewAdmittedEvent
  | EvidenceAdmittedEvent
  | HeadObservedEvent
  | HumanGateOpenedEvent
  | CloseRequestedEvent;

/**
 * The result of one `applyWorkflowEvent` call.
 *
 * On `REJECTED`, `state` is the **identical prior reference** — testable proof
 * that no partial application occurred.
 */
export interface TransitionResult {
  readonly outcome: TransitionOutcome;
  readonly state: WorkflowState;
  readonly rejection: TransitionRejection | null;
  /** Offending field paths, in fixed declaration order. Empty on `APPLIED`. */
  readonly invalidFields: readonly string[];
}

/**
 * The result of one `openWorkflow` call.
 *
 * Distinct from {@link TransitionResult} because there is no prior state to
 * echo: `state` is `null` exactly when `outcome` is `REJECTED`. Keeping the two
 * shapes apart is what lets `TransitionResult.state` stay non-nullable, which
 * is what the identical-reference invariant needs.
 */
export interface WorkflowOpenResult {
  readonly outcome: TransitionOutcome;
  readonly state: WorkflowState | null;
  readonly rejection: TransitionRejection | null;
  readonly invalidFields: readonly string[];
}

/**
 * Cut a string to `limit` characters using a captured `slice`.
 *
 * No identifier in this boundary is ever cut; this exists so the reader set
 * matches the PR 005 and PR 006 copies exactly and can be pinned by the parity
 * guard.
 */
export function clampText(value: string, limit: number): string {
  if (value.length <= limit) {
    return value;
  }
  const cut: unknown = reflectApply(stringSlice, value, [0, limit]);
  return typeof cut === 'string' ? cut : '';
}

/**
 * Bound an untrusted value, then narrow it to a non-blank string or `null`.
 *
 * The bound is applied before `trim`, so blankness checks never scan more than
 * the field's advertised limit. The trimmed form is never returned —
 * normalising a value before storing it would let `" abc"` and `"abc"` become
 * the same string on a boundary where exactness matters.
 */
export function readText(value: unknown, limit: number): string | null {
  if (typeof value !== 'string') {
    return null;
  }
  const bounded = clampText(value, limit);
  const trimmed: unknown = reflectApply(stringTrim, bounded, []);
  return typeof trimmed === 'string' && trimmed.length > 0 ? bounded : null;
}

/**
 * Read an exact identifier, rejecting rather than aliasing an oversized value.
 *
 * **Identifiers reject; nothing here truncates.** A truncated identifier is
 * worse than no identifier: git resolves commit prefixes, so a cut SHA can
 * falsely match a real object, and a cut workflow or invocation id can collide
 * with a different one. An oversized value becomes `null` and its prefix never
 * reaches the output at all.
 */
export function readExactIdentifier(value: unknown): string | null {
  return typeof value === 'string' && value.length <= WORKFLOW_BOUNDS.MAX_IDENTIFIER_LENGTH
    ? readText(value, WORKFLOW_BOUNDS.MAX_IDENTIFIER_LENGTH)
    : null;
}

/**
 * Read one **own** property of an untrusted object.
 *
 * Own-only on purpose: an inherited property — including one planted on
 * `Object.prototype` via a `__proto__` payload — must never supply a value the
 * caller did not actually send. Reads are guarded because an own getter or a
 * Proxy trap may throw.
 */
export function readOwnProperty(target: object, key: string): unknown {
  try {
    if (!objectHasOwn(target, key)) {
      return undefined;
    }
    return (target as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

/**
 * Narrow an untrusted value to a non-negative integer within `limit`.
 *
 * `-0` is rejected explicitly: it compares equal to `0` but does not survive a
 * JSON round trip as the same value, which would break the byte-identity
 * guarantee this layer makes.
 */
export function readCount(value: unknown, limit: number): number | null {
  if (typeof value !== 'number' || !numberIsInteger(value)) {
    return null;
  }
  if (objectIs(value, -0)) {
    return null;
  }
  return value >= 0 && value <= limit ? value : null;
}

/** Type guard: is this untrusted value a supported workflow status? */
export function isWorkflowStatus(value: unknown): value is WorkflowStatus {
  return typeof value === 'string' && containsValue(WORKFLOW_STATUSES, value);
}

/** Type guard: is this untrusted value a supported invocation state? */
export function isInvocationState(value: unknown): value is InvocationState {
  return typeof value === 'string' && containsValue(INVOCATION_STATES, value);
}

/** Type guard: is this untrusted value a supported closure reason? */
export function isWorkflowClosure(value: unknown): value is WorkflowClosure {
  return typeof value === 'string' && containsValue(WORKFLOW_CLOSURES, value);
}

/** Type guard: is this untrusted value a supported event kind? */
export function isWorkflowEventKind(value: unknown): value is WorkflowEventKind {
  return typeof value === 'string' && containsValue(WORKFLOW_EVENT_KINDS, value);
}

/**
 * Type guard for a value drawn from any frozen vocabulary list.
 *
 * Used for vocabularies this module imports rather than owns, so membership is
 * always tested against the owning layer's frozen list and never against a
 * redeclared copy that could drift.
 */
export function isVocabularyMember<T extends string>(
  list: readonly T[],
  value: unknown,
): value is T {
  return typeof value === 'string' && containsValue(list, value);
}

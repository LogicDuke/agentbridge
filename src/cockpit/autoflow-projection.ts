/**
 * Cockpit Autoflow projection (Cockpit D4, Stage A).
 *
 * Projects one **already-valid, in-process** PR 007 {@link WorkflowState} into an
 * immutable Cockpit presentation value:
 *
 *     valid WorkflowState
 *       -> verbatim orchestration facts
 *       -> mechanically derived presentation counts
 *       -> immutable Cockpit read model
 *
 * There is no reverse arrow. This module is presentation/observability only. It
 * never advances, transitions, closes, or reopens a workflow; it imports neither
 * `openWorkflow` nor `applyWorkflowEvent`; and it performs no I/O, no clock read,
 * no environment read, no filesystem, network, or subprocess access, no provider
 * invocation, no persistence, and no identifier generation.
 *
 * ## Trust boundary (D2 "Option A")
 *
 * The input is a `WorkflowState` produced by the PR 007 state machine
 * (`applyWorkflowEvent` / `openWorkflow`), which returns only deeply-frozen,
 * self-consistent, JSON-round-trippable values. D4 mirrors D2: it consumes an
 * already-validated domain value and is **not** a second reader — it accepts no
 * `unknown`, adds no `invalidFields` envelope, and re-validates nothing. The
 * future serialized/collector provenance boundary (hostile JSON re-read) is
 * explicitly deferred and, when it lands, belongs to the D1 snapshot reader, not
 * here.
 *
 * ## No second answer, no manufactured value
 *
 * Every projected fact is **echoed verbatim** from the workflow state, or is a
 * count mechanically derived from it. D4 invents nothing the domain did not
 * record and re-derives nothing another layer owns:
 *
 * - no invocation stale / superseded verdict (a `targetCommitSha` vs
 *   `boundCommitSha` comparison is PR 007's deliberately-refused second freshness
 *   answer — both SHAs are shown, no verdict is);
 * - no evidence `CURRENT`/`STALE` (PR 004, projected by D2 over the D1 snapshot,
 *   not over workflow admission pointers);
 * - no review sufficiency, current gate, next permitted transition, ready state,
 *   merge readiness, approval, authorization, permit, convergence, escalation
 *   level/reason, or reviewer budget — those belong to other layers or do not
 *   exist yet.
 *
 * `status` plus `humanGateOpenedAtRevision` are the truthful human-gate facts;
 * there is deliberately **no** `humanGateOpen` boolean — PR 007 stores no boolean
 * and nothing derivable is stored twice.
 *
 * ## Ambient-realm robustness
 *
 * Although the input is trusted, the JavaScript realm may be mutated between the
 * domain transition and this projection. Every intrinsic is captured at load; no
 * `Array.prototype` method, spread, or iterator is on the path; returned records
 * carry a `null` prototype and returned lists shadow `toJSON`, so a poisoned
 * `Object.prototype` cannot reach the projection or its JSON form. This is realm
 * robustness, not input validation — no domain field is re-validated here.
 */

import type { AgentReportStatus, InvocationPurpose } from '../domain/agent-invocation.js';
import {
  INVOCATION_STATE,
  type InvocationState,
  type TrackedInvocation,
  type WorkflowClosure,
  type WorkflowState,
  type WorkflowStatus,
} from '../domain/workflow.js';

/**
 * Intrinsics captured at module load, before any ambient mutation that could
 * follow the domain transition. Everything below uses these captured references
 * or depends on no prototype method at all.
 */
const objectFreeze = Object.freeze;
const objectDefineProperty = Object.defineProperty;
const objectSetPrototypeOf = Object.setPrototypeOf;

/**
 * One tracked invocation, projected for display in `state.invocations` order.
 *
 * `purpose`, `providerId`, `agentId`, and `reportedStatus` are echoed **inert**,
 * exactly as PR 007 records them: no branch here reads them for meaning, and no
 * provider label or purpose grants authority.
 */
export interface CockpitAutoflowInvocation {
  readonly invocationId: string;
  /** The commit this invocation was bound to. Never rewritten to a newer HEAD. */
  readonly targetCommitSha: string;
  /** PR 006 label, echoed inert. */
  readonly purpose: InvocationPurpose;
  /** Echoed inert. */
  readonly providerId: string;
  /** Echoed inert. */
  readonly agentId: string;
  readonly requestedAtRevision: number;
  readonly requestedAtSequence: number;
  readonly state: InvocationState;
  /** Carried verbatim from PR 006, echoed inert. `null` while `REQUESTED`. */
  readonly reportedStatus: AgentReportStatus | null;
  readonly reportedAtRevision: number | null;
  readonly reportedAtSequence: number | null;
}

/**
 * Counts mechanically derived from the workflow state. Each is unambiguous:
 * `invocationsTotal` is the tracked-invocation count, `requested`/`reported`
 * split it by `InvocationState`, and the admission counts are the lengths of the
 * evidence and review admission lists. No count implies sufficiency.
 */
export interface CockpitAutoflowCounts {
  readonly invocationsTotal: number;
  readonly requested: number;
  readonly reported: number;
  readonly evidenceAdmissions: number;
  readonly reviewAdmissions: number;
}

/**
 * The projection: verbatim orchestration facts plus derived presentation counts.
 *
 * Every field is a primitive, `null`, or a frozen list of frozen records, so the
 * value survives `JSON.parse(JSON.stringify(...))` unchanged. There is no
 * authority-, readiness-, freshness-, next-action-, or escalation-shaped field,
 * and no `humanGateOpen` boolean: `status` plus `humanGateOpenedAtRevision` are
 * the truthful human-gate facts.
 */
export interface CockpitAutoflowProjection {
  readonly workflowId: string;
  readonly repositoryId: string;
  readonly pullRequestId: string | null;
  readonly boundCommitSha: string;
  readonly revision: number;
  readonly sequence: number;
  readonly status: WorkflowStatus;
  readonly closureReason: WorkflowClosure | null;
  readonly humanGateOpenedAtRevision: number | null;
  /** `state.invocations` order preserved. Never sorted, filtered, or deduplicated. */
  readonly invocations: readonly CockpitAutoflowInvocation[];
  readonly counts: CockpitAutoflowCounts;
}

/**
 * Make a D4-owned descriptor immune to an inherited `Object.prototype.get` /
 * `.set`. `ToPropertyDescriptor` walks the prototype chain, so an ordinary
 * `{...}` descriptor under a poisoned realm would present accessor keys beside
 * its own data keys and be rejected by `Object.defineProperty`.
 */
function dataDescriptor(value: unknown, enumerable: boolean): PropertyDescriptor {
  const descriptor: PropertyDescriptor = {
    value,
    writable: false,
    enumerable,
    configurable: false,
  };
  objectSetPrototypeOf(descriptor, null);
  return descriptor;
}

/** Append by defining an own element: no `push`, no inherited index setter. */
function append<T>(list: T[], value: T): void {
  objectDefineProperty(list, list.length, dataDescriptor(value, true));
}

/**
 * Detach a D4 record node from the live `Object.prototype` (so a poisoned
 * inherited `toJSON` cannot reach it) and freeze it.
 */
function freezeRecord<T extends object>(record: T): Readonly<T> {
  objectSetPrototypeOf(record, null);
  return objectFreeze(record);
}

/**
 * Freeze a D4 list node. Lists keep `Array.prototype` for consumers, so the
 * inherited `toJSON` is shadowed by an own, non-enumerable, non-callable
 * `undefined` that `JSON.stringify` skips. Enumeration and structural equality
 * are unaffected.
 */
function freezeList<T>(list: T[]): readonly T[] {
  objectDefineProperty(list, 'toJSON', dataDescriptor(undefined, false));
  return objectFreeze(list);
}

/**
 * Project one valid Autoflow workflow state for Cockpit display.
 *
 * Pure, deterministic, synchronous, side-effect free, and non-mutating. The
 * returned projection is deeply frozen and fully detached from the caller's
 * state, contains only primitives and frozen records/lists, and survives
 * `JSON.parse(JSON.stringify(...))` with its enumerable data unchanged.
 *
 * Bounded by PR 007's own `WORKFLOW_BOUNDS`; D4 adds no bound of its own and
 * drops no invocation.
 *
 * @param state A `WorkflowState` produced by `openWorkflow` / `applyWorkflowEvent`.
 */
export function projectCockpitAutoflow(state: WorkflowState): CockpitAutoflowProjection {
  // The invocation list reference is read once; each element once.
  const sourceInvocations: readonly TrackedInvocation[] = state.invocations;
  const sourceLength = sourceInvocations.length;

  const invocations: CockpitAutoflowInvocation[] = [];
  let requested = 0;
  let reported = 0;

  for (let index = 0; index < sourceLength; index += 1) {
    const invocation = sourceInvocations[index];
    if (invocation === undefined) {
      continue;
    }
    // `InvocationState` is exactly REQUESTED | REPORTED, so the split is total.
    const invocationState = invocation.state;
    if (invocationState === INVOCATION_STATE.REQUESTED) {
      requested += 1;
    } else {
      reported += 1;
    }
    append(
      invocations,
      freezeRecord({
        invocationId: invocation.invocationId,
        targetCommitSha: invocation.targetCommitSha,
        purpose: invocation.purpose,
        providerId: invocation.providerId,
        agentId: invocation.agentId,
        requestedAtRevision: invocation.requestedAtRevision,
        requestedAtSequence: invocation.requestedAtSequence,
        state: invocationState,
        reportedStatus: invocation.reportedStatus,
        reportedAtRevision: invocation.reportedAtRevision,
        reportedAtSequence: invocation.reportedAtSequence,
      }),
    );
  }

  const counts: CockpitAutoflowCounts = freezeRecord({
    invocationsTotal: invocations.length,
    requested,
    reported,
    evidenceAdmissions: state.evidence.length,
    reviewAdmissions: state.reviews.length,
  });

  return freezeRecord({
    workflowId: state.workflowId,
    repositoryId: state.repositoryId,
    pullRequestId: state.pullRequestId,
    boundCommitSha: state.boundCommitSha,
    revision: state.revision,
    sequence: state.sequence,
    status: state.status,
    closureReason: state.closureReason,
    humanGateOpenedAtRevision: state.humanGateOpenedAtRevision,
    invocations: freezeList(invocations),
    counts,
  });
}

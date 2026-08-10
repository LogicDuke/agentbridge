/**
 * The policy gate: the layer between an agent's request and the PR 002 kernel.
 *
 *     Agent request -> ActionRequest -> PolicyGate -> GateDecision
 *
 * PR 003 scope: evaluation only. Nothing here executes, spawns, reads a clock,
 * touches the filesystem or network, loads configuration, or persists anything.
 * `evaluateActionRequest` is a pure function of its arguments.
 *
 * The gate does not reimplement policy. It delegates the entire question of
 * "what is this action?" to `classifyAction` from PR 002 and adds exactly one
 * thing of its own: whether the envelope is traceable enough to act on.
 */

import { type ActionClassification, classifyAction } from './classification.js';
import {
  type ActionRequest,
  findInvalidRequestFields,
  type RequiredRequestField,
} from './action-request.js';
import { APPROVAL_STATE, type ApprovalRecord, type ApprovalState } from './approval.js';
import { isAutonomouslyAllowed } from './decisions.js';

/**
 * Gate-level outcome.
 *
 * This vocabulary does not restate `ALLOW` / `ESCALATE` / `DENY`; the
 * classifier's decision travels intact inside `classification`. It records the
 * gate's own conclusion, which adds the envelope dimension the classifier
 * cannot see.
 */
export const GATE_OUTCOME = {
  /** Classified ALLOW and the envelope is traceable. Autonomy granted. */
  AUTONOMOUS: 'AUTONOMOUS',
  /** Classified non-ALLOW. A human must decide. */
  HUMAN_REVIEW_REQUIRED: 'HUMAN_REVIEW_REQUIRED',
  /** Envelope is not traceable. Fails closed regardless of classification. */
  INVALID_REQUEST: 'INVALID_REQUEST',
} as const;

export type GateOutcome = (typeof GATE_OUTCOME)[keyof typeof GATE_OUTCOME];

/** Every member of the {@link GateOutcome} union. */
export const GATE_OUTCOMES: readonly GateOutcome[] = [
  GATE_OUTCOME.AUTONOMOUS,
  GATE_OUTCOME.HUMAN_REVIEW_REQUIRED,
  GATE_OUTCOME.INVALID_REQUEST,
];

/** Stable, machine-readable rationale for a gate outcome. */
export const GATE_REASON = {
  /** The classifier allowed the action and the envelope is traceable. */
  CLASSIFICATION_ALLOWED: 'CLASSIFICATION_ALLOWED',
  /** The classifier did not allow the action. */
  CLASSIFICATION_REQUIRES_HUMAN: 'CLASSIFICATION_REQUIRES_HUMAN',
  /** One or more required envelope fields were missing or blank. */
  REQUEST_ENVELOPE_INVALID: 'REQUEST_ENVELOPE_INVALID',
} as const;

export type GateReason = (typeof GATE_REASON)[keyof typeof GATE_REASON];

/** Every member of the {@link GateReason} union. */
export const GATE_REASONS: readonly GateReason[] = [
  GATE_REASON.CLASSIFICATION_ALLOWED,
  GATE_REASON.CLASSIFICATION_REQUIRES_HUMAN,
  GATE_REASON.REQUEST_ENVELOPE_INVALID,
];

/**
 * The gate's answer about a single request.
 *
 * Optional envelope values are echoed as `null` rather than omitted, so
 * `JSON.stringify` cannot silently drop an authorization-relevant field and a
 * round trip is lossless.
 *
 * `rationale` and `metadata` are intentionally *not* echoed here. They carry no
 * authority, and reproducing them in the decision record would suggest they
 * were weighed. `requestId` links the decision back to the full request.
 */
export interface GateDecision {
  /** Correlates this decision with the originating request. */
  readonly requestId: string;
  /** The action string exactly as requested. */
  readonly action: string;
  /** The requesting agent. Audit only. */
  readonly actorId: string;
  /** The requesting agent's provider. Audit only. */
  readonly actorProvider: string;
  /** Repository the request targeted. */
  readonly repositoryId: string;
  /** Session or workflow correlation identifier, or `null`. */
  readonly sessionId: string | null;
  /** The caller-supplied request timestamp, echoed verbatim. */
  readonly requestedAt: string;
  /** The unmodified PR 002 classification of `action`. */
  readonly classification: ActionClassification;
  /** The gate's own outcome. */
  readonly outcome: GateOutcome;
  /**
   * The single reliable answer to "may AgentBridge execute this without human
   * approval?"
   *
   * True only when the classifier returned `ALLOW` *and* the envelope is
   * traceable. No other input can raise it.
   */
  readonly mayExecuteAutonomously: boolean;
  /** The exact inverse of {@link mayExecuteAutonomously}. */
  readonly requiresHumanApproval: boolean;
  /** Recorded human approval state. Never a source of autonomous authority. */
  readonly approvalState: ApprovalState;
  /** Stable, machine-readable rationale. */
  readonly reason: GateReason;
  /** Required envelope fields that were missing or blank. */
  readonly invalidFields: readonly RequiredRequestField[];
}

/**
 * Resolve the recorded approval state.
 *
 * This function reports state; it never widens authority. An `approved` record
 * on a non-allowed action still leaves `mayExecuteAutonomously` false — acting
 * on an approval is a later PR's job.
 *
 * A record whose `requestId` does not match is ignored, so an approval granted
 * for one request cannot be replayed onto another.
 */
function resolveApprovalState(
  request: ActionRequest,
  approval: ApprovalRecord | undefined,
  autonomyGranted: boolean,
): ApprovalState {
  if (autonomyGranted) {
    return APPROVAL_STATE.NOT_REQUIRED;
  }
  if (approval !== undefined && approval.requestId === request.requestId) {
    return approval.state;
  }
  return APPROVAL_STATE.PENDING;
}

/**
 * Evaluate a request against V1 policy.
 *
 * Pure, total, and deterministic: equal arguments always yield an equal result,
 * and no input throws. The gate reads no clock and performs no I/O.
 *
 * **Only `request.action` reaches the classifier.** Actor identity, provider,
 * rationale, metadata, evidence references, and session all travel to the
 * result for audit and are never consulted for policy. An agent may explain why
 * it wants something; explanation is not authority.
 *
 * `mayExecuteAutonomously` is the conjunction of two conditions, one of which
 * is literally `decision === ALLOW`. There is no third term, no override, and
 * no branch that sets it true any other way, so no combination of inputs can
 * produce autonomy for a non-allowed classification.
 *
 * @param request Untrusted envelope supplied by an agent.
 * @param approval Optional human decision from the trusted approval boundary.
 */
export function evaluateActionRequest(
  request: ActionRequest,
  approval?: ApprovalRecord,
): GateDecision {
  const classification = classifyAction(request.action);
  const invalidFields = findInvalidRequestFields(request);
  const envelopeTraceable = invalidFields.length === 0;
  const classificationAllows = isAutonomouslyAllowed(classification.decision);

  const mayExecuteAutonomously = classificationAllows && envelopeTraceable;

  let outcome: GateOutcome;
  let reason: GateReason;
  if (!envelopeTraceable) {
    outcome = GATE_OUTCOME.INVALID_REQUEST;
    reason = GATE_REASON.REQUEST_ENVELOPE_INVALID;
  } else if (classificationAllows) {
    outcome = GATE_OUTCOME.AUTONOMOUS;
    reason = GATE_REASON.CLASSIFICATION_ALLOWED;
  } else {
    outcome = GATE_OUTCOME.HUMAN_REVIEW_REQUIRED;
    reason = GATE_REASON.CLASSIFICATION_REQUIRES_HUMAN;
  }

  return Object.freeze({
    requestId: request.requestId,
    action: request.action,
    actorId: request.actorId,
    actorProvider: request.actorProvider,
    repositoryId: request.repositoryId,
    sessionId: request.sessionId ?? null,
    requestedAt: request.requestedAt,
    classification,
    outcome,
    mayExecuteAutonomously,
    requiresHumanApproval: !mayExecuteAutonomously,
    approvalState: resolveApprovalState(request, approval, mayExecuteAutonomously),
    reason,
    invalidFields,
  });
}

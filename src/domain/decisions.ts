/**
 * Policy outcomes produced by the AgentBridge domain kernel.
 *
 * A decision describes what the orchestrator is permitted to do with a
 * requested action. It does not describe what happened, because PR 002
 * executes nothing.
 */

/**
 * - `ALLOW`    — the orchestrator may proceed autonomously.
 * - `ESCALATE` — not permitted autonomously; routed to human review.
 * - `DENY`     — refused outright, with no human review path.
 *
 * V1 defaults never emit `DENY`. Every non-allowed outcome — dangerous *and*
 * unrecognized — routes to human review, so there is exactly one fail-closed
 * contract rather than two. `DENY` remains in the vocabulary because the
 * decision model must be able to express an outright refusal once policy
 * becomes repository-configurable; nothing in V1 selects it.
 */
export const DECISION = {
  ALLOW: 'ALLOW',
  DENY: 'DENY',
  ESCALATE: 'ESCALATE',
} as const;

export type Decision = (typeof DECISION)[keyof typeof DECISION];

/** Every member of the {@link Decision} union. */
export const DECISIONS: readonly Decision[] = [
  DECISION.ALLOW,
  DECISION.DENY,
  DECISION.ESCALATE,
];

/**
 * Machine-readable rationale for a decision.
 *
 * Reason codes are stable identifiers meant for logs, audit trails, and
 * assertions. Human-facing wording belongs in a presentation layer, not here.
 */
export const REASON_CODE = {
  /** Action is on the V1 read-only allowlist. */
  READ_ONLY_ACTION_ALLOWED: 'READ_ONLY_ACTION_ALLOWED',
  /** Action is modeled but carries authority a human must grant. */
  HUMAN_AUTHORITY_REQUIRED: 'HUMAN_AUTHORITY_REQUIRED',
  /**
   * Action is not modeled by the taxonomy. The kernel fails closed and routes
   * it to human review; it is never allowed autonomously.
   */
  UNRECOGNIZED_ACTION_ESCALATED: 'UNRECOGNIZED_ACTION_ESCALATED',
} as const;

export type ReasonCode = (typeof REASON_CODE)[keyof typeof REASON_CODE];

/** Every member of the {@link ReasonCode} union. */
export const REASON_CODES: readonly ReasonCode[] = [
  REASON_CODE.READ_ONLY_ACTION_ALLOWED,
  REASON_CODE.HUMAN_AUTHORITY_REQUIRED,
  REASON_CODE.UNRECOGNIZED_ACTION_ESCALATED,
];

/**
 * True when the orchestrator may proceed without human authority.
 *
 * `ALLOW` is the single autonomous outcome. Every other decision — present or
 * future — is non-autonomous by construction, so adding a decision variant
 * cannot accidentally widen autonomy.
 */
export function isAutonomouslyAllowed(decision: Decision): boolean {
  return decision === DECISION.ALLOW;
}

/**
 * Policy outcomes produced by the AgentBridge domain kernel.
 *
 * A decision describes what the orchestrator is permitted to do with a
 * requested action. It does not describe what happened, because PR 002
 * executes nothing.
 */

/**
 * - `ALLOW`    — the orchestrator may proceed autonomously.
 * - `ESCALATE` — legitimate operation, but authority belongs to a human.
 * - `DENY`     — refused; no in-band autonomous or approval path exists.
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
  /** Action is not modeled by the taxonomy; the kernel fails closed. */
  UNRECOGNIZED_ACTION_DENIED: 'UNRECOGNIZED_ACTION_DENIED',
} as const;

export type ReasonCode = (typeof REASON_CODE)[keyof typeof REASON_CODE];

/** Every member of the {@link ReasonCode} union. */
export const REASON_CODES: readonly ReasonCode[] = [
  REASON_CODE.READ_ONLY_ACTION_ALLOWED,
  REASON_CODE.HUMAN_AUTHORITY_REQUIRED,
  REASON_CODE.UNRECOGNIZED_ACTION_DENIED,
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

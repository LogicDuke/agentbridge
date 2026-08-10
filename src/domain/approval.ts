/**
 * Human approval modelled as data, on the far side of a trust boundary.
 *
 * An {@link ApprovalRecord} represents a decision a *human* made. It is a
 * separate input to the gate, never part of the agent's request envelope, so a
 * requesting agent has no field to forge. Even when a record says `approved`,
 * PR 003 does not turn that into execution authority: approval is recorded,
 * not acted upon.
 *
 * PR 003 deliberately does not implement the boundary that produces these
 * records — no approval UI, no persistence, no GitHub review integration, and
 * no execution after approval. Those belong to a later PR.
 */

export const APPROVAL_STATE = {
  /** The action is autonomously allowed; no human is needed. */
  NOT_REQUIRED: 'not-required',
  /** A human must decide and has not yet. */
  PENDING: 'pending',
  /** A human approved. Recorded only; grants no autonomous authority. */
  APPROVED: 'approved',
  /** A human refused. */
  REJECTED: 'rejected',
} as const;

export type ApprovalState = (typeof APPROVAL_STATE)[keyof typeof APPROVAL_STATE];

/** Every member of the {@link ApprovalState} union. */
export const APPROVAL_STATES: readonly ApprovalState[] = [
  APPROVAL_STATE.NOT_REQUIRED,
  APPROVAL_STATE.PENDING,
  APPROVAL_STATE.APPROVED,
  APPROVAL_STATE.REJECTED,
];

/**
 * A human decision about one specific request.
 *
 * `requestId` binds the record to a single request. The gate ignores a record
 * whose `requestId` does not match, so an approval for a harmless request
 * cannot be replayed onto a dangerous one.
 */
export interface ApprovalRecord {
  /** The request this decision applies to. Must match exactly. */
  readonly requestId: string;
  /** The state a human placed the request in. */
  readonly state: ApprovalState;
  /** Identifier of the human who decided. Audit only. */
  readonly decidedBy: string;
  /** Caller-supplied timestamp. Data, not generated inside the gate. */
  readonly decidedAt: string;
}

/**
 * The closed internal control-command vocabulary and bounded result semantics
 * for the Decision 062 post-start operator control path.
 *
 * Exactly **one** production command exists: {@link CONTROL_COMMAND.OPEN_HUMAN_GATE}.
 * There is deliberately no generic command surface, no second command, and no
 * caller-supplied `WorkflowEvent`. A hostile request that parses is projected
 * into a **fresh** {@link ControlCommand} built here from a captured literal — a
 * caller-owned object never crosses into the dispatch or workflow-authority
 * layer.
 *
 * Every outcome the channel can produce maps to exactly one member of the closed
 * {@link CONTROL_RESULT} vocabulary; nothing else is ever emitted over the wire.
 */

/** The one production command. There is no second command, ever. */
export const CONTROL_COMMAND = Object.freeze({
  /** Open the human gate on the currently open workflow. Takes no payload. */
  OPEN_HUMAN_GATE: 'OPEN_HUMAN_GATE',
} as const);

export type ControlCommandKind = (typeof CONTROL_COMMAND)[keyof typeof CONTROL_COMMAND];

/** Every member of the command vocabulary — exactly one. */
export const CONTROL_COMMANDS: readonly ControlCommandKind[] = Object.freeze([
  CONTROL_COMMAND.OPEN_HUMAN_GATE,
]);

/**
 * The trusted internal command. Minted fresh from a validated request; it
 * carries no payload, because `OPEN_HUMAN_GATE` takes none — the orchestrator
 * derives the bound commit internally (Decision 061). A closed, one-member
 * discriminated shape: no other command kind is representable.
 */
export interface ControlCommand {
  readonly command: typeof CONTROL_COMMAND.OPEN_HUMAN_GATE;
}

/**
 * The bounded, closed result vocabulary. Section 14's required distinctions:
 * applied, no workflow, gate already open / domain rejection, authentication
 * failure, malformed request, unavailable control channel.
 */
export const CONTROL_RESULT = Object.freeze({
  /** The gate was opened; the workflow advanced to `AWAITING_HUMAN_DECISION`. */
  APPLIED: 'APPLIED',
  /** No workflow is open; none was manufactured. */
  NO_WORKFLOW: 'NO_WORKFLOW',
  /** A gate is already open; the domain rejected a no-op re-open (no state change). */
  GATE_ALREADY_OPEN: 'GATE_ALREADY_OPEN',
  /** The domain rejected the transition for any other reason (no state change). */
  REJECTED: 'REJECTED',
  /** Mutual authentication failed; no dispatch occurred, nothing mutated. */
  AUTH_FAILED: 'AUTH_FAILED',
  /** The request framing/parsing was malformed; no dispatch occurred. */
  MALFORMED: 'MALFORMED',
  /** The control channel was unavailable (not verified, not listening). */
  UNAVAILABLE: 'UNAVAILABLE',
} as const);

export type ControlResultStatus = (typeof CONTROL_RESULT)[keyof typeof CONTROL_RESULT];

/** Every member of the result vocabulary, in a fixed order. */
export const CONTROL_RESULTS: readonly ControlResultStatus[] = Object.freeze([
  CONTROL_RESULT.APPLIED,
  CONTROL_RESULT.NO_WORKFLOW,
  CONTROL_RESULT.GATE_ALREADY_OPEN,
  CONTROL_RESULT.REJECTED,
  CONTROL_RESULT.AUTH_FAILED,
  CONTROL_RESULT.MALFORMED,
  CONTROL_RESULT.UNAVAILABLE,
]);

/** True when `value` is exactly the one production command literal. */
export function isControlCommandKind(value: unknown): value is ControlCommandKind {
  return value === CONTROL_COMMAND.OPEN_HUMAN_GATE;
}

/** True when `value` is a member of the closed result vocabulary. */
export function isControlResultStatus(value: unknown): value is ControlResultStatus {
  for (let index = 0; index < CONTROL_RESULTS.length; index += 1) {
    if (CONTROL_RESULTS[index] === value) {
      return true;
    }
  }
  return false;
}

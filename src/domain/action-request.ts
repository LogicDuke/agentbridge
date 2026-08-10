/**
 * The structured envelope an external agent uses to *request* an action.
 *
 * Every field here is untrusted. An agent controls all of it, so nothing in
 * this envelope may grant authority. The gate reads exactly one field —
 * `action` — to decide policy; the rest exists for traceability.
 *
 * Deliberately absent, and never to be added: credentials, secrets, tokens,
 * executable callbacks, streams, file handles, and mutable service objects.
 * The envelope is data. `metadata` is constrained to string values so a caller
 * cannot smuggle a function or a live object through it.
 *
 * Note what is *not* here: any approval field. Approval is a separate trusted
 * input (see `approval.ts`). An agent cannot approve its own request because
 * there is no channel in this type through which to try.
 */

/**
 * A request from an agent to perform an action.
 *
 * `requestedAt` is supplied by the caller as data. The gate never reads a
 * clock, which is what keeps evaluation a pure function of its arguments.
 */
export interface ActionRequest {
  /** Stable identifier for this request, used to correlate the decision. */
  readonly requestId: string;
  /** Untrusted action identifier. The only field that reaches the classifier. */
  readonly action: string;
  /** Untrusted identifier of the requesting agent. Audit only. */
  readonly actorId: string;
  /** Untrusted provider label, e.g. a model vendor. Audit only, never authority. */
  readonly actorProvider: string;
  /** Repository the request targets. */
  readonly repositoryId: string;
  /** Caller-supplied timestamp. Data, not generated inside the gate. */
  readonly requestedAt: string;
  /** Optional session or workflow correlation identifier. */
  readonly sessionId?: string;
  /** Optional agent explanation. Advisory; carries no authority. */
  readonly rationale?: string;
  /** Optional string-valued annotations. Advisory; carries no authority. */
  readonly metadata?: Readonly<Record<string, string>>;
  /** Optional references to supporting evidence. Advisory; carries no authority. */
  readonly evidenceRefs?: readonly string[];
}

/**
 * Fields that must be present and non-blank for a request to be traceable.
 *
 * These are checked for *auditability*, not authority. A malformed envelope can
 * only ever block a request; it can never grant one. An action that nobody can
 * trace back to a requester and a repository must not run autonomously, even
 * when the action itself is on the read-only allowlist.
 */
export const REQUIRED_REQUEST_FIELDS = [
  'requestId',
  'action',
  'actorId',
  'repositoryId',
  'requestedAt',
] as const;

export type RequiredRequestField = (typeof REQUIRED_REQUEST_FIELDS)[number];

/**
 * Return the required fields that are missing or blank, in declaration order.
 * Pure and total; never throws.
 */
export function findInvalidRequestFields(
  request: ActionRequest,
): readonly RequiredRequestField[] {
  return Object.freeze(
    REQUIRED_REQUEST_FIELDS.filter((field) => {
      // Read as `unknown`: the envelope arrives as untrusted external data, so
      // a required property may be absent or hold a non-string at runtime even
      // though the type says otherwise. Anything that is not a non-blank string
      // is invalid, which fails the request closed instead of throwing.
      const value: unknown = request[field];
      return typeof value !== 'string' || value.trim().length === 0;
    }),
  );
}

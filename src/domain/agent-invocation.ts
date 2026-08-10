/**
 * Provider-neutral agent invocation model.
 *
 * An invocation records *that AgentBridge asked an external agent to do
 * something, bound to an exact commit*. It is never authority, never execution,
 * and never a statement that anything happened. PR 003's policy gate remains the
 * only authority boundary, PR 004's freshness kernel remains the only judge of
 * CURRENT versus STALE, and PR 005's ingestion remains the only normalizer of
 * review findings.
 *
 * Two kinds of input meet at this boundary and are kept strictly apart:
 *
 * - **Trusted binding context** ({@link AgentInvocation}) supplied by the
 *   caller. It alone decides invocation identity, repository, pull request,
 *   target commit, provider, agent, and purpose.
 * - **Untrusted provider output** ({@link AgentReport}) produced by an external
 *   agent. It contributes a reported status, diagnostic prose, and artifact
 *   *claims*, and can never set or override a binding field.
 *
 * Provider identity and purpose are labels. Nothing here reads either one to
 * decide anything: no provider is permanently an implementer or a reviewer, and
 * `purpose: 'repair'` grants AgentBridge no write authority whatsoever. An
 * external agent that repairs something acts under its own credentials in its
 * own workspace; AgentBridge records only that it asked and what was claimed.
 *
 * Deliberately absent, and never to be added: credentials, tokens, secrets,
 * prompt or instruction payloads, callbacks, streams, file handles, API
 * clients, mutable service objects, and metadata bags. There is no field typed
 * to accept one.
 *
 * This module is self-contained on purpose. It imports nothing — not even the
 * structurally similar readers in `review.ts` — so there is no runtime
 * dependency between the PR 006 and PR 005 boundaries in either direction.
 */

/**
 * Intrinsics captured at module load.
 *
 * Untrusted provider output is read through getters and Proxy traps that
 * execute during normalization, and such a trap can repoint the prototype
 * methods this module would otherwise rely on afterwards. Capturing before any
 * untrusted access removes that lever; everything downstream uses these
 * references or depends on no prototype method at all. Same pattern as
 * `evidence.ts` and `review.ts`.
 */
const objectFreeze = Object.freeze;
const objectDefineProperty = Object.defineProperty;
const objectHasOwn = Object.hasOwn;
const reflectApply = Reflect.apply;
// Captured unbound on purpose and invoked through `Reflect.apply`, so neither a
// poisoned prototype method nor a poisoned `Function.prototype.call` is on the
// path. `this` is supplied explicitly at every call site.
/* eslint-disable @typescript-eslint/unbound-method */
const stringTrim = String.prototype.trim;
const stringSlice = String.prototype.slice;
/* eslint-enable @typescript-eslint/unbound-method */

/** Membership test that touches no prototype method. */
function containsValue(list: readonly string[], value: unknown): boolean {
  for (let index = 0; index < list.length; index += 1) {
    if (list[index] === value) {
      return true;
    }
  }
  return false;
}

/** Append by defining an own element, bypassing inherited index setters. */
function append<T>(list: T[], value: T): void {
  objectDefineProperty(list, list.length, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

/**
 * Why an agent was invoked.
 *
 * Configurable per repository; a label only. **There is deliberately no
 * `unknown` member.** Purpose is trusted caller input, so an unrecognised value
 * invalidates the invocation rather than silently reclassifying what
 * AgentBridge asked for. A caller that does not know the purpose has no
 * business dispatching.
 *
 * No code path reads a purpose to decide anything. Roles are not permanently
 * assigned to providers, and a purpose grants no authority.
 */
export const INVOCATION_PURPOSE = objectFreeze({
  REVIEW: 'review',
  IMPLEMENT: 'implement',
  REPAIR: 'repair',
  AUDIT: 'audit',
} as const);

export type InvocationPurpose =
  (typeof INVOCATION_PURPOSE)[keyof typeof INVOCATION_PURPOSE];

/** Every member of the {@link InvocationPurpose} union. */
export const INVOCATION_PURPOSES: readonly InvocationPurpose[] = objectFreeze([
  INVOCATION_PURPOSE.REVIEW,
  INVOCATION_PURPOSE.IMPLEMENT,
  INVOCATION_PURPOSE.REPAIR,
  INVOCATION_PURPOSE.AUDIT,
]);

/**
 * Status as *reported by the provider*. Untrusted, and terminal only.
 *
 * The `reported-` prefix is load-bearing: no member asserts that an artifact
 * exists, was integrated, or is correct. `reported-complete` means exactly
 * "the provider said it finished" and nothing more.
 *
 * There is deliberately no `queued`, `started`, `running`, `waiting`, or
 * `pending`. A non-terminal state requires something to transition it, and
 * transitions are an Autoflow concern, not a record-shape concern.
 *
 * `unknown` is the fail-closed value for a missing, malformed, or unrecognised
 * status. **It is not a low-risk value.** It means "the provider said something
 * we do not understand", which deserves at least as much attention as
 * `reported-failed`, and it must never decay toward `reported-complete`.
 */
export const AGENT_REPORT_STATUS = objectFreeze({
  REPORTED_COMPLETE: 'reported-complete',
  REPORTED_FAILED: 'reported-failed',
  REPORTED_CANCELLED: 'reported-cancelled',
  UNKNOWN: 'unknown',
} as const);

export type AgentReportStatus =
  (typeof AGENT_REPORT_STATUS)[keyof typeof AGENT_REPORT_STATUS];

/** Every member of the {@link AgentReportStatus} union. */
export const AGENT_REPORT_STATUSES: readonly AgentReportStatus[] = objectFreeze([
  AGENT_REPORT_STATUS.REPORTED_COMPLETE,
  AGENT_REPORT_STATUS.REPORTED_FAILED,
  AGENT_REPORT_STATUS.REPORTED_CANCELLED,
  AGENT_REPORT_STATUS.UNKNOWN,
]);

/**
 * Provider-neutral artifact kinds.
 *
 * **Zero behaviour attaches to any member.** These are audit labels: no
 * branch-naming rule, no child-pull-request convention, no forge semantics, no
 * ordering, no merge implication. `change-request` is the neutral name for what
 * a given forge calls a pull or merge request.
 */
export const ARTIFACT_TYPE = objectFreeze({
  COMMIT: 'commit',
  BRANCH: 'branch',
  CHANGE_REQUEST: 'change-request',
  PATCH: 'patch',
  REPORT: 'report',
  UNKNOWN: 'unknown',
} as const);

export type ArtifactType = (typeof ARTIFACT_TYPE)[keyof typeof ARTIFACT_TYPE];

/** Every member of the {@link ArtifactType} union. */
export const ARTIFACT_TYPES: readonly ArtifactType[] = objectFreeze([
  ARTIFACT_TYPE.COMMIT,
  ARTIFACT_TYPE.BRANCH,
  ARTIFACT_TYPE.CHANGE_REQUEST,
  ARTIFACT_TYPE.PATCH,
  ARTIFACT_TYPE.REPORT,
  ARTIFACT_TYPE.UNKNOWN,
]);

/** Why normalization refused a candidate artifact claim. */
export const CLAIM_REJECTION = objectFreeze({
  /** The candidate could not be read at all (non-object, array, or reads threw). */
  CLAIM_UNREADABLE: 'CLAIM_UNREADABLE',
  /** `reference` was absent, blank, or not a string. */
  REFERENCE_MISSING: 'REFERENCE_MISSING',
  /** `reference` exceeded the identifier bound. Rejected, never truncated. */
  REFERENCE_OVERSIZED: 'REFERENCE_OVERSIZED',
} as const);

export type ClaimRejection = (typeof CLAIM_REJECTION)[keyof typeof CLAIM_REJECTION];

/** Outcome of one report ingestion call. */
export const REPORT_OUTCOME = objectFreeze({
  /** Invocation binding validated; the report was normalized. */
  INGESTED: 'INGESTED',
  /** Invocation binding unusable; nothing was ingested. */
  INVOCATION_INVALID: 'INVOCATION_INVALID',
} as const);

export type ReportOutcome = (typeof REPORT_OUTCOME)[keyof typeof REPORT_OUTCOME];

/** Every member of the {@link ReportOutcome} union. */
export const REPORT_OUTCOMES: readonly ReportOutcome[] = objectFreeze([
  REPORT_OUTCOME.INGESTED,
  REPORT_OUTCOME.INVOCATION_INVALID,
]);

/**
 * V1 bounds.
 *
 * Provider reports are hostile input, so every unbounded dimension is capped
 * before iteration. The caps are generous for real invocations and exist only
 * to stop a payload from causing unbounded synchronous work or memory growth.
 *
 * `MAX_IDENTIFIER_LENGTH` must equal PR 005's `REVIEW_BOUNDS.MAX_IDENTIFIER_LENGTH`.
 * The two boundaries share no code, so the invariant is pinned by a test rather
 * than by an import.
 */
export const INVOCATION_BOUNDS = objectFreeze({
  /** Candidate artifact claims examined. Extras are dropped and flagged. */
  MAX_CLAIMS: 64,
  /** Characters permitted in any identifier-shaped field. Oversize rejects. */
  MAX_IDENTIFIER_LENGTH: 256,
  /** Characters retained in `reportedDetail`. The only field that is ever cut. */
  MAX_DETAIL_LENGTH: 2_048,
} as const);

/**
 * Trusted binding context, supplied by the caller.
 *
 * This is the **only** source of invocation identity, repository, pull request,
 * target commit, provider, agent, and purpose. Values echoed inside provider
 * output are never consulted for binding.
 *
 * `pullRequestId` is a string so every binding field validates uniformly; a
 * caller holding a numeric pull-request number stringifies it. It is optional
 * because an implementation invocation may precede any pull request.
 *
 * `providerId` and `agentId` are trusted for *binding* — they record which
 * adapter and which agent were asked — and are entirely **inert as authority**.
 */
export interface AgentInvocation {
  /** Caller-minted identity. Exact; never generated here, never truncated. */
  readonly invocationId: string;
  /** Repository the invocation targets. */
  readonly repositoryId: string;
  /** Pull request, where one exists. */
  readonly pullRequestId?: string;
  /** The commit this invocation is permanently bound to. */
  readonly targetCommitSha: string;
  /** Which provider adapter was asked. Metadata only, never authority. */
  readonly providerId: string;
  /** Which agent, model, or reviewer within that provider. Never authority. */
  readonly agentId: string;
  /** Why the agent was invoked. A label; grants nothing. */
  readonly purpose: InvocationPurpose;
  /** Caller-supplied timestamp. Data; no clock is read here. */
  readonly requestedAt: string;
}

/**
 * Every trusted field, in declaration order.
 *
 * Invalid-field reporting walks this list, so the order of
 * `invalidInvocationFields` is deterministic and stable.
 */
export const INVOCATION_FIELD_ORDER = objectFreeze([
  'invocationId',
  'repositoryId',
  'pullRequestId',
  'targetCommitSha',
  'providerId',
  'agentId',
  'purpose',
  'requestedAt',
] as const);

/**
 * Trusted fields that must always be present and valid.
 *
 * `pullRequestId` is absent from this list because it is optional. When it *is*
 * present it must still validate: trusted context is all-or-nothing, so there
 * is no partially accepted invocation.
 */
export const REQUIRED_INVOCATION_FIELDS = objectFreeze([
  'invocationId',
  'repositoryId',
  'targetCommitSha',
  'providerId',
  'agentId',
  'purpose',
  'requestedAt',
] as const);

/**
 * One artifact a provider claims it produced. Entirely untrusted.
 *
 * Declared shape is advisory: at runtime every property is read defensively and
 * any type may arrive. Fields not listed here are ignored.
 */
export interface ClaimedArtifactInput {
  readonly artifactType?: string;
  /** Provider-side identifier. Opaque; never resolved or dereferenced. */
  readonly reference?: string;
  /** A *claim* about a commit. Never a binding, never an evidence SHA. */
  readonly commitSha?: string;
}

/**
 * Untrusted provider output.
 *
 * `detail` is diagnostic prose only. It is bounded, echoed, and **never
 * parsed**: no status, artifact identity, routing, authority, policy, retry
 * behaviour, freshness, or lifecycle transition may ever be derived from it.
 */
export interface AgentReport {
  readonly status?: string;
  readonly detail?: string;
  readonly artifacts?: readonly ClaimedArtifactInput[];
}

/**
 * Cut a string to `limit` characters using a captured `slice`.
 *
 * Used for diagnostic prose only. No identifier in this boundary is ever cut.
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
 * normalising a value before it is stored would let `" abc"` and `"abc"` become
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
 * **Identifiers reject; only prose truncates.** A truncated identifier is worse
 * than no identifier: git resolves commit prefixes, so a cut SHA can falsely
 * match a real object, and a cut reference can name a different object
 * entirely. An oversized value therefore becomes `null` and its prefix never
 * reaches the output at all.
 */
export function readExactIdentifier(value: unknown): string | null {
  return typeof value === 'string' && value.length <= INVOCATION_BOUNDS.MAX_IDENTIFIER_LENGTH
    ? readText(value, INVOCATION_BOUNDS.MAX_IDENTIFIER_LENGTH)
    : null;
}

/**
 * Read one **own** property of an untrusted object.
 *
 * Own-only on purpose: an inherited property — including one planted on
 * `Object.prototype` via a `__proto__` payload — must never supply a value the
 * provider did not actually send. Reads are guarded because an own getter or a
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

/** Type guard: is this untrusted value a supported invocation purpose? */
export function isInvocationPurpose(value: unknown): value is InvocationPurpose {
  return typeof value === 'string' && containsValue(INVOCATION_PURPOSES, value);
}

/** Type guard: is this untrusted value a supported artifact type? */
export function isArtifactType(value: unknown): value is ArtifactType {
  return typeof value === 'string' && containsValue(ARTIFACT_TYPES, value);
}

/**
 * Narrow to a supported report status, failing closed to `unknown`.
 *
 * Matching is exact and case-sensitive. `'complete'`, `'COMPLETE'`,
 * `'reported-complete '`, `'success'`, and `'done'` are all `unknown`: this
 * boundary never interprets a provider's own status language.
 */
export function readReportStatus(value: unknown): AgentReportStatus {
  return typeof value === 'string' && containsValue(AGENT_REPORT_STATUSES, value)
    ? (value as AgentReportStatus)
    : AGENT_REPORT_STATUS.UNKNOWN;
}

/** Narrow to a supported artifact type, failing closed to `unknown`. */
export function readArtifactType(value: unknown): ArtifactType {
  return isArtifactType(value) ? value : ARTIFACT_TYPE.UNKNOWN;
}

/**
 * Return the trusted invocation fields that are missing or invalid, in
 * {@link INVOCATION_FIELD_ORDER} order.
 *
 * Pure and total; never throws. Intended for callers that want to validate an
 * invocation before dispatching it. `ingestInvocationReport` applies the
 * identical rules through its own single-read normalizer, and a test pins the
 * two to the same answer.
 *
 * Trusted context is all-or-nothing: a *present* `pullRequestId` that does not
 * validate is reported here exactly like a missing required field. Only an
 * absent (or `undefined`) `pullRequestId` is acceptable.
 */
export function findInvalidInvocationFields(
  invocation: AgentInvocation,
): readonly string[] {
  const record: unknown = invocation;
  if (typeof record !== 'object' || record === null) {
    return allRequiredFields();
  }

  const invalid: string[] = [];

  if (readExactIdentifier(readOwnProperty(record, 'invocationId')) === null) {
    append(invalid, 'invocationId');
  }
  if (readExactIdentifier(readOwnProperty(record, 'repositoryId')) === null) {
    append(invalid, 'repositoryId');
  }
  let rawPullRequestId: unknown;
  let pullRequestIdReadFailed = false;
  try {
    if (objectHasOwn(record, 'pullRequestId')) {
      rawPullRequestId = (record as Record<string, unknown>).pullRequestId;
    }
  } catch {
    pullRequestIdReadFailed = true;
  }
  if (
    pullRequestIdReadFailed ||
    (rawPullRequestId !== undefined && readExactIdentifier(rawPullRequestId) === null)
  ) {
    append(invalid, 'pullRequestId');
  }
  if (readExactIdentifier(readOwnProperty(record, 'targetCommitSha')) === null) {
    append(invalid, 'targetCommitSha');
  }
  if (readExactIdentifier(readOwnProperty(record, 'providerId')) === null) {
    append(invalid, 'providerId');
  }
  if (readExactIdentifier(readOwnProperty(record, 'agentId')) === null) {
    append(invalid, 'agentId');
  }
  if (!isInvocationPurpose(readOwnProperty(record, 'purpose'))) {
    append(invalid, 'purpose');
  }
  if (readExactIdentifier(readOwnProperty(record, 'requestedAt')) === null) {
    append(invalid, 'requestedAt');
  }

  return objectFreeze(invalid);
}

/** Every required field, for an invocation that cannot be read at all. */
function allRequiredFields(): readonly string[] {
  const all: string[] = [];
  for (let index = 0; index < REQUIRED_INVOCATION_FIELDS.length; index += 1) {
    const field = REQUIRED_INVOCATION_FIELDS[index];
    if (field !== undefined) {
      append(all, field);
    }
  }
  return objectFreeze(all);
}

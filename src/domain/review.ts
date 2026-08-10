/**
 * Review ingestion domain model.
 *
 * A review finding is *evidence about a specific commit*, never authority. It
 * records what a reviewer reported for one repository, pull request, and commit
 * SHA. It never states whether a finding should be fixed, whether a pull request
 * may merge, whether an agent may act, or whether the review is current — PR
 * 003's policy gate remains the only authority boundary and PR 004's freshness
 * kernel remains the only judge of CURRENT versus STALE.
 *
 * Two kinds of input meet here and are kept strictly apart:
 *
 * - **Trusted binding context** ({@link ReviewContext}) supplied by the caller.
 *   It alone decides repository, pull request, commit SHA, provider, reviewer,
 *   and review identity.
 * - **Untrusted reviewer content** ({@link ReviewSubmission}) produced by an
 *   agent or external reviewer. It contributes finding text only, and can never
 *   set or override a binding field.
 *
 * Provider names are metadata. Nothing here interprets a provider's own
 * severity language; provider adapters translate into this contract later.
 */

/**
 * Intrinsics captured at module load.
 *
 * Reviewer content is read through getters and Proxy traps that execute during
 * ingestion, and such a trap can repoint prototype methods the normalizer would
 * otherwise rely on afterwards. Capturing before any untrusted access removes
 * that lever; everything downstream uses these references or depends on no
 * prototype method at all. Same pattern as `evidence.ts`.
 */
const objectFreeze = Object.freeze;
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

/**
 * V1 severity vocabulary, deliberately small.
 *
 * `unknown` is the fail-closed value for a missing, malformed, or unrecognised
 * severity. **It is not a low-risk value.** A consumer must never treat
 * `unknown` as safer than `blocking`; it means "this reviewer did not say
 * something we understand", which deserves at least as much attention as a
 * recognised finding.
 */
export const REVIEW_SEVERITY = objectFreeze({
  BLOCKING: 'blocking',
  MAJOR: 'major',
  MINOR: 'minor',
  INFO: 'info',
  UNKNOWN: 'unknown',
} as const);

export type ReviewSeverity = (typeof REVIEW_SEVERITY)[keyof typeof REVIEW_SEVERITY];

/** Every member of the {@link ReviewSeverity} union. */
export const REVIEW_SEVERITIES: readonly ReviewSeverity[] = objectFreeze([
  REVIEW_SEVERITY.BLOCKING,
  REVIEW_SEVERITY.MAJOR,
  REVIEW_SEVERITY.MINOR,
  REVIEW_SEVERITY.INFO,
  REVIEW_SEVERITY.UNKNOWN,
]);

/**
 * V1 classification vocabulary.
 *
 * `other` means the reviewer supplied a recognised-but-uncategorised finding;
 * `unknown` is the fail-closed value for missing or malformed input.
 */
export const REVIEW_CLASSIFICATION = objectFreeze({
  SECURITY: 'security',
  CORRECTNESS: 'correctness',
  PERFORMANCE: 'performance',
  MAINTAINABILITY: 'maintainability',
  OTHER: 'other',
  UNKNOWN: 'unknown',
} as const);

export type ReviewClassification =
  (typeof REVIEW_CLASSIFICATION)[keyof typeof REVIEW_CLASSIFICATION];

/** Every member of the {@link ReviewClassification} union. */
export const REVIEW_CLASSIFICATIONS: readonly ReviewClassification[] = objectFreeze([
  REVIEW_CLASSIFICATION.SECURITY,
  REVIEW_CLASSIFICATION.CORRECTNESS,
  REVIEW_CLASSIFICATION.PERFORMANCE,
  REVIEW_CLASSIFICATION.MAINTAINABILITY,
  REVIEW_CLASSIFICATION.OTHER,
  REVIEW_CLASSIFICATION.UNKNOWN,
]);

/**
 * Status as *reported by the reviewer*. Reported state, never authority: a
 * `resolved` finding does not mean anything may proceed.
 */
export const REVIEW_FINDING_STATUS = objectFreeze({
  OPEN: 'open',
  RESOLVED: 'resolved',
  UNKNOWN: 'unknown',
} as const);

export type ReviewFindingStatus =
  (typeof REVIEW_FINDING_STATUS)[keyof typeof REVIEW_FINDING_STATUS];

/** Every member of the {@link ReviewFindingStatus} union. */
export const REVIEW_FINDING_STATUSES: readonly ReviewFindingStatus[] = objectFreeze([
  REVIEW_FINDING_STATUS.OPEN,
  REVIEW_FINDING_STATUS.RESOLVED,
  REVIEW_FINDING_STATUS.UNKNOWN,
]);

/** Why ingestion refused a candidate finding. */
export const REVIEW_REJECTION = objectFreeze({
  /** The candidate could not be read at all (non-object, or reads threw). */
  FINDING_UNREADABLE: 'FINDING_UNREADABLE',
  /** A required field (`title` or `message`) was missing or blank. */
  REQUIRED_FIELD_MISSING: 'REQUIRED_FIELD_MISSING',
} as const);

export type ReviewRejection = (typeof REVIEW_REJECTION)[keyof typeof REVIEW_REJECTION];

/** Outcome of an ingestion call. */
export const INGESTION_OUTCOME = objectFreeze({
  /** Binding context validated; findings were normalized. */
  INGESTED: 'INGESTED',
  /** Binding context was unusable; nothing was ingested. */
  CONTEXT_INVALID: 'CONTEXT_INVALID',
} as const);

export type IngestionOutcome = (typeof INGESTION_OUTCOME)[keyof typeof INGESTION_OUTCOME];

/** Every member of the {@link IngestionOutcome} union. */
export const INGESTION_OUTCOMES: readonly IngestionOutcome[] = objectFreeze([
  INGESTION_OUTCOME.INGESTED,
  INGESTION_OUTCOME.CONTEXT_INVALID,
]);

/**
 * V1 bounds.
 *
 * Reviewer payloads are hostile input, so every unbounded dimension is capped
 * before iteration. The caps are generous for real reviews and exist only to
 * stop a payload from causing unbounded synchronous work or memory growth.
 */
export const REVIEW_BOUNDS = objectFreeze({
  /** Candidate findings examined. Extras are dropped and flagged `truncated`. */
  MAX_FINDINGS: 1_000,
  /** Characters retained in a finding title. */
  MAX_TITLE_LENGTH: 512,
  /** Characters retained in a finding message. */
  MAX_MESSAGE_LENGTH: 8_192,
  /** Characters retained in a file path. */
  MAX_PATH_LENGTH: 1_024,
  /** Characters retained in any identifier-shaped field. */
  MAX_IDENTIFIER_LENGTH: 256,
} as const);

/**
 * Trusted binding context, supplied by the caller.
 *
 * This is the **only** source of repository, pull request, commit, provider,
 * reviewer, and review identity. Values echoed inside reviewer prose are never
 * consulted for binding. `pullRequestId` is a string so every binding field
 * validates uniformly; callers holding a numeric PR number stringify it.
 */
export interface ReviewContext {
  readonly repositoryId: string;
  readonly pullRequestId: string;
  /** The commit the review was performed against. Bound permanently. */
  readonly reviewedCommitSha: string;
  /** Provider label, e.g. a vendor name. Metadata only, never authority. */
  readonly provider: string;
  /** Reviewer or agent identifier. Metadata only, never authority. */
  readonly reviewerId: string;
  /** Review or invocation identifier, where the caller has one. */
  readonly reviewId?: string;
}

/** Binding fields that must be present and non-blank. */
export const REQUIRED_CONTEXT_FIELDS = objectFreeze([
  'repositoryId',
  'pullRequestId',
  'reviewedCommitSha',
  'provider',
  'reviewerId',
] as const);

/**
 * One candidate finding as produced by a reviewer. Entirely untrusted.
 *
 * Declared shape is advisory: at runtime every property is read defensively and
 * any type may arrive. Fields not listed here are ignored.
 */
export interface ReviewFindingInput {
  readonly title?: string;
  readonly message?: string;
  readonly severity?: string;
  readonly classification?: string;
  readonly status?: string;
  readonly filePath?: string;
  readonly startLine?: number;
  readonly endLine?: number;
  /** Provider-side thread or comment identifier. */
  readonly sourceId?: string;
  /** Provider's own identifier for the finding. */
  readonly providerFindingId?: string;
}

/** Untrusted reviewer output. */
export interface ReviewSubmission {
  readonly findings?: readonly ReviewFindingInput[];
}

/**
 * A normalized finding, permanently bound to the commit it was reviewed at.
 *
 * Every field is a primitive or `null`, so the result is JSON-serializable and
 * survives a round trip unchanged. There is deliberately no field expressing
 * permission, merge readiness, or freshness.
 */
export interface ReviewFinding {
  /** Stable identity within this review: `f<ordinal>`. */
  readonly findingId: string;
  /** Position in the submitted payload, including rejected neighbours. */
  readonly ordinal: number;
  readonly repositoryId: string;
  readonly pullRequestId: string;
  /** The reviewed commit. Never rewritten to a newer HEAD. */
  readonly reviewedCommitSha: string;
  readonly reviewId: string | null;
  readonly provider: string;
  readonly reviewerId: string;
  readonly severity: ReviewSeverity;
  readonly classification: ReviewClassification;
  readonly status: ReviewFindingStatus;
  readonly title: string;
  readonly message: string;
  readonly filePath: string | null;
  readonly startLine: number | null;
  readonly endLine: number | null;
  readonly sourceId: string | null;
  readonly providerFindingId: string | null;
  /** True when a text field hit a {@link REVIEW_BOUNDS} cap. */
  readonly truncated: boolean;
}

/** A candidate that could not be normalized. */
export interface RejectedFinding {
  readonly ordinal: number;
  readonly reason: ReviewRejection;
}

/** The result of one ingestion call. */
export interface ReviewResult {
  readonly outcome: IngestionOutcome;
  readonly repositoryId: string | null;
  readonly pullRequestId: string | null;
  readonly reviewedCommitSha: string | null;
  readonly reviewId: string | null;
  readonly provider: string | null;
  readonly reviewerId: string | null;
  readonly findings: readonly ReviewFinding[];
  readonly rejected: readonly RejectedFinding[];
  /** Binding fields that failed validation, in declaration order. */
  readonly invalidContextFields: readonly string[];
  /** True when the payload exceeded a bound and content was dropped or cut. */
  readonly truncated: boolean;
}

/**
 * Bound an untrusted value, then narrow it to a non-blank string or `null`.
 *
 * The bound is applied before `trim`, so blankness checks never scan more than
 * the field's advertised limit. The trimmed form is never returned —
 * normalising an identifier before it is stored would let `" abc"` and
 * `"abc"` become the same binding.
 */
export function readText(value: unknown, limit: number): string | null {
  if (typeof value !== 'string') {
    return null;
  }
  const bounded = clampText(value, limit);
  const trimmed: unknown = reflectApply(stringTrim, bounded, []);
  return typeof trimmed === 'string' && trimmed.length > 0 ? bounded : null;
}

/** Cut a string to `limit` characters using a captured `slice`. */
export function clampText(value: string, limit: number): string {
  if (value.length <= limit) {
    return value;
  }
  const cut: unknown = reflectApply(stringSlice, value, [0, limit]);
  return typeof cut === 'string' ? cut : '';
}

/**
 * Read one **own** property of an untrusted object.
 *
 * Own-only on purpose: an inherited property — including one planted on
 * `Object.prototype` via a `__proto__` payload — must never supply a value the
 * reviewer did not actually set. Reads are guarded because an own getter or a
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

/** Narrow to a supported severity, failing closed to `unknown`. */
export function readSeverity(value: unknown): ReviewSeverity {
  return typeof value === 'string' && containsValue(REVIEW_SEVERITIES, value)
    ? (value as ReviewSeverity)
    : REVIEW_SEVERITY.UNKNOWN;
}

/** Narrow to a supported classification, failing closed to `unknown`. */
export function readClassification(value: unknown): ReviewClassification {
  return typeof value === 'string' && containsValue(REVIEW_CLASSIFICATIONS, value)
    ? (value as ReviewClassification)
    : REVIEW_CLASSIFICATION.UNKNOWN;
}

/** Narrow to a supported status, failing closed to `unknown`. */
export function readStatus(value: unknown): ReviewFindingStatus {
  return typeof value === 'string' && containsValue(REVIEW_FINDING_STATUSES, value)
    ? (value as ReviewFindingStatus)
    : REVIEW_FINDING_STATUS.UNKNOWN;
}

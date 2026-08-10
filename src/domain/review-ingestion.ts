/**
 * Deterministic normalization of untrusted reviewer output.
 *
 *     trusted binding context + untrusted reviewer content -> ReviewResult
 *
 * PR 005 scope: normalization only. Nothing here calls GitHub, Claude, OpenAI,
 * or CodeRabbit, reads a clock, touches the filesystem or network, spawns a
 * process, persists anything, dispatches a repair, selects a reviewer, or makes
 * a merge decision. `ingestReview` is a pure function of its two arguments.
 *
 * It answers exactly one question:
 *
 *     What review findings were reported for this exact repository, pull
 *     request, and commit?
 *
 * It does not answer whether a finding should be fixed, whether a pull request
 * is safe to merge, whether an agent may act, or whether the evidence is
 * current. Freshness stays in PR 004's kernel; authority stays in PR 003's gate.
 */

import {
  clampText,
  INGESTION_OUTCOME,
  type IngestionOutcome,
  readClassification,
  readOwnProperty,
  readSeverity,
  readStatus,
  readText,
  REQUIRED_CONTEXT_FIELDS,
  REVIEW_BOUNDS,
  REVIEW_REJECTION,
  type RejectedFinding,
  type ReviewContext,
  type ReviewFinding,
  type ReviewResult,
  type ReviewSubmission,
} from './review.js';

/**
 * Intrinsics captured at module load, before any untrusted property access is
 * possible. Array handling avoids `push`, `filter`, spread, and ordinary
 * indexed assignment, so neither prototype methods nor inherited index setters
 * are on the path. Same pattern as `evidence-freshness.ts`.
 */
const objectFreeze = Object.freeze;
const objectDefineProperty = Object.defineProperty;
const arrayIsArray = Array.isArray;
const numberIsInteger = Number.isInteger;

/** Append by defining an own element, bypassing inherited index setters. */
function append<T>(list: T[], value: T): void {
  objectDefineProperty(list, list.length, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

/** Read a positive integer line number, or `null`. */
function readLine(value: unknown): number | null {
  return typeof value === 'number' && numberIsInteger(value) && value >= 1 ? value : null;
}

interface NormalizedContext {
  readonly repositoryId: string;
  readonly pullRequestId: string;
  readonly reviewedCommitSha: string;
  readonly provider: string;
  readonly reviewerId: string;
  readonly reviewId: string | null;
}

/** A finding plus whether any of its text hit a bound. */
interface Normalized {
  readonly finding: ReviewFinding | null;
  readonly rejection: RejectedFinding | null;
}

function emptyResult(invalidContextFields: readonly string[]): ReviewResult {
  return objectFreeze({
    outcome: INGESTION_OUTCOME.CONTEXT_INVALID,
    repositoryId: null,
    pullRequestId: null,
    reviewedCommitSha: null,
    reviewId: null,
    provider: null,
    reviewerId: null,
    findings: objectFreeze([]),
    rejected: objectFreeze([]),
    invalidContextFields: objectFreeze(invalidContextFields),
    truncated: false,
  });
}

/**
 * Validate the trusted binding context.
 *
 * The context is caller-supplied and therefore trusted for *binding*, but it is
 * still dereferenced, so a non-object or a throwing getter must fail closed
 * rather than abort. Every field is read exactly once.
 */
function normalizeContext(context: ReviewContext): {
  readonly normalized: NormalizedContext | null;
  readonly invalidFields: readonly string[];
} {
  const record: unknown = context;
  if (typeof record !== 'object' || record === null) {
    const all: string[] = [];
    for (let index = 0; index < REQUIRED_CONTEXT_FIELDS.length; index += 1) {
      const field = REQUIRED_CONTEXT_FIELDS[index];
      if (field !== undefined) {
        append(all, field);
      }
    }
    return { normalized: null, invalidFields: objectFreeze(all) };
  }

  const repositoryId = readText(readOwnProperty(record, 'repositoryId'));
  const pullRequestId = readText(readOwnProperty(record, 'pullRequestId'));
  const reviewedCommitSha = readText(readOwnProperty(record, 'reviewedCommitSha'));
  const provider = readText(readOwnProperty(record, 'provider'));
  const reviewerId = readText(readOwnProperty(record, 'reviewerId'));
  const reviewId = readText(readOwnProperty(record, 'reviewId'));

  const invalidFields: string[] = [];
  if (repositoryId === null) {
    append(invalidFields, 'repositoryId');
  }
  if (pullRequestId === null) {
    append(invalidFields, 'pullRequestId');
  }
  if (reviewedCommitSha === null) {
    append(invalidFields, 'reviewedCommitSha');
  }
  if (provider === null) {
    append(invalidFields, 'provider');
  }
  if (reviewerId === null) {
    append(invalidFields, 'reviewerId');
  }

  if (
    repositoryId === null ||
    pullRequestId === null ||
    reviewedCommitSha === null ||
    provider === null ||
    reviewerId === null
  ) {
    return { normalized: null, invalidFields: objectFreeze(invalidFields) };
  }

  return {
    normalized: {
      repositoryId: clampText(repositoryId, REVIEW_BOUNDS.MAX_IDENTIFIER_LENGTH),
      pullRequestId: clampText(pullRequestId, REVIEW_BOUNDS.MAX_IDENTIFIER_LENGTH),
      reviewedCommitSha: clampText(reviewedCommitSha, REVIEW_BOUNDS.MAX_IDENTIFIER_LENGTH),
      provider: clampText(provider, REVIEW_BOUNDS.MAX_IDENTIFIER_LENGTH),
      reviewerId: clampText(reviewerId, REVIEW_BOUNDS.MAX_IDENTIFIER_LENGTH),
      reviewId: reviewId === null ? null : clampText(reviewId, REVIEW_BOUNDS.MAX_IDENTIFIER_LENGTH),
    },
    invalidFields: objectFreeze(invalidFields),
  };
}

/**
 * Normalize one candidate finding.
 *
 * Binding fields come from `context` only. Nothing the reviewer supplies can
 * reach them, because they are never read from the candidate.
 */
function normalizeFinding(
  candidate: unknown,
  ordinal: number,
  context: NormalizedContext,
): Normalized {
  // An array is `typeof 'object'` but is never a plausible finding record, so
  // it is unreadable rather than merely incomplete. Keeping the two rejection
  // reasons honest matters for audit.
  let candidateIsArray = false;
  try {
    candidateIsArray = arrayIsArray(candidate);
  } catch {
    candidateIsArray = true;
  }
  if (typeof candidate !== 'object' || candidate === null || candidateIsArray) {
    return {
      finding: null,
      rejection: objectFreeze({ ordinal, reason: REVIEW_REJECTION.FINDING_UNREADABLE }),
    };
  }

  const rawTitle = readOwnProperty(candidate, 'title');
  const rawMessage = readOwnProperty(candidate, 'message');
  const rawSeverity = readOwnProperty(candidate, 'severity');
  const rawClassification = readOwnProperty(candidate, 'classification');
  const rawStatus = readOwnProperty(candidate, 'status');
  const rawFilePath = readOwnProperty(candidate, 'filePath');
  const rawStartLine = readOwnProperty(candidate, 'startLine');
  const rawEndLine = readOwnProperty(candidate, 'endLine');
  const rawSourceId = readOwnProperty(candidate, 'sourceId');
  const rawProviderFindingId = readOwnProperty(candidate, 'providerFindingId');

  const title = readText(rawTitle);
  const message = readText(rawMessage);
  if (title === null || message === null) {
    return {
      finding: null,
      rejection: objectFreeze({ ordinal, reason: REVIEW_REJECTION.REQUIRED_FIELD_MISSING }),
    };
  }

  const filePath = readText(rawFilePath);
  const sourceId = readText(rawSourceId);
  const providerFindingId = readText(rawProviderFindingId);

  const startLine = readLine(rawStartLine);
  const endLineCandidate = readLine(rawEndLine);
  // A range is kept only when it is coherent; anything else degrades to null
  // rather than throwing or inventing a location.
  const endLine =
    startLine !== null && endLineCandidate !== null && endLineCandidate >= startLine
      ? endLineCandidate
      : null;

  const clampedTitle = clampText(title, REVIEW_BOUNDS.MAX_TITLE_LENGTH);
  const clampedMessage = clampText(message, REVIEW_BOUNDS.MAX_MESSAGE_LENGTH);
  const clampedPath = filePath === null ? null : clampText(filePath, REVIEW_BOUNDS.MAX_PATH_LENGTH);
  const clampedSourceId =
    sourceId === null ? null : clampText(sourceId, REVIEW_BOUNDS.MAX_IDENTIFIER_LENGTH);
  const clampedProviderFindingId =
    providerFindingId === null
      ? null
      : clampText(providerFindingId, REVIEW_BOUNDS.MAX_IDENTIFIER_LENGTH);

  const truncated =
    clampedTitle.length !== title.length ||
    clampedMessage.length !== message.length ||
    (filePath !== null && clampedPath !== null && clampedPath.length !== filePath.length) ||
    (sourceId !== null && clampedSourceId !== null && clampedSourceId.length !== sourceId.length) ||
    (providerFindingId !== null &&
      clampedProviderFindingId !== null &&
      clampedProviderFindingId.length !== providerFindingId.length);

  return {
    finding: objectFreeze({
      findingId: `f${String(ordinal)}`,
      ordinal,
      repositoryId: context.repositoryId,
      pullRequestId: context.pullRequestId,
      reviewedCommitSha: context.reviewedCommitSha,
      reviewId: context.reviewId,
      provider: context.provider,
      reviewerId: context.reviewerId,
      severity: readSeverity(rawSeverity),
      classification: readClassification(rawClassification),
      status: readStatus(rawStatus),
      title: clampedTitle,
      message: clampedMessage,
      filePath: clampedPath,
      startLine,
      endLine,
      sourceId: clampedSourceId,
      providerFindingId: clampedProviderFindingId,
      truncated,
    }),
    rejection: null,
  };
}

/**
 * Ingest one reviewer submission.
 *
 * Pure, total, and deterministic: equal arguments always yield an equal result,
 * and no input throws. No clock, no randomness, no I/O, no global mutation.
 *
 * Binding is taken from `context` alone. Candidate findings contribute text and
 * location only; a candidate that names a different repository, pull request, or
 * commit SHA has no way to change the binding, because those properties are
 * never read from it.
 *
 * Duplicates are **preserved, not merged**. Two byte-identical candidates become
 * two findings with distinct stable `findingId`s derived from their payload
 * position, so output is deterministic without any fuzzy matching. Semantic
 * reconciliation belongs to a later layer.
 *
 * @param context Trusted binding context supplied by the caller.
 * @param submission Untrusted reviewer output.
 */
export function ingestReview(
  context: ReviewContext,
  submission: ReviewSubmission,
): ReviewResult {
  const { normalized, invalidFields } = normalizeContext(context);
  if (normalized === null) {
    return emptyResult(invalidFields);
  }

  // The candidate list is untrusted: it may be absent, a non-array, a Proxy
  // reporting an absurd length, or an array with hostile index getters. The
  // count is bounded *before* iteration so no payload can cause unbounded work.
  let rawFindings: unknown;
  const payload: unknown = submission;
  if (typeof payload === 'object' && payload !== null) {
    rawFindings = readOwnProperty(payload, 'findings');
  }

  let elements: readonly unknown[] | null = null;
  try {
    elements = arrayIsArray(rawFindings) ? (rawFindings as readonly unknown[]) : null;
  } catch {
    elements = null;
  }

  const findings: ReviewFinding[] = [];
  const rejected: RejectedFinding[] = [];
  let truncated = false;

  if (elements !== null) {
    let rawLength: unknown;
    try {
      rawLength = elements.length;
    } catch {
      rawLength = 0;
    }
    const declared =
      typeof rawLength === 'number' && numberIsInteger(rawLength) && rawLength >= 0
        ? rawLength
        : 0;
    const limit = declared > REVIEW_BOUNDS.MAX_FINDINGS ? REVIEW_BOUNDS.MAX_FINDINGS : declared;
    if (limit < declared) {
      truncated = true;
    }

    for (let index = 0; index < limit; index += 1) {
      let candidate: unknown;
      try {
        candidate = elements[index];
      } catch {
        candidate = undefined;
      }
      const outcome = normalizeFinding(candidate, index, normalized);
      if (outcome.finding !== null) {
        append(findings, outcome.finding);
        if (outcome.finding.truncated) {
          truncated = true;
        }
      } else if (outcome.rejection !== null) {
        append(rejected, outcome.rejection);
      }
    }
  }

  const ingested: IngestionOutcome = INGESTION_OUTCOME.INGESTED;
  return objectFreeze({
    outcome: ingested,
    repositoryId: normalized.repositoryId,
    pullRequestId: normalized.pullRequestId,
    reviewedCommitSha: normalized.reviewedCommitSha,
    reviewId: normalized.reviewId,
    provider: normalized.provider,
    reviewerId: normalized.reviewerId,
    findings: objectFreeze(findings),
    rejected: objectFreeze(rejected),
    invalidContextFields: objectFreeze([]),
    truncated,
  });
}

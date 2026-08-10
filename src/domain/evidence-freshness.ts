/**
 * Deterministic freshness evaluation for commit-bound evidence.
 *
 *     Evidence -> SHA binding -> freshness evaluation -> evidence status
 *
 * PR 004 scope: evaluation only. Nothing here fetches evidence, calls GitHub,
 * invokes agents, persists records, executes commands, reads a clock, touches
 * the filesystem or network, or makes a merge decision.
 *
 * This kernel answers exactly one question:
 *
 *     Is this evidence valid and current for this repository at this HEAD?
 *
 * It does not answer "may AgentBridge execute this action?" — that remains
 * PR 003's policy gate. Evidence is data, never authority.
 */

import {
  type EvidenceKind,
  type EvidenceRecord,
  type EvidenceSource,
  isEvidenceKind,
  isEvidenceSource,
  readIdentifier,
} from './evidence.js';

/**
 * Intrinsics captured at module load, before any untrusted property access is
 * possible. See the matching note in `evidence.ts`: a hostile getter or Proxy
 * trap runs mid-evaluation and could otherwise repoint these.
 *
 * Array handling below additionally avoids `push`, `filter`, and spread, so no
 * `Array.prototype` method is on the path at all. Bucket arrays are built with
 * indexed assignment on arrays this module owns.
 */
const objectFreeze = Object.freeze;
const arrayIsArray = Array.isArray;
const numberIsInteger = Number.isInteger;

/**
 * - `CURRENT`  — structurally valid, and repository + commit match the target.
 * - `STALE`    — well-formed and about this repository, but bound to a
 *                different commit than the supplied HEAD.
 * - `INVALID`  — malformed, missing provenance, or otherwise unable to take
 *                part in reconciliation for this target.
 *
 * Frozen at runtime, not merely `as const`.
 *
 * `as const` is a compile-time assertion only: a JS consumer, or a TS caller
 * using a cast, could otherwise assign `FRESHNESS.STALE = 'CURRENT'` and the
 * evaluator — which reads these properties when building its result — would
 * start reporting stale evidence as current. Freezing removes that lever.
 */
export const FRESHNESS = objectFreeze({
  CURRENT: 'CURRENT',
  STALE: 'STALE',
  INVALID: 'INVALID',
} as const);

export type FreshnessState = (typeof FRESHNESS)[keyof typeof FRESHNESS];

/** Every member of the {@link FreshnessState} union. */
export const FRESHNESS_STATES: readonly FreshnessState[] = objectFreeze([
  FRESHNESS.CURRENT,
  FRESHNESS.STALE,
  FRESHNESS.INVALID,
]);

/** Stable, machine-readable rationale for a freshness state. */
export const FRESHNESS_REASON = objectFreeze({
  /** Repository and commit both match the evaluation target. */
  BOUND_TO_CURRENT_HEAD: 'BOUND_TO_CURRENT_HEAD',
  /** About this repository, but bound to a different commit. */
  COMMIT_SHA_MISMATCH: 'COMMIT_SHA_MISMATCH',
  /** About a different repository entirely. */
  REPOSITORY_MISMATCH: 'REPOSITORY_MISMATCH',
  /** Required provenance is missing, blank, or not a supported value. */
  EVIDENCE_MALFORMED: 'EVIDENCE_MALFORMED',
  /** The caller-supplied evaluation target is itself unusable. */
  EVALUATION_TARGET_INVALID: 'EVALUATION_TARGET_INVALID',
} as const);

export type FreshnessReason = (typeof FRESHNESS_REASON)[keyof typeof FRESHNESS_REASON];

/** Every member of the {@link FreshnessReason} union. */
export const FRESHNESS_REASONS: readonly FreshnessReason[] = objectFreeze([
  FRESHNESS_REASON.BOUND_TO_CURRENT_HEAD,
  FRESHNESS_REASON.COMMIT_SHA_MISMATCH,
  FRESHNESS_REASON.REPOSITORY_MISMATCH,
  FRESHNESS_REASON.EVIDENCE_MALFORMED,
  FRESHNESS_REASON.EVALUATION_TARGET_INVALID,
]);

/**
 * The repository state evidence is evaluated against.
 *
 * This is a **trusted** input. It is a separate argument, not a field on the
 * evidence, so HEAD can never be inferred from agent-controlled data. PR 004
 * does not discover HEAD; a GitHub adapter will eventually supply it.
 */
export interface EvidenceTarget {
  readonly repositoryId: string;
  readonly currentHeadSha: string;
}

/**
 * The kernel's answer about a single evidence record.
 *
 * Echoed evidence values are `null` unless they validated as non-blank
 * strings, so a malformed record cannot put a non-string into the result.
 * Every field is a primitive or `null`, so the result is JSON-serializable and
 * survives a round trip unchanged.
 */
export interface EvidenceFreshness {
  readonly evidenceId: string | null;
  readonly repositoryId: string | null;
  readonly commitSha: string | null;
  readonly kind: EvidenceKind | null;
  readonly source: EvidenceSource | null;
  readonly targetRepositoryId: string | null;
  readonly targetHeadSha: string | null;
  readonly state: FreshnessState;
  readonly reason: FreshnessReason;
  /** Fields that failed validation, in declaration order. */
  readonly invalidFields: readonly string[];
}

function freeze(result: EvidenceFreshness): EvidenceFreshness {
  return objectFreeze({ ...result, invalidFields: objectFreeze(result.invalidFields) });
}

/** Append without `Array.prototype.push`, which an attacker may have poisoned. */
function append<T>(list: T[], value: T): void {
  list[list.length] = value;
}

/** Partition without `Array.prototype.filter`. */
function bucketFor(
  results: readonly EvidenceFreshness[],
  state: FreshnessState,
): readonly EvidenceFreshness[] {
  const bucket: EvidenceFreshness[] = [];
  for (let index = 0; index < results.length; index += 1) {
    const result = results[index];
    if (result !== undefined && result.state === state) {
      append(bucket, result);
    }
  }
  return objectFreeze(bucket);
}

/** Target field names that failed validation, without array spread. */
function targetInvalidFields(
  targetRepositoryId: string | null,
  targetHeadSha: string | null,
): readonly string[] {
  const fields: string[] = [];
  if (targetRepositoryId === null) {
    append(fields, 'target.repositoryId');
  }
  if (targetHeadSha === null) {
    append(fields, 'target.currentHeadSha');
  }
  return fields;
}

/** The result for a record that cannot be read at all. */
function malformedEvidence(
  targetRepositoryId: string | null,
  targetHeadSha: string | null,
): EvidenceFreshness {
  return freeze({
    evidenceId: null,
    repositoryId: null,
    commitSha: null,
    kind: null,
    source: null,
    targetRepositoryId,
    targetHeadSha,
    state: FRESHNESS.INVALID,
    reason: FRESHNESS_REASON.EVIDENCE_MALFORMED,
    invalidFields: ['evidence'],
  });
}

/**
 * Evaluate one evidence record against a repository HEAD.
 *
 * Pure, total, and deterministic: equal arguments always yield an equal result,
 * and no input throws. Every field of both arguments is read as `unknown` and
 * narrowed before use, so absent properties and non-string runtime values fail
 * closed instead of raising.
 *
 * **The only path to `CURRENT` is the final return**, reached only after the
 * target validates, every required field validates, the repository matches, and
 * `commitSha === currentHeadSha` by exact string equality. Each earlier guard
 * returns a non-`CURRENT` state. Nothing inside the record — verdict, status,
 * metadata, provider, actor, claimed confidence, or a literal `current: true`
 * annotation — is consulted, so nothing inside it can override a SHA mismatch.
 *
 * Comparison is exact and case-sensitive, with no trimming or normalisation.
 * A SHA that differs by case or surrounding whitespace does not match, which
 * fails closed. Format is deliberately not validated: a malformed SHA simply
 * cannot equal a trusted HEAD, so it fails closed on its own.
 *
 * @param evidence Untrusted evidence record.
 * @param target Trusted repository identity and current HEAD.
 */
export function evaluateEvidenceFreshness(
  evidence: EvidenceRecord,
  target: EvidenceTarget,
): EvidenceFreshness {
  // The target is trusted but still dereferenced, so a non-object value — or a
  // getter that throws — must fail closed rather than abort. Both identifiers
  // then read as `null`, which the target check below turns into
  // EVALUATION_TARGET_INVALID.
  const targetRecord: unknown = target;
  const targetIsObject = typeof targetRecord === 'object' && targetRecord !== null;
  let rawTargetRepositoryId: unknown;
  let rawTargetHeadSha: unknown;
  if (targetIsObject) {
    try {
      rawTargetRepositoryId = target.repositoryId;
      rawTargetHeadSha = target.currentHeadSha;
    } catch {
      rawTargetRepositoryId = undefined;
      rawTargetHeadSha = undefined;
    }
  }
  const targetRepositoryId = readIdentifier(rawTargetRepositoryId);
  const targetHeadSha = readIdentifier(rawTargetHeadSha);

  // Reject a non-object record before dereferencing it, so `null`, `undefined`,
  // and primitives fail closed instead of throwing.
  const record: unknown = evidence;
  if (typeof record !== 'object' || record === null) {
    return malformedEvidence(targetRepositoryId, targetHeadSha);
  }

  // Snapshot every freshness-relevant property exactly once. A getter or Proxy
  // can return a different value on each read, so validating one read and
  // comparing another would let a record pass validation with one SHA and be
  // matched against HEAD with a different one. Everything below reads only
  // these locals; the record is never touched again.
  //
  // The reads are guarded because a getter or `get` trap may also *throw*. A
  // hostile record must fail closed, never abort the evaluation.
  let rawEvidenceId: unknown;
  let rawRepositoryId: unknown;
  let rawCommitSha: unknown;
  let rawReference: unknown;
  let rawObservedAt: unknown;
  let rawKind: unknown;
  let rawSource: unknown;
  try {
    rawEvidenceId = evidence.evidenceId;
    rawRepositoryId = evidence.repositoryId;
    rawCommitSha = evidence.commitSha;
    rawReference = evidence.reference;
    rawObservedAt = evidence.observedAt;
    rawKind = evidence.kind;
    rawSource = evidence.source;
  } catch {
    return malformedEvidence(targetRepositoryId, targetHeadSha);
  }

  const evidenceId = readIdentifier(rawEvidenceId);
  const repositoryId = readIdentifier(rawRepositoryId);
  const commitSha = readIdentifier(rawCommitSha);
  const kind = isEvidenceKind(rawKind) ? rawKind : null;
  const source = isEvidenceSource(rawSource) ? rawSource : null;

  const base = {
    evidenceId,
    repositoryId,
    commitSha,
    kind,
    source,
    targetRepositoryId,
    targetHeadSha,
  };

  if (targetRepositoryId === null || targetHeadSha === null) {
    return freeze({
      ...base,
      state: FRESHNESS.INVALID,
      reason: FRESHNESS_REASON.EVALUATION_TARGET_INVALID,
      invalidFields: targetInvalidFields(targetRepositoryId, targetHeadSha),
    });
  }

  // Derived from the snapshot above, in REQUIRED_EVIDENCE_FIELDS order. The
  // record is deliberately not re-read here. Built with indexed appends rather
  // than array spread, so a poisoned array iterator cannot drop entries.
  const invalidFields: string[] = [];
  if (evidenceId === null) {
    append(invalidFields, 'evidenceId');
  }
  if (repositoryId === null) {
    append(invalidFields, 'repositoryId');
  }
  if (commitSha === null) {
    append(invalidFields, 'commitSha');
  }
  if (readIdentifier(rawReference) === null) {
    append(invalidFields, 'reference');
  }
  if (readIdentifier(rawObservedAt) === null) {
    append(invalidFields, 'observedAt');
  }
  if (kind === null) {
    append(invalidFields, 'kind');
  }
  if (source === null) {
    append(invalidFields, 'source');
  }

  if (invalidFields.length > 0) {
    return freeze({
      ...base,
      state: FRESHNESS.INVALID,
      reason: FRESHNESS_REASON.EVIDENCE_MALFORMED,
      invalidFields,
    });
  }

  if (repositoryId !== targetRepositoryId) {
    return freeze({
      ...base,
      state: FRESHNESS.INVALID,
      reason: FRESHNESS_REASON.REPOSITORY_MISMATCH,
      invalidFields: [],
    });
  }

  if (commitSha !== targetHeadSha) {
    return freeze({
      ...base,
      state: FRESHNESS.STALE,
      reason: FRESHNESS_REASON.COMMIT_SHA_MISMATCH,
      invalidFields: [],
    });
  }

  return freeze({
    ...base,
    state: FRESHNESS.CURRENT,
    reason: FRESHNESS_REASON.BOUND_TO_CURRENT_HEAD,
    invalidFields: [],
  });
}

/**
 * The result of evaluating a collection of evidence against one target.
 *
 * `results` preserves input order. The three buckets are filtered views of it —
 * partitioning only, with no quorum rules, required-review policy, merge
 * readiness, or reviewer requirements. Those belong to a later PR.
 */
export interface EvidenceSetEvaluation {
  readonly results: readonly EvidenceFreshness[];
  readonly current: readonly EvidenceFreshness[];
  readonly stale: readonly EvidenceFreshness[];
  readonly invalid: readonly EvidenceFreshness[];
}

/**
 * Evaluate many records against one target.
 *
 * Each record is evaluated independently by {@link evaluateEvidenceFreshness},
 * so a record's neighbours cannot change its state — there is no path by which
 * a set operation promotes a stale record to current.
 */
export function evaluateEvidenceSet(
  evidence: readonly EvidenceRecord[],
  target: EvidenceTarget,
): EvidenceSetEvaluation {
  // Snapshot the trusted target exactly once, into a frozen object of our own.
  // Records are evaluated against this copy, never the caller's object, so a
  // hostile getter on one record cannot mutate the target and change the
  // verdict of a later record in the same set.
  const targetRecord: unknown = target;
  const targetIsObject = typeof targetRecord === 'object' && targetRecord !== null;
  let rawTargetRepositoryId: unknown;
  let rawTargetHeadSha: unknown;
  if (targetIsObject) {
    try {
      rawTargetRepositoryId = target.repositoryId;
      rawTargetHeadSha = target.currentHeadSha;
    } catch {
      rawTargetRepositoryId = undefined;
      rawTargetHeadSha = undefined;
    }
  }
  const snapshotTarget: EvidenceTarget = objectFreeze({
    repositoryId: readIdentifier(rawTargetRepositoryId) ?? '',
    currentHeadSha: readIdentifier(rawTargetHeadSha) ?? '',
  });

  // A non-array collection fails closed to an empty evaluation rather than
  // throwing, matching the totality guarantee of the single-record evaluator.
  //
  // Iteration deliberately avoids the collection's own `map`: an array can
  // carry an own non-function `map`, a throwing `map` getter, or inherit a
  // poisoned `Array.prototype.map`. A plain indexed loop touches none of those.
  // `length` on a real array is a non-configurable own data property, but a
  // Proxy wrapping an array also passes `Array.isArray`, so both the length and
  // each element read are guarded. `Array.isArray` itself throws on a revoked
  // Proxy, so even that call is guarded. Input order is preserved.
  const rawRecords: unknown = evidence;
  const results: EvidenceFreshness[] = [];

  // `Array.isArray` itself throws on a revoked Proxy, so the check is guarded
  // and the narrowed reference is kept for the reads below.
  let elements: readonly unknown[] | null = null;
  try {
    elements = arrayIsArray(rawRecords) ? (rawRecords as readonly unknown[]) : null;
  } catch {
    elements = null;
  }

  if (elements !== null) {
    let rawLength: unknown;
    try {
      rawLength = elements.length;
    } catch {
      rawLength = 0;
    }
    const length =
      typeof rawLength === 'number' && numberIsInteger(rawLength) && rawLength >= 0
        ? rawLength
        : 0;

    for (let index = 0; index < length; index += 1) {
      let element: unknown;
      try {
        element = elements[index];
      } catch {
        element = undefined;
      }
      append(results, evaluateEvidenceFreshness(element as EvidenceRecord, snapshotTarget));
    }
  }

  return objectFreeze({
    results: objectFreeze(results),
    current: bucketFor(results, FRESHNESS.CURRENT),
    stale: bucketFor(results, FRESHNESS.STALE),
    invalid: bucketFor(results, FRESHNESS.INVALID),
  });
}

/** Current evidence of one kind. Reads the already-partitioned current bucket. */
export function currentEvidenceOfKind(
  evaluation: EvidenceSetEvaluation,
  kind: EvidenceKind,
): readonly EvidenceFreshness[] {
  const matches: EvidenceFreshness[] = [];
  const current = evaluation.current;
  for (let index = 0; index < current.length; index += 1) {
    const result = current[index];
    if (result !== undefined && result.kind === kind) {
      append(matches, result);
    }
  }
  return objectFreeze(matches);
}

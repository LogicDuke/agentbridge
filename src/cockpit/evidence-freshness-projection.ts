/**
 * Cockpit evidence-freshness projection (Cockpit D2).
 *
 * Projects PR 004's freshness answers for the evidence records contained in
 * one **already-validated** {@link CockpitSnapshot}:
 *
 *     validated CockpitSnapshot
 *       -> snapshot evidence read models
 *       -> minimal EvidenceRecord reconstruction
 *       -> EvidenceTarget derived from the enclosing snapshot
 *       -> PR 004 evaluateEvidenceSet()
 *       -> immutable Cockpit presentation projection
 *
 * There is no reverse arrow. This module is presentation/observability only:
 * no evidence authority, no policy, no merge readiness, no reviewer quorum, no
 * execution or repair authority, no collector, no persistence, and no
 * filesystem, network, Git/GitHub, or subprocess access.
 *
 * ## Trust boundary (Option A)
 *
 * The input is a `CockpitSnapshot` that has already passed D1's read boundary
 * (`readCockpitSnapshot`). D1 owns hostile, JSON-shaped `unknown` input and its
 * rejection; D2 owns only the projection of a valid snapshot. This module is
 * deliberately **not** a second `readCockpitSnapshot`: it adds no `invalidFields`
 * envelope, no malformed-snapshot handling, and no validation branches. A
 * zero-result projection therefore means exactly one thing — the valid snapshot
 * contains zero evidence records. Behaviour for values forced through an unsafe
 * cast is intentionally undefined; that separation of responsibilities is the
 * design, not a missing defence.
 *
 * ## Freshness authority
 *
 * PR 004 (`evidence-freshness.ts`) is the only freshness authority. D2 never
 * compares a SHA, never decides `CURRENT`/`STALE`/`INVALID` on its own, and
 * copies `state`, `reason`, and `invalidFields` verbatim from the kernel. The
 * evaluation target is built from the enclosing snapshot's identity alone:
 * `repository.repositoryId` and `repository.observedHeadSha`. Nothing inside an
 * evidence record, finding, pull request, or provenance block can become HEAD.
 *
 * Finding `advisoryFreshness` is out of scope and is never read.
 *
 * ## Ambient-realm robustness
 *
 * Although the input is trusted, the JavaScript realm may be mutated between
 * D1 validation and D2 projection. Every intrinsic this module relies on is
 * captured at load; no `Array.prototype` method, spread, or iterator is on the
 * path; returned records carry a `null` prototype and returned lists shadow
 * `toJSON`, so a poisoned `Object.prototype` cannot reach the projection or its
 * JSON form. This is realm robustness, not input validation — no D1 field is
 * re-validated here.
 */

import type { EvidenceKind, EvidenceRecord, EvidenceSource } from '../domain/evidence.js';
import {
  evaluateEvidenceSet,
  FRESHNESS,
  type EvidenceTarget,
  type FreshnessReason,
  type FreshnessState,
} from '../domain/evidence-freshness.js';
import type { CockpitSnapshot } from './read-model.js';

/**
 * Intrinsics captured at module load, before any ambient mutation that could
 * follow D1 validation. Everything below uses these captured references or
 * depends on no prototype method at all.
 */
const objectFreeze = Object.freeze;
const objectDefineProperty = Object.defineProperty;
const objectSetPrototypeOf = Object.setPrototypeOf;

/** One evidence record's projected freshness, in `snapshot.evidence` order. */
export interface CockpitEvidenceFreshnessItem {
  readonly evidenceId: string;
  readonly kind: EvidenceKind;
  readonly source: EvidenceSource;
  /** The commit the evidence is bound to. Data, never the evaluation HEAD. */
  readonly commitSha: string;
  /** PR 004's state, verbatim. */
  readonly state: FreshnessState;
  /** PR 004's reason, verbatim. */
  readonly reason: FreshnessReason;
  /** PR 004's invalid-field list, verbatim (empty for a valid D1 snapshot). */
  readonly invalidFields: readonly string[];
}

/**
 * Summary counts over `results`. `invalid` mirrors the complete PR 004
 * vocabulary; a contract-valid D1 snapshot is expected to yield `0` there.
 */
export interface CockpitEvidenceFreshnessCounts {
  readonly current: number;
  readonly stale: number;
  readonly invalid: number;
  readonly total: number;
}

/**
 * The projection: flat, input-ordered results plus summary counts. No
 * `current[]`/`stale[]`/`invalid[]` buckets — they would only duplicate
 * derivable presentation data.
 */
export interface CockpitEvidenceFreshnessProjection {
  /** Injected from `snapshot.repository.repositoryId`. */
  readonly repositoryId: string;
  /** The only target HEAD: `snapshot.repository.observedHeadSha`. */
  readonly observedHeadSha: string;
  /** `results[i]` corresponds to `snapshot.evidence[i]`. Never sorted, filtered, or deduplicated. */
  readonly results: readonly CockpitEvidenceFreshnessItem[];
  readonly counts: CockpitEvidenceFreshnessCounts;
}

/**
 * Make a D2-owned descriptor immune to an inherited `Object.prototype.get` /
 * `.set`. `ToPropertyDescriptor` walks the prototype chain, so an ordinary
 * `{...}` descriptor under a poisoned realm would present accessor keys beside
 * its own data keys and be rejected by `Object.defineProperty`.
 */
function dataDescriptor(value: unknown, enumerable: boolean): PropertyDescriptor {
  const descriptor: PropertyDescriptor = {
    value,
    writable: false,
    enumerable,
    configurable: false,
  };
  objectSetPrototypeOf(descriptor, null);
  return descriptor;
}

/** Append by defining an own element: no `push`, no inherited index setter. */
function append<T>(list: T[], value: T): void {
  objectDefineProperty(list, list.length, dataDescriptor(value, true));
}

/**
 * Detach a D2 record node from the live `Object.prototype` (so a poisoned
 * inherited `toJSON` cannot reach it) and freeze it.
 */
function freezeRecord<T extends object>(record: T): Readonly<T> {
  objectSetPrototypeOf(record, null);
  return objectFreeze(record);
}

/**
 * Freeze a D2 list node. Lists keep `Array.prototype` for consumers, so the
 * inherited `toJSON` is shadowed by an own, non-enumerable, non-callable
 * `undefined` that `JSON.stringify` skips. Enumeration and structural equality
 * are unaffected.
 */
function freezeList<T>(list: T[]): readonly T[] {
  objectDefineProperty(list, 'toJSON', dataDescriptor(undefined, false));
  return objectFreeze(list);
}

/** Copy PR 004's `invalidFields` into a D2-owned frozen list, element by element. */
function copyInvalidFields(source: readonly string[]): readonly string[] {
  const copy: string[] = [];
  const length = source.length;
  for (let index = 0; index < length; index += 1) {
    const field = source[index];
    if (field !== undefined) {
      append(copy, field);
    }
  }
  return freezeList(copy);
}

/**
 * Project evidence freshness for one valid Cockpit snapshot.
 *
 * Pure, deterministic, synchronous, side-effect free, and non-mutating. The
 * returned projection is deeply frozen and fully detached from the caller's
 * snapshot, contains only primitives and frozen records/lists, and survives
 * `JSON.parse(JSON.stringify(...))` with its enumerable data unchanged.
 *
 * Bounded by D1's `COCKPIT_BOUNDS.MAX_EVIDENCE_RECORDS`; D2 adds no bound of
 * its own and drops no record.
 *
 * @param snapshot A `CockpitSnapshot` already accepted by `readCockpitSnapshot`.
 */
export function projectCockpitEvidenceFreshness(
  snapshot: CockpitSnapshot,
): CockpitEvidenceFreshnessProjection {
  // Snapshot identity is read exactly once. Every record below is evaluated
  // against these same two locals; no evidence commit can become the target.
  const repository = snapshot.repository;
  const repositoryId = repository.repositoryId;
  const observedHeadSha = repository.observedHeadSha;

  const target: EvidenceTarget = freezeRecord({
    repositoryId,
    currentHeadSha: observedHeadSha,
  });

  // The evidence list reference is read once; each element once.
  const evidence = snapshot.evidence;
  const evidenceLength = evidence.length;

  const records: EvidenceRecord[] = [];
  const evidenceIds: string[] = [];
  const kinds: EvidenceKind[] = [];
  const sources: EvidenceSource[] = [];
  const commitShas: string[] = [];

  for (let index = 0; index < evidenceLength; index += 1) {
    const item = evidence[index];
    if (item === undefined) {
      continue;
    }
    const evidenceId = item.evidenceId;
    const kind = item.kind;
    const source = item.source;
    const commitSha = item.commitSha;

    // Exactly the minimum EvidenceRecord. Repository identity is injected from
    // the enclosing snapshot, which describes exactly one repository.
    append(
      records,
      freezeRecord({
        evidenceId,
        repositoryId,
        commitSha,
        kind,
        source,
        reference: item.reference,
        observedAt: item.observedAt,
      }),
    );
    append(evidenceIds, evidenceId);
    append(kinds, kind);
    append(sources, source);
    append(commitShas, commitSha);
  }

  // PR 004 is the freshness authority. Its per-record answers are copied
  // verbatim; nothing is reinterpreted, promoted, sorted, or dropped.
  const evaluation = evaluateEvidenceSet(records, target);
  const evaluated = evaluation.results;

  const results: CockpitEvidenceFreshnessItem[] = [];
  let current = 0;
  let stale = 0;
  let invalid = 0;

  const resultLength = evaluated.length;
  for (let index = 0; index < resultLength; index += 1) {
    const answer = evaluated[index];
    const evidenceId = evidenceIds[index];
    const kind = kinds[index];
    const source = sources[index];
    const commitSha = commitShas[index];
    if (
      answer === undefined ||
      evidenceId === undefined ||
      kind === undefined ||
      source === undefined ||
      commitSha === undefined
    ) {
      continue;
    }
    const state = answer.state;
    if (state === FRESHNESS.CURRENT) {
      current += 1;
    } else if (state === FRESHNESS.STALE) {
      stale += 1;
    } else {
      invalid += 1;
    }
    append(
      results,
      freezeRecord({
        evidenceId,
        kind,
        source,
        commitSha,
        state,
        reason: answer.reason,
        invalidFields: copyInvalidFields(answer.invalidFields),
      }),
    );
  }

  const counts: CockpitEvidenceFreshnessCounts = freezeRecord({
    current,
    stale,
    invalid,
    total: results.length,
  });

  return freezeRecord({
    repositoryId,
    observedHeadSha,
    results: freezeList(results),
    counts,
  });
}

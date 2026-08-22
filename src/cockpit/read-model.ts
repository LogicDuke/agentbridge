/**
 * Cockpit snapshot / read-model contract (Cockpit D1).
 *
 * A Cockpit snapshot is a **derived presentation representation**: the complete
 * statement of what a future read-only Cockpit surface may display about one
 * repository at one observed commit, and nothing else.
 *
 *     collector observation -> snapshot envelope -> read-only presentation
 *
 * Nothing here executes, collects, or persists. There is no filesystem, no git,
 * no subprocess, no network, no HTTP, no clock, no identifier generation, and
 * no Evidence Store implementation. D1 models and validates shapes; every value
 * arrives from a caller, including the observation timestamp.
 *
 * ## The Cockpit is presentation, never authority
 *
 * Domain/evidence truth and the Cockpit view model are different things and
 * must never be conflated. The kernels that already exist — PR 002/003's
 * classification and gate, PR 004's freshness evaluation, PR 005's review
 * ingestion, PR 006's invocation boundary, C1's repair-job authority — remain
 * the only sources of domain truth. A snapshot is a *derived echo* of such
 * truth for display, and no field in it can grant, widen, or record authority:
 * there is no decision, permit, approval, or authorization field typed here at
 * all, so an authority-shaped value has nowhere to land.
 *
 * Any future durable storage of snapshots belongs to the Evidence Store
 * boundary. D1 defines the serializable envelope only: every accepted field is
 * a primitive, `null`, or a frozen array of frozen records, so a snapshot
 * survives a plain-JSON round trip unchanged.
 *
 * ## Freshness is advisory here, and disposition is not freshness
 *
 * The formal freshness vocabulary stays PR 004's: {@link FreshnessState}. A
 * snapshot may *echo* a freshness state on a finding as
 * `advisoryFreshness`, but that echo is recomputable data, never a verdict —
 * `CURRENT`/`STALE` can always be recomputed against a current HEAD with the
 * domain freshness kernel, using the finding's `reviewedCommitSha` and the
 * envelope's `observedHeadSha`, and a consumer that needs the truth must do
 * exactly that. An unrecognised advisory value folds to `null` ("no advisory
 * claim"), never to a state.
 *
 * Presentation categories such as "maintenance observation" or "deferred" are a
 * separate axis: {@link CockpitFindingDisposition}. A disposition is not a
 * freshness state, not a review severity, and not a review status, and it adds
 * no member to any domain vocabulary.
 *
 * ## Hostile-data discipline
 *
 * A snapshot is re-read from JSON-shaped, unknown-provenance data, so the
 * reader follows the same discipline as the domain boundaries it borrows its
 * readers from: own-properties only, every read guarded, every value read
 * exactly once into a local, all-or-nothing list acceptance, deterministic
 * rejection, and a frozen result. Identity-shaped fields are exact-or-rejected
 * (never trimmed or truncated), descriptive vocabulary fields fold to their
 * fail-closed member, and prose fields are bounded.
 */

import {
  isEvidenceKind,
  isEvidenceSource,
  type EvidenceKind,
  type EvidenceSource,
} from '../domain/evidence.js';
import { FRESHNESS_STATES, type FreshnessState } from '../domain/evidence-freshness.js';
import {
  containsValue,
  readCanonicalBranchRef,
  readExactIdentifier,
  readOwnProperty,
} from '../domain/repair-job.js';
import {
  readClassification,
  readSeverity,
  readStatus,
  readText,
  REVIEW_BOUNDS,
  type ReviewClassification,
  type ReviewFindingStatus,
  type ReviewSeverity,
} from '../domain/review.js';

/**
 * Intrinsics captured at module load, before any untrusted property access is
 * possible. Same pattern as PR 004, PR 005, PR 006, and C1: a hostile getter or
 * Proxy trap runs mid-validation and could otherwise repoint the prototype
 * methods this module would rely on afterwards. The imported domain readers
 * capture their own intrinsics at their module load, which precedes this one.
 */
const objectFreeze = Object.freeze;
const objectHasOwn = Object.hasOwn;
const objectSetPrototypeOf = Object.setPrototypeOf;
const objectDefineProperty = Object.defineProperty;
const arrayIsArray = Array.isArray;
const numberIsInteger = Number.isInteger;

/**
 * Build an accepted-snapshot **record** node that cannot inherit behaviour from
 * the live `Object.prototype`, then freeze it.
 *
 * A hostile getter or Proxy trap that runs mid-validation can mutate the realm —
 * for instance installing `Object.prototype.toJSON = () => { throw }`. The reader
 * still accepts an otherwise-valid snapshot, but an ordinary `{...}` record would
 * inherit that poisoned hook, so a later `JSON.stringify(snapshot)` would invoke
 * it and break D1's plain-JSON round-trip promise. Giving every returned record a
 * `null` prototype removes the inherited chain entirely, so no realm mutation can
 * reach the accepted object graph. Own data properties are unaffected.
 */
function freezeRecord<T extends object>(record: T): Readonly<T> {
  objectSetPrototypeOf(record, null);
  return objectFreeze(record);
}

/**
 * Freeze an accepted-snapshot **list** node so it, too, is insulated from a
 * poisoned inherited `toJSON`.
 *
 * A list must keep `Array.prototype` — consumers iterate and map the returned
 * arrays — so a `null` prototype is not usable here. Instead the inherited
 * `toJSON` is shadowed by an own, non-enumerable `undefined`: `JSON.stringify`
 * finds a non-callable own `toJSON`, skips it, and serialises the array itself,
 * never reaching a mutated `Object.prototype.toJSON`. The shadow is
 * non-enumerable, so it changes neither enumeration nor structural equality.
 */
function freezeList<T>(list: T[]): readonly T[] {
  // The descriptor object itself is given a `null` prototype before it reaches
  // `Object.defineProperty`. A hostile getter run earlier during validation may
  // have installed `Object.prototype.get`/`.set`; an ordinary `{...}` descriptor
  // would inherit those, and `ToPropertyDescriptor` — which walks the prototype
  // chain — would then observe inherited accessor keys beside the own `value`/
  // `writable` keys, reject the mixed descriptor, and throw, breaking this
  // reader's never-throws contract. A `null` prototype removes the inherited
  // chain entirely, the same insulation `freezeRecord` gives its nodes.
  const descriptor: PropertyDescriptor = {
    value: undefined,
    enumerable: false,
    writable: false,
    configurable: false,
  };
  objectSetPrototypeOf(descriptor, null);
  objectDefineProperty(list, 'toJSON', descriptor);
  return objectFreeze(list);
}

/**
 * Append `value` as the next own indexed property of `list`.
 *
 * Same append semantics as C1's shared `repair-job` helper — define an own
 * indexed data property rather than call `Array.prototype.push`, so a mutated
 * `push` cannot intercept the write — but the descriptor is given a `null`
 * prototype before the captured `Object.defineProperty` consumes it. A hostile
 * getter read earlier during validation may have installed
 * `Object.prototype.get`/`.set`; an ordinary `{...}` descriptor would inherit
 * those, and `ToPropertyDescriptor` — which walks the prototype chain — would
 * then observe inherited accessor keys beside the own `value`/`writable` keys,
 * reject the mixed descriptor, and throw. Every Cockpit append runs on the
 * reader's never-throws path (list building and `invalidFields` collection),
 * so this module keeps its own insulated append rather than the shared one,
 * the same defensive shape {@link freezeList} gives its `toJSON` descriptor.
 */
function append<T>(list: T[], value: T): void {
  const descriptor: PropertyDescriptor = {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  };
  objectSetPrototypeOf(descriptor, null);
  objectDefineProperty(list, list.length, descriptor);
}

/** V1 bounds. Every unbounded dimension is capped before iteration. */
export const COCKPIT_BOUNDS = objectFreeze({
  /** Entries permitted in `pullRequests`. Oversize rejects the snapshot. */
  MAX_PULL_REQUESTS: 500,
  /** Entries permitted in `evidence`. Oversize rejects the snapshot. */
  MAX_EVIDENCE_RECORDS: 1_000,
  /**
   * Entries permitted in `findings`. Matches PR 005's `MAX_FINDINGS` by
   * convention — a snapshot re-presents ingested findings and must not need a
   * smaller universe than ingestion admits. A test pins the equality.
   */
  MAX_FINDINGS: 1_000,
  /** Entries permitted in `repairJobs`. Oversize rejects the snapshot. */
  MAX_REPAIR_JOBS: 500,
} as const);

/**
 * The one schema version D1 defines. A snapshot carrying any other value is
 * rejected whole: a reader must never guess at a future shape.
 */
export const COCKPIT_SNAPSHOT_SCHEMA_VERSION = 1;

export type CockpitSnapshotSchemaVersion = typeof COCKPIT_SNAPSHOT_SCHEMA_VERSION;

/**
 * Pull-request state *as observed at a provider*, for display only.
 *
 * This is a Cockpit presentation vocabulary — no domain shape models provider
 * PR state, so D1 defines one. `unknown` is the fail-closed member for a
 * missing, malformed, or unrecognised value; it is not a low-risk value, it
 * means "the collector did not say something we understand".
 */
export const COCKPIT_PULL_REQUEST_STATE = objectFreeze({
  OPEN: 'open',
  MERGED: 'merged',
  CLOSED: 'closed',
  UNKNOWN: 'unknown',
} as const);

export type CockpitPullRequestState =
  (typeof COCKPIT_PULL_REQUEST_STATE)[keyof typeof COCKPIT_PULL_REQUEST_STATE];

/** Every member of the {@link CockpitPullRequestState} union. */
export const COCKPIT_PULL_REQUEST_STATES: readonly CockpitPullRequestState[] = objectFreeze([
  COCKPIT_PULL_REQUEST_STATE.OPEN,
  COCKPIT_PULL_REQUEST_STATE.MERGED,
  COCKPIT_PULL_REQUEST_STATE.CLOSED,
  COCKPIT_PULL_REQUEST_STATE.UNKNOWN,
]);

/** Narrow to a supported pull-request state, failing closed to `unknown`. */
export function readCockpitPullRequestState(value: unknown): CockpitPullRequestState {
  return typeof value === 'string' && containsValue(COCKPIT_PULL_REQUEST_STATES, value)
    ? (value as CockpitPullRequestState)
    : COCKPIT_PULL_REQUEST_STATE.UNKNOWN;
}

/**
 * Presentation disposition of a finding, for display grouping only.
 *
 * **This is not a finding classification and must never become one.** The
 * formal review vocabularies (severity, classification, status) and the formal
 * freshness vocabulary (`CURRENT`/`STALE`/`INVALID`) are domain truth and are
 * imported, not extended. A disposition answers a different, softer question —
 * "how should a human triage view group this finding right now?" — and carries
 * no authority, no freshness meaning, and no resolution meaning.
 *
 * `unspecified` is the fail-closed member for a missing, malformed, or
 * unrecognised value.
 */
export const COCKPIT_FINDING_DISPOSITION = objectFreeze({
  MAINTENANCE_OBSERVATION: 'maintenance-observation',
  FUTURE_LAYER_OBLIGATION: 'future-layer-obligation',
  OPTIONAL_CLEANUP: 'optional-cleanup',
  DEFERRED: 'deferred',
  UNSPECIFIED: 'unspecified',
} as const);

export type CockpitFindingDisposition =
  (typeof COCKPIT_FINDING_DISPOSITION)[keyof typeof COCKPIT_FINDING_DISPOSITION];

/** Every member of the {@link CockpitFindingDisposition} union. */
export const COCKPIT_FINDING_DISPOSITIONS: readonly CockpitFindingDisposition[] = objectFreeze([
  COCKPIT_FINDING_DISPOSITION.MAINTENANCE_OBSERVATION,
  COCKPIT_FINDING_DISPOSITION.FUTURE_LAYER_OBLIGATION,
  COCKPIT_FINDING_DISPOSITION.OPTIONAL_CLEANUP,
  COCKPIT_FINDING_DISPOSITION.DEFERRED,
  COCKPIT_FINDING_DISPOSITION.UNSPECIFIED,
]);

/** Narrow to a supported disposition, failing closed to `unspecified`. */
export function readCockpitFindingDisposition(value: unknown): CockpitFindingDisposition {
  return typeof value === 'string' && containsValue(COCKPIT_FINDING_DISPOSITIONS, value)
    ? (value as CockpitFindingDisposition)
    : COCKPIT_FINDING_DISPOSITION.UNSPECIFIED;
}

/**
 * What was observed about the repository itself.
 *
 * One snapshot describes exactly one repository at exactly one observed HEAD.
 * Per-element repository fields are deliberately absent everywhere else in the
 * envelope, so a single snapshot cannot mix observations from two repositories.
 */
export interface CockpitRepositoryObservation {
  /** The one repository this snapshot describes. */
  readonly repositoryId: string;
  /** The commit the observation was taken at. Presentation context, never HEAD authority. */
  readonly observedHeadSha: string;
  /**
   * The default branch, in the canonical `refs/heads/<name>` spelling C1's
   * {@link readCanonicalBranchRef} defines, or `null` when not observed.
   */
  readonly defaultBranchRef: string | null;
}

/**
 * Who produced this snapshot, and when.
 *
 * `observedAt` is caller-supplied data; no clock is read anywhere in D1.
 * `collectorId` is audit metadata and is inert as authority — naming a
 * collector `root` or `agentbridge-internal` changes no outcome anywhere.
 */
export interface CockpitProvenance {
  /** Identity of the collector/source that produced the observation. */
  readonly collectorId: string;
  /** Externally supplied observation timestamp. Data, never a clock read. */
  readonly observedAt: string;
}

/** One pull request as observed at the provider. Display only. */
export interface CockpitPullRequestObservation {
  readonly pullRequestId: string;
  /** The pull request's HEAD at observation time. */
  readonly headSha: string;
  /** Canonical base ref, or `null` when not observed. */
  readonly baseRef: string | null;
  /** Observed provider state, folded fail-closed to `unknown`. */
  readonly state: CockpitPullRequestState;
  /** Bounded display title, or `null` when not observed. */
  readonly title: string | null;
}

/**
 * One evidence record as re-presented for display.
 *
 * The kind and source vocabularies are PR 004's, imported unchanged. This is a
 * *view* of an evidence record, not the record of truth: the Evidence Store
 * boundary owns durable evidence, and nothing read from a snapshot may be
 * treated as evidence for a decision.
 */
export interface CockpitEvidenceReadModel {
  readonly evidenceId: string;
  readonly kind: EvidenceKind;
  readonly source: EvidenceSource;
  /** The commit the underlying evidence is bound to. */
  readonly commitSha: string;
  /** Source-side reference identifier. Audit only. */
  readonly reference: string;
  /** The underlying record's caller-supplied timestamp. */
  readonly observedAt: string;
}

/**
 * One review finding as re-presented for display.
 *
 * Severity, classification, and status are PR 005's vocabularies, imported
 * unchanged and folded by PR 005's own readers. `disposition` and
 * `advisoryFreshness` are the two Cockpit-only axes, and they are distinct on
 * purpose: disposition is triage grouping, advisory freshness is a recomputable
 * echo of PR 004's answer. Neither is authority, and neither may substitute for
 * recomputing freshness against a current HEAD.
 */
export interface CockpitFindingReadModel {
  readonly findingId: string;
  readonly pullRequestId: string;
  /** The commit the review was performed against. Never rewritten. */
  readonly reviewedCommitSha: string;
  readonly provider: string;
  readonly reviewerId: string;
  readonly severity: ReviewSeverity;
  readonly classification: ReviewClassification;
  readonly status: ReviewFindingStatus;
  readonly title: string;
  readonly message: string;
  readonly filePath: string | null;
  /** Cockpit triage grouping. Never a finding classification. */
  readonly disposition: CockpitFindingDisposition;
  /**
   * Recomputable echo of a freshness evaluation, or `null` for "no advisory
   * claim". Never authority: consumers recompute with the domain kernel.
   */
  readonly advisoryFreshness: FreshnessState | null;
}

/**
 * One repair job as re-presented for display: identity fields only.
 *
 * C1's envelope, validation, and authorization semantics are not duplicated
 * here — this is what a human sees in a list, not what an execution layer may
 * consult. There is deliberately no path list, no command-class list, no
 * permit, and no decision field.
 */
export interface CockpitRepairJobReadModel {
  readonly jobId: string;
  readonly parentPullRequestId: string;
  readonly findingId: string;
  /** Canonical repair branch ref, in C1's one accepted spelling. */
  readonly repairBranch: string;
  readonly repairAgentId: string;
  readonly independentValidatorId: string;
}

/**
 * The serializable snapshot envelope: one repository, one observed HEAD, one
 * collector, one externally supplied timestamp, and the derived read models.
 *
 * Every field of an accepted snapshot is a primitive, `null`, or a frozen array
 * of frozen records, so `JSON.parse(JSON.stringify(snapshot))` re-reads to an
 * equal snapshot.
 */
export interface CockpitSnapshot {
  readonly schemaVersion: CockpitSnapshotSchemaVersion;
  readonly repository: CockpitRepositoryObservation;
  readonly provenance: CockpitProvenance;
  readonly pullRequests: readonly CockpitPullRequestObservation[];
  readonly evidence: readonly CockpitEvidenceReadModel[];
  readonly findings: readonly CockpitFindingReadModel[];
  readonly repairJobs: readonly CockpitRepairJobReadModel[];
}

/**
 * Every snapshot leaf field the reader validates, in the order invalid fields
 * are reported. Deterministic on purpose: equal inputs yield equal reports.
 */
export const COCKPIT_SNAPSHOT_FIELD_ORDER: readonly string[] = objectFreeze([
  'schemaVersion',
  'repository.repositoryId',
  'repository.observedHeadSha',
  'repository.defaultBranchRef',
  'provenance.collectorId',
  'provenance.observedAt',
  'pullRequests',
  'evidence',
  'findings',
  'repairJobs',
]);

/** The outcome of reading a snapshot exactly once. */
export interface CockpitSnapshotReadResult {
  /** The frozen snapshot, or `null` when any field is invalid. */
  readonly snapshot: CockpitSnapshot | null;
  /** Invalid field names in {@link COCKPIT_SNAPSHOT_FIELD_ORDER} order. */
  readonly invalidFields: readonly string[];
}

const ALL_COCKPIT_FIELDS_INVALID: CockpitSnapshotReadResult = objectFreeze({
  snapshot: null,
  invalidFields: COCKPIT_SNAPSHOT_FIELD_ORDER,
});

/**
 * Absence marker for {@link readOwnElement}. Module-private, compared by
 * reference identity only. Same rationale as C1: `undefined` is also a
 * legitimate, and rejected, element *value*, and a list must refuse a missing
 * element on its own.
 */
const NO_OWN_ELEMENT = {};

/**
 * Read one **own** indexed element of an untrusted array, reporting absence as
 * {@link NO_OWN_ELEMENT}. A sparse hole or an inherited numeric property —
 * including one planted on `Array.prototype` — is absence, never a value.
 * Both operations are guarded because a getter or Proxy trap may throw.
 */
function readOwnElement(elements: object, index: number): unknown {
  try {
    if (!objectHasOwn(elements, index)) {
      return NO_OWN_ELEMENT;
    }
    return (elements as Record<number, unknown>)[index];
  } catch {
    return NO_OWN_ELEMENT;
  }
}

/**
 * Read a bounded list of untrusted values, all-or-nothing.
 *
 * One unreadable, malformed, missing, or inherited entry rejects the whole
 * list, and an oversized list is rejected rather than truncated: a snapshot
 * that silently dropped observations would present an incomplete picture as a
 * complete one. Same discipline as C1's authorization-list reader.
 */
function readCockpitList<T>(
  value: unknown,
  maxLength: number,
  read: (element: unknown) => T | null,
): readonly T[] | null {
  let elements: readonly unknown[] | null;
  try {
    elements = arrayIsArray(value) ? (value as readonly unknown[]) : null;
  } catch {
    // `Array.isArray` itself throws on a revoked Proxy.
    return null;
  }
  if (elements === null) {
    return null;
  }

  let rawLength: unknown;
  try {
    rawLength = elements.length;
  } catch {
    return null;
  }
  if (
    typeof rawLength !== 'number' ||
    !numberIsInteger(rawLength) ||
    rawLength < 0 ||
    rawLength > maxLength
  ) {
    return null;
  }

  const parsed: T[] = [];
  for (let index = 0; index < rawLength; index += 1) {
    const element = readOwnElement(elements, index);
    if (element === NO_OWN_ELEMENT) {
      return null;
    }
    const parsedElement = read(element);
    if (parsedElement === null) {
      return null;
    }
    append(parsed, parsedElement);
  }
  return freezeList(parsed);
}

/**
 * Unreadability marker for {@link readOwnOptionalProperty}. Module-private,
 * compared by reference identity only. `undefined` cannot mark unreadability
 * here, because `undefined` already means legitimate absence on the optional
 * path, and a present-but-unreadable property must never read as absent.
 */
const UNREADABLE_PROPERTY = {};

/**
 * Read one **own** optional property, distinguishing absence from a present
 * property that cannot be read. A property that is not an own property —
 * including one inherited from a hostile prototype — is absence (`undefined`).
 * A present own property whose read throws, or a record whose presence check
 * itself throws, is {@link UNREADABLE_PROPERTY}, never absence: "the collector
 * did not send this" and "the collector sent something unreadable" must not
 * collapse into one answer on a fail-closed boundary. The value is read
 * exactly once.
 */
function readOwnOptionalProperty(target: object, key: string): unknown {
  try {
    if (!objectHasOwn(target, key)) {
      return undefined;
    }
  } catch {
    return UNREADABLE_PROPERTY;
  }
  try {
    return (target as Record<string, unknown>)[key];
  } catch {
    return UNREADABLE_PROPERTY;
  }
}

/**
 * Read an optional field: absent (`undefined`/`null`) is a legitimate `null`,
 * while a present-but-unreadable value rejects. The distinction matters — "the
 * collector did not observe this" and "the collector sent something malformed"
 * must not collapse into one answer on a fail-closed boundary.
 */
function readOptional(
  raw: unknown,
  read: (value: unknown) => string | null,
): { readonly value: string | null; readonly valid: boolean } {
  if (raw === UNREADABLE_PROPERTY) {
    return { value: null, valid: false };
  }
  if (raw === undefined || raw === null) {
    return { value: null, valid: true };
  }
  const parsed = read(raw);
  return { value: parsed, valid: parsed !== null };
}

/** Fold an advisory freshness echo, failing closed to `null` (no claim). */
function readAdvisoryFreshness(value: unknown): FreshnessState | null {
  return typeof value === 'string' && containsValue(FRESHNESS_STATES, value)
    ? (value as FreshnessState)
    : null;
}

/** Read one pull-request observation, or `null` when malformed. */
function readPullRequestObservation(element: unknown): CockpitPullRequestObservation | null {
  if (typeof element !== 'object' || element === null) {
    return null;
  }
  const pullRequestId = readExactIdentifier(readOwnProperty(element, 'pullRequestId'));
  const headSha = readExactIdentifier(readOwnProperty(element, 'headSha'));
  const baseRef = readOptional(readOwnOptionalProperty(element, 'baseRef'), readCanonicalBranchRef);
  const state = readCockpitPullRequestState(readOwnProperty(element, 'state'));
  const title = readOptional(readOwnOptionalProperty(element, 'title'), (value: unknown) =>
    readText(value, REVIEW_BOUNDS.MAX_TITLE_LENGTH),
  );
  if (pullRequestId === null || headSha === null || !baseRef.valid || !title.valid) {
    return null;
  }
  return freezeRecord({
    pullRequestId,
    headSha,
    baseRef: baseRef.value,
    state,
    title: title.value,
  });
}

/** Read one evidence read model, or `null` when malformed. */
function readEvidenceReadModel(element: unknown): CockpitEvidenceReadModel | null {
  if (typeof element !== 'object' || element === null) {
    return null;
  }
  const evidenceId = readExactIdentifier(readOwnProperty(element, 'evidenceId'));
  const rawKind = readOwnProperty(element, 'kind');
  const kind = isEvidenceKind(rawKind) ? rawKind : null;
  const rawSource = readOwnProperty(element, 'source');
  const source = isEvidenceSource(rawSource) ? rawSource : null;
  const commitSha = readExactIdentifier(readOwnProperty(element, 'commitSha'));
  const reference = readExactIdentifier(readOwnProperty(element, 'reference'));
  const observedAt = readExactIdentifier(readOwnProperty(element, 'observedAt'));
  if (
    evidenceId === null ||
    kind === null ||
    source === null ||
    commitSha === null ||
    reference === null ||
    observedAt === null
  ) {
    return null;
  }
  return freezeRecord({ evidenceId, kind, source, commitSha, reference, observedAt });
}

/** Read one finding read model, or `null` when malformed. */
function readFindingReadModel(element: unknown): CockpitFindingReadModel | null {
  if (typeof element !== 'object' || element === null) {
    return null;
  }
  const findingId = readExactIdentifier(readOwnProperty(element, 'findingId'));
  const pullRequestId = readExactIdentifier(readOwnProperty(element, 'pullRequestId'));
  const reviewedCommitSha = readExactIdentifier(readOwnProperty(element, 'reviewedCommitSha'));
  const provider = readExactIdentifier(readOwnProperty(element, 'provider'));
  const reviewerId = readExactIdentifier(readOwnProperty(element, 'reviewerId'));
  const severity = readSeverity(readOwnProperty(element, 'severity'));
  const classification = readClassification(readOwnProperty(element, 'classification'));
  const status = readStatus(readOwnProperty(element, 'status'));
  const title = readText(readOwnProperty(element, 'title'), REVIEW_BOUNDS.MAX_TITLE_LENGTH);
  const message = readText(readOwnProperty(element, 'message'), REVIEW_BOUNDS.MAX_MESSAGE_LENGTH);
  const filePath = readOptional(readOwnOptionalProperty(element, 'filePath'), (value: unknown) =>
    readText(value, REVIEW_BOUNDS.MAX_PATH_LENGTH),
  );
  const disposition = readCockpitFindingDisposition(readOwnProperty(element, 'disposition'));
  const advisoryFreshness = readAdvisoryFreshness(readOwnProperty(element, 'advisoryFreshness'));
  if (
    findingId === null ||
    pullRequestId === null ||
    reviewedCommitSha === null ||
    provider === null ||
    reviewerId === null ||
    title === null ||
    message === null ||
    !filePath.valid
  ) {
    return null;
  }
  return freezeRecord({
    findingId,
    pullRequestId,
    reviewedCommitSha,
    provider,
    reviewerId,
    severity,
    classification,
    status,
    title,
    message,
    filePath: filePath.value,
    disposition,
    advisoryFreshness,
  });
}

/** Read one repair-job read model, or `null` when malformed. */
function readRepairJobReadModel(element: unknown): CockpitRepairJobReadModel | null {
  if (typeof element !== 'object' || element === null) {
    return null;
  }
  const jobId = readExactIdentifier(readOwnProperty(element, 'jobId'));
  const parentPullRequestId = readExactIdentifier(readOwnProperty(element, 'parentPullRequestId'));
  const findingId = readExactIdentifier(readOwnProperty(element, 'findingId'));
  const repairBranch = readCanonicalBranchRef(readOwnProperty(element, 'repairBranch'));
  const repairAgentId = readExactIdentifier(readOwnProperty(element, 'repairAgentId'));
  const independentValidatorId = readExactIdentifier(
    readOwnProperty(element, 'independentValidatorId'),
  );
  if (
    jobId === null ||
    parentPullRequestId === null ||
    findingId === null ||
    repairBranch === null ||
    repairAgentId === null ||
    independentValidatorId === null
  ) {
    return null;
  }
  return freezeRecord({
    jobId,
    parentPullRequestId,
    findingId,
    repairBranch,
    repairAgentId,
    independentValidatorId,
  });
}

/**
 * Read and validate a snapshot envelope, in a single pass, exactly once per
 * field.
 *
 * Pure, total, and deterministic; never throws. Every security-relevant value
 * is read once into a local and never re-read, so a getter or Proxy that
 * returns a different value on each access cannot validate one value and hand a
 * different one to the accepted snapshot. Only **own** properties are
 * consulted, so a property planted on `Object.prototype` or on a hostile
 * prototype chain never becomes a trusted field. The accepted snapshot is a
 * frozen copy built from the validated locals — never the caller's objects — so
 * later mutation of the input cannot change an accepted snapshot.
 */
export function readCockpitSnapshot(value: unknown): CockpitSnapshotReadResult {
  const record: unknown = value;
  if (typeof record !== 'object' || record === null) {
    return ALL_COCKPIT_FIELDS_INVALID;
  }

  const schemaVersionValid =
    readOwnProperty(record, 'schemaVersion') === COCKPIT_SNAPSHOT_SCHEMA_VERSION;

  const rawRepository = readOwnProperty(record, 'repository');
  let repositoryId: string | null = null;
  let observedHeadSha: string | null = null;
  let defaultBranchRef: { readonly value: string | null; readonly valid: boolean } = {
    value: null,
    valid: false,
  };
  if (typeof rawRepository === 'object' && rawRepository !== null) {
    repositoryId = readExactIdentifier(readOwnProperty(rawRepository, 'repositoryId'));
    observedHeadSha = readExactIdentifier(readOwnProperty(rawRepository, 'observedHeadSha'));
    defaultBranchRef = readOptional(
      readOwnOptionalProperty(rawRepository, 'defaultBranchRef'),
      readCanonicalBranchRef,
    );
  }

  const rawProvenance = readOwnProperty(record, 'provenance');
  let collectorId: string | null = null;
  let observedAt: string | null = null;
  if (typeof rawProvenance === 'object' && rawProvenance !== null) {
    collectorId = readExactIdentifier(readOwnProperty(rawProvenance, 'collectorId'));
    observedAt = readExactIdentifier(readOwnProperty(rawProvenance, 'observedAt'));
  }

  const pullRequests = readCockpitList(
    readOwnProperty(record, 'pullRequests'),
    COCKPIT_BOUNDS.MAX_PULL_REQUESTS,
    readPullRequestObservation,
  );
  const evidence = readCockpitList(
    readOwnProperty(record, 'evidence'),
    COCKPIT_BOUNDS.MAX_EVIDENCE_RECORDS,
    readEvidenceReadModel,
  );
  const findings = readCockpitList(
    readOwnProperty(record, 'findings'),
    COCKPIT_BOUNDS.MAX_FINDINGS,
    readFindingReadModel,
  );
  const repairJobs = readCockpitList(
    readOwnProperty(record, 'repairJobs'),
    COCKPIT_BOUNDS.MAX_REPAIR_JOBS,
    readRepairJobReadModel,
  );

  const invalidFields: string[] = [];
  if (!schemaVersionValid) {
    append(invalidFields, 'schemaVersion');
  }
  if (repositoryId === null) {
    append(invalidFields, 'repository.repositoryId');
  }
  if (observedHeadSha === null) {
    append(invalidFields, 'repository.observedHeadSha');
  }
  if (!defaultBranchRef.valid) {
    append(invalidFields, 'repository.defaultBranchRef');
  }
  if (collectorId === null) {
    append(invalidFields, 'provenance.collectorId');
  }
  if (observedAt === null) {
    append(invalidFields, 'provenance.observedAt');
  }
  if (pullRequests === null) {
    append(invalidFields, 'pullRequests');
  }
  if (evidence === null) {
    append(invalidFields, 'evidence');
  }
  if (findings === null) {
    append(invalidFields, 'findings');
  }
  if (repairJobs === null) {
    append(invalidFields, 'repairJobs');
  }

  if (invalidFields.length > 0) {
    return objectFreeze({ snapshot: null, invalidFields: objectFreeze(invalidFields) });
  }

  // Every value above is non-null here; the narrowing is re-stated per field so
  // no assertion operator is used on a trust boundary.
  if (
    repositoryId === null ||
    observedHeadSha === null ||
    collectorId === null ||
    observedAt === null ||
    pullRequests === null ||
    evidence === null ||
    findings === null ||
    repairJobs === null
  ) {
    return ALL_COCKPIT_FIELDS_INVALID;
  }

  return objectFreeze({
    snapshot: freezeRecord<CockpitSnapshot>({
      schemaVersion: COCKPIT_SNAPSHOT_SCHEMA_VERSION,
      repository: freezeRecord({
        repositoryId,
        observedHeadSha,
        defaultBranchRef: defaultBranchRef.value,
      }),
      provenance: freezeRecord({ collectorId, observedAt }),
      pullRequests,
      evidence,
      findings,
      repairJobs,
    }),
    invalidFields: objectFreeze([] as string[]),
  });
}

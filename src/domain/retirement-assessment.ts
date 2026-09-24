/**
 * Governed retirement-candidate assessment — the pure domain kernel of Autoflow
 * Job #1 (Decision 065 Revision 2 with Amendments 1, 2 and 3; WF3 clean rebuild).
 *
 * This module holds exactly the domain half of Job #1:
 *
 * - the closed classification, reason and governance-hold vocabularies;
 * - the F1..F10 fact schema, typed **per fact**, with the one shared count bound;
 * - the pure, total classifier `F1..F10 -> { classification, reasonCodes,
 *   gateRequested }`;
 * - the AB-CJSON-1 canonicalizer;
 * - the hostile readers for the serialized fact map and the assessment envelope.
 *
 * It performs no I/O of any kind: no `node:` import, no process, environment,
 * clock, filesystem, network, or digest. SHA-256 belongs to the runtime layer
 * (Decision 065, integrity step 3) and is deliberately unreachable from here.
 *
 * ## Classifier purity
 *
 * {@link classifyRetirementCandidate} takes the ten facts and nothing else. No
 * digest, admission pointer, projection state, prose, or clock is on its
 * signature, so an integrity outcome has no way to become a classification
 * (Invariants 5 and 14). A test pins the arity.
 *
 * ## Classification grants nothing
 *
 * `RETIRE_ELIGIBLE` is not `AUTHORIZED_TO_DELETE` (Invariant 8). Nothing here
 * deletes, mutates, commits, pushes, merges, or opens a gate; `gateRequested` is
 * a request the runtime may act on once, never an authority.
 *
 * ## Hostile-data discipline
 *
 * Intrinsics are captured at load; only own properties are read, each exactly
 * once into a local; acceptance is all-or-nothing; every accepted value is a
 * frozen copy built from validated locals, never the caller's object.
 */

import { readCanonicalBranchRef, readExactIdentifier, readOwnProperty } from './repair-job.js';

/* ------------------------------------------------------------------------- *
 * Captured intrinsics
 * ------------------------------------------------------------------------- */

const objectFreeze = Object.freeze;
const objectHasOwn = Object.hasOwn;
const objectKeys = Object.keys;
const objectIs = Object.is;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectSetPrototypeOf = Object.setPrototypeOf;
const objectDefineProperty = Object.defineProperty;
const objectGetOwnPropertyNames = Object.getOwnPropertyNames;
const objectGetOwnPropertySymbols = Object.getOwnPropertySymbols;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectPrototype: unknown = Object.prototype;
const arrayIsArray = Array.isArray;
const arrayPrototype: unknown = Array.prototype;
const numberIsInteger = Number.isInteger;
const numberIsSafeInteger = Number.isSafeInteger;
const jsonStringify = JSON.stringify;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
// The global `String` is mutable, so a numeric scalar reached after a hostile
// getter has run must not resolve it live.
const stringOf = String;
// Captured unbound and invoked through `Reflect.apply`, so a poisoned
// `Function.prototype.call` is never on the path.
// eslint-disable-next-line @typescript-eslint/unbound-method
const stringCharCodeAt = String.prototype.charCodeAt;

/* ------------------------------------------------------------------------- *
 * Small prototype-free helpers
 * ------------------------------------------------------------------------- */

/** Membership by `===` over an indexed scan: no prototype method on the path. */
function containsValue(list: readonly string[], value: unknown): boolean {
  for (let index = 0; index < list.length; index += 1) {
    if (list[index] === value) {
      return true;
    }
  }
  return false;
}

/** Define one own data property with a prototype-free descriptor. */
function defineOwn(target: object, key: string | number, value: unknown, writable: boolean): void {
  const descriptor: PropertyDescriptor = {
    value,
    writable,
    enumerable: true,
    configurable: writable,
  };
  objectSetPrototypeOf(descriptor, null);
  objectDefineProperty(target, key, descriptor);
}

/** Append by defining an own element, bypassing inherited index setters. */
function append<T>(list: T[], value: T): void {
  defineOwn(list, list.length, value, true);
}

/** Detach a record from the live `Object.prototype`, then freeze it. */
function freezeRecord<T extends object>(record: T): Readonly<T> {
  objectSetPrototypeOf(record, null);
  return objectFreeze(record);
}

/**
 * Freeze a list. Lists keep `Array.prototype` for consumers, so an inherited
 * `toJSON` is shadowed by an own, non-enumerable, non-callable `undefined` that
 * `JSON.stringify` ignores.
 */
function freezeList<T>(list: T[]): readonly T[] {
  const descriptor: PropertyDescriptor = {
    value: undefined,
    writable: false,
    enumerable: false,
    configurable: false,
  };
  objectSetPrototypeOf(descriptor, null);
  objectDefineProperty(list, 'toJSON', descriptor);
  return objectFreeze(list);
}

/** Character code at `index`, or `-1` when the read is unusable. */
function charCodeAt(value: string, index: number): number {
  const code: unknown = reflectApply(stringCharCodeAt, value, [index]);
  return typeof code === 'number' && numberIsInteger(code) ? code : -1;
}

/** Own enumerable string keys of an untrusted object, or `null` if unreadable. */
function ownKeysOf(target: object): readonly string[] | null {
  try {
    return objectKeys(target);
  } catch {
    return null;
  }
}

/**
 * Is `key` an own, enumerable **data** property of `target`? The descriptor is
 * inspected and the property is never read, so a getter never runs. An accessor
 * is not schema state: its answer can change between reads, and running it
 * would let hostile code reshape a container after its shape was checked.
 */
function isEnumerableOwnData(target: object, key: string | number): boolean {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = objectGetOwnPropertyDescriptor(target, key);
  } catch {
    return false;
  }
  return descriptor !== undefined && descriptor.enumerable === true && objectHasOwn(descriptor, 'value');
}

/**
 * Does `target` carry **exactly** the expected own state — every expected key
 * an own enumerable data property, and no other own key of any kind? All own
 * keys are counted, string and symbol, enumerable or not; with every expected
 * key proved own, an equal count leaves no room for a surplus. An inherited
 * key does not count as present.
 */
function hasExactOwnKeys(target: object, expected: readonly string[]): boolean {
  let keys: readonly (string | symbol)[];
  try {
    keys = reflectOwnKeys(target);
  } catch {
    return false;
  }
  if (keys.length !== expected.length) {
    return false;
  }
  for (let index = 0; index < expected.length; index += 1) {
    const key = expected[index];
    if (key === undefined || !isEnumerableOwnData(target, key)) {
      return false;
    }
  }
  return true;
}

/* ------------------------------------------------------------------------- *
 * Bounds
 * ------------------------------------------------------------------------- */

/**
 * The one shared count bound. F5 and F6 are determinate only within
 * `0 <= value <= MAX_COUNT`; the observer folds a larger count to indeterminate
 * before it can reach a body, and this reader rejects one that arrives anyway,
 * so producer and reader can never disagree about the universe of counts.
 */
export const MAX_COUNT = 100_000;

/** Bounds for every other otherwise-unbounded dimension this kernel reads. */
export const RETIREMENT_BOUNDS = objectFreeze({
  /** Reason codes on one assessment. The vocabulary is smaller than this. */
  MAX_REASON_CODES: 16,
  /** Nested containers AB-CJSON-1 will canonicalize (the root counts as one). */
  MAX_CANONICAL_DEPTH: 8,
  /** Own keys on one canonicalized object node. */
  MAX_CANONICAL_KEYS: 64,
  /** Elements in one canonicalized array node. */
  MAX_CANONICAL_ELEMENTS: 256,
  /** UTF-16 code units in one canonicalized string scalar or key. */
  MAX_CANONICAL_STRING_LENGTH: 4_096,
  /** Assessments one Cockpit snapshot may carry. */
  MAX_ASSESSMENTS: 8,
} as const);

/* ------------------------------------------------------------------------- *
 * Closed vocabularies
 * ------------------------------------------------------------------------- */

/** The classification vocabulary. `BLOCKED` is the fail-closed member. */
export const RETIREMENT_CLASSIFICATION = objectFreeze({
  PRESERVE_FOR_HISTORY: 'PRESERVE_FOR_HISTORY',
  RETIRE_ELIGIBLE: 'RETIRE_ELIGIBLE',
  BLOCKED: 'BLOCKED',
} as const);

export type RetirementClassification =
  (typeof RETIREMENT_CLASSIFICATION)[keyof typeof RETIREMENT_CLASSIFICATION];

export const RETIREMENT_CLASSIFICATIONS: readonly RetirementClassification[] = objectFreeze([
  RETIREMENT_CLASSIFICATION.PRESERVE_FOR_HISTORY,
  RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE,
  RETIREMENT_CLASSIFICATION.BLOCKED,
]);

/**
 * The reason vocabulary. A reason explains a classification and never widens
 * one; there is no free-text reason field anywhere.
 */
export const RETIREMENT_REASON = objectFreeze({
  /** At least one fact was not determinate. Always BLOCKED. */
  INDETERMINATE_FACT: 'INDETERMINATE_FACT',
  /** F1 false. */
  CANDIDATE_IDENTITY_MISMATCH: 'CANDIDATE_IDENTITY_MISMATCH',
  /** F2 false. */
  REMOTE_DISAGREEMENT: 'REMOTE_DISAGREEMENT',
  /** F3 false. */
  MAIN_UNSTABLE: 'MAIN_UNSTABLE',
  /** F4 false. */
  NOT_CONTAINED: 'NOT_CONTAINED',
  /** F5 > 0. */
  UNIQUE_COMMITS_PRESENT: 'UNIQUE_COMMITS_PRESENT',
  /** F6 > 0. */
  UNIQUE_PATCHES_PRESENT: 'UNIQUE_PATCHES_PRESENT',
  /** F7 false. */
  WORKTREE_NOT_CLEAN: 'WORKTREE_NOT_CLEAN',
  /** F8 false. */
  DEPENDENCY_CLEARANCE_FAILED: 'DEPENDENCY_CLEARANCE_FAILED',
  /** F9 = HOLD. */
  GOVERNANCE_HOLD: 'GOVERNANCE_HOLD',
  /** F10 false. */
  PROTECTED_OR_DEFAULT_BRANCH: 'PROTECTED_OR_DEFAULT_BRANCH',
  /** Two determinate facts disagree. Always BLOCKED; never resolved by preference. */
  INTERNAL_CONTRADICTION: 'INTERNAL_CONTRADICTION',
} as const);

export type RetirementReason = (typeof RETIREMENT_REASON)[keyof typeof RETIREMENT_REASON];

/** Every reason, in the one report order. `reasonCodes` is always a subsequence of this. */
export const RETIREMENT_REASONS: readonly RetirementReason[] = objectFreeze([
  RETIREMENT_REASON.INDETERMINATE_FACT,
  RETIREMENT_REASON.CANDIDATE_IDENTITY_MISMATCH,
  RETIREMENT_REASON.REMOTE_DISAGREEMENT,
  RETIREMENT_REASON.MAIN_UNSTABLE,
  RETIREMENT_REASON.NOT_CONTAINED,
  RETIREMENT_REASON.UNIQUE_COMMITS_PRESENT,
  RETIREMENT_REASON.UNIQUE_PATCHES_PRESENT,
  RETIREMENT_REASON.WORKTREE_NOT_CLEAN,
  RETIREMENT_REASON.DEPENDENCY_CLEARANCE_FAILED,
  RETIREMENT_REASON.GOVERNANCE_HOLD,
  RETIREMENT_REASON.PROTECTED_OR_DEFAULT_BRANCH,
  RETIREMENT_REASON.INTERNAL_CONTRADICTION,
]);

/**
 * The governance manifest verdict (F9). There is no third member: a manifest
 * that failed verification makes F9 **indeterminate**, never `NO_HOLD`.
 */
export const GOVERNANCE_HOLD = objectFreeze({
  HOLD: 'HOLD',
  NO_HOLD: 'NO_HOLD',
} as const);

export type GovernanceHold = (typeof GOVERNANCE_HOLD)[keyof typeof GOVERNANCE_HOLD];

export const GOVERNANCE_HOLDS: readonly GovernanceHold[] = objectFreeze([
  GOVERNANCE_HOLD.HOLD,
  GOVERNANCE_HOLD.NO_HOLD,
]);

/** Narrow an untrusted value to a classification member, or `null`. */
export function readRetirementClassification(value: unknown): RetirementClassification | null {
  return typeof value === 'string' && containsValue(RETIREMENT_CLASSIFICATIONS, value)
    ? (value as RetirementClassification)
    : null;
}

/** Narrow an untrusted value to a reason member, or `null`. */
export function readRetirementReason(value: unknown): RetirementReason | null {
  return typeof value === 'string' && containsValue(RETIREMENT_REASONS, value)
    ? (value as RetirementReason)
    : null;
}

/** Narrow an untrusted value to a governance-hold member, or `null`. */
export function readGovernanceHold(value: unknown): GovernanceHold | null {
  return typeof value === 'string' && containsValue(GOVERNANCE_HOLDS, value)
    ? (value as GovernanceHold)
    : null;
}

/* ------------------------------------------------------------------------- *
 * Identifier shapes shared with the runtime
 * ------------------------------------------------------------------------- */

const SHA1_HEX_LENGTH = 40;
const SHA256_HEX_LENGTH = 64;
const CODE_ZERO = 0x30;
const CODE_NINE = 0x39;
const CODE_LOWER_A = 0x61;
const CODE_LOWER_F = 0x66;

function isLowerHexCode(code: number): boolean {
  return (code >= CODE_ZERO && code <= CODE_NINE) || (code >= CODE_LOWER_A && code <= CODE_LOWER_F);
}

/** Is `value[start, end)` entirely lowercase hex? */
function isLowerHexRange(value: string, start: number, end: number): boolean {
  for (let index = start; index < end; index += 1) {
    if (!isLowerHexCode(charCodeAt(value, index))) {
      return false;
    }
  }
  return true;
}

/**
 * Narrow an untrusted value to exactly 40 lowercase hex characters, or `null`.
 *
 * Exact or rejected: never trimmed, case-folded, or abbreviated. An abbreviated
 * SHA is not an immutable identity — a prefix that resolves today can resolve to
 * a different object once the repository grows.
 */
export function readFullSha(value: unknown): string | null {
  return typeof value === 'string' &&
    value.length === SHA1_HEX_LENGTH &&
    isLowerHexRange(value, 0, SHA1_HEX_LENGTH)
    ? value
    : null;
}

/** The one accepted evidence-id prefix. */
export const EVIDENCE_ID_PREFIX = 'sha256:';

/**
 * Narrow an untrusted value to a well-formed evidence id, or `null`: the literal
 * prefix `sha256:` followed by exactly 64 lowercase hex characters. The value is
 * returned unmodified; normalising an identifier on a binding boundary is a
 * bypass vector. This checks **shape only** — binding to a body is the runtime's
 * digest check, which this module cannot perform.
 */
export function readEvidenceId(value: unknown): string | null {
  const prefixLength = EVIDENCE_ID_PREFIX.length;
  if (typeof value !== 'string' || value.length !== prefixLength + SHA256_HEX_LENGTH) {
    return null;
  }
  for (let index = 0; index < prefixLength; index += 1) {
    if (charCodeAt(value, index) !== charCodeAt(EVIDENCE_ID_PREFIX, index)) {
      return null;
    }
  }
  return isLowerHexRange(value, prefixLength, value.length) ? value : null;
}

/* ------------------------------------------------------------------------- *
 * The F1..F10 fact schema
 * ------------------------------------------------------------------------- */

/**
 * One observed fact: **either** determinate with a value **or** indeterminate.
 * The indeterminate form carries no value field at all, so there is no stale or
 * default value for a later branch to read by mistake.
 */
export type RetirementFact<T> =
  | { readonly determinate: true; readonly value: T }
  | { readonly determinate: false };

/** Build a determinate fact. */
export function determinate<T>(value: T): RetirementFact<T> {
  return freezeRecord({ determinate: true as const, value });
}

/** The single indeterminate fact value. Shared: it carries no payload. */
export const INDETERMINATE: RetirementFact<never> = freezeRecord({ determinate: false as const });

/**
 * The ten pre-classification facts — the **entire** classifier input. No
 * `evidenceId`, digest, admission pointer, projection state, timestamp, or
 * prose is typed here, so none can become a classifier input.
 */
export interface RetirementFacts {
  /** F1 — the observed candidate ref resolves to the configured immutable SHA. */
  readonly f1CandidateIdentity: RetirementFact<boolean>;
  /** F2 — GitHub and the remote witness agree the candidate is at the configured SHA. */
  readonly f2RemoteAgreement: RetirementFact<boolean>;
  /** F3 — authoritative main equals the configured value before and after observation. */
  readonly f3StableMain: RetirementFact<boolean>;
  /** F4 — the candidate SHA is an ancestor of authoritative main. */
  readonly f4Containment: RetirementFact<boolean>;
  /** F5 — commits reachable from the candidate but not from main. */
  readonly f5UniqueCommits: RetirementFact<number>;
  /** F6 — patches on the candidate not found upstream. */
  readonly f6UniquePatches: RetirementFact<number>;
  /** F7 — every registered worktree on the candidate is clean and not prunable. */
  readonly f7WorktreeClean: RetirementFact<boolean>;
  /** F8 — GitHub dependency clearance passed in full. */
  readonly f8DependencyClearance: RetirementFact<boolean>;
  /** F9 — the verified governance run manifest's hold result. */
  readonly f9GovernanceManifest: RetirementFact<GovernanceHold>;
  /** F10 — the candidate is not main, not the default branch, and not protected. */
  readonly f10NotProtected: RetirementFact<boolean>;
}

export type RetirementFactKey = keyof RetirementFacts;

/** Every fact key, in declaration order. Report order is this order. */
export const RETIREMENT_FACT_ORDER: readonly RetirementFactKey[] = objectFreeze([
  'f1CandidateIdentity',
  'f2RemoteAgreement',
  'f3StableMain',
  'f4Containment',
  'f5UniqueCommits',
  'f6UniquePatches',
  'f7WorktreeClean',
  'f8DependencyClearance',
  'f9GovernanceManifest',
  'f10NotProtected',
]);

/** The value class each fact carries when determinate. */
export const RETIREMENT_FACT_KIND = objectFreeze({
  f1CandidateIdentity: 'boolean',
  f2RemoteAgreement: 'boolean',
  f3StableMain: 'boolean',
  f4Containment: 'boolean',
  f5UniqueCommits: 'count',
  f6UniquePatches: 'count',
  f7WorktreeClean: 'boolean',
  f8DependencyClearance: 'boolean',
  f9GovernanceManifest: 'hold',
  f10NotProtected: 'boolean',
} as const satisfies Record<RetirementFactKey, 'boolean' | 'count' | 'hold'>);

/** Is `value` a determinate count: a safe integer in `[0, MAX_COUNT]`, not `-0`? */
export function isRetirementCount(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    numberIsSafeInteger(value) &&
    !objectIs(value, -0) &&
    value >= 0 &&
    value <= MAX_COUNT
  );
}

/* ------------------------------------------------------------------------- *
 * The classifier
 * ------------------------------------------------------------------------- */

/**
 * The classifier's answer. `gateRequested` is a mechanical restatement of
 * `classification === RETIRE_ELIGIBLE`, derived in exactly one place. It is a
 * request, never an authority.
 */
export interface RetirementAssessmentVerdict {
  readonly classification: RetirementClassification;
  /** Closed-vocabulary reasons, always in {@link RETIREMENT_REASONS} order. */
  readonly reasonCodes: readonly RetirementReason[];
  readonly gateRequested: boolean;
}

/** The determinate value, or `null` when indeterminate. */
function factValue<T>(fact: RetirementFact<T>): T | null {
  return fact.determinate ? fact.value : null;
}

/**
 * Classify one retirement candidate from F1..F10.
 *
 * Pure, total, deterministic, arity one, and non-throwing for typed input.
 * Precedence is `BLOCKED` > `PRESERVE_FOR_HISTORY` > `RETIRE_ELIGIBLE`:
 *
 * 1. any indeterminate fact → `BLOCKED`;
 * 2. F1, F2, F3, F7, F8, or F10 false → `BLOCKED`;
 * 3. an internal contradiction between determinate facts → `BLOCKED`
 *    (F4 must equal `F5 === 0`; F6 may not exceed F5);
 * 4. F5 > 0, F6 > 0, or F9 = `HOLD` → `PRESERVE_FOR_HISTORY`;
 * 5. every fact determinate, F1/F2/F3/F4/F7/F8/F10 true, F5 = 0, F6 = 0,
 *    F9 = `NO_HOLD` → `RETIRE_ELIGIBLE`;
 * 6. anything else → `BLOCKED`. Ambiguity is always `BLOCKED`.
 *
 * Reasons are reported for everything that is wrong, not only the first thing,
 * in the fixed {@link RETIREMENT_REASONS} order.
 */
export function classifyRetirementCandidate(facts: RetirementFacts): RetirementAssessmentVerdict {
  const f1 = factValue(facts.f1CandidateIdentity);
  const f2 = factValue(facts.f2RemoteAgreement);
  const f3 = factValue(facts.f3StableMain);
  const f4 = factValue(facts.f4Containment);
  const f5 = factValue(facts.f5UniqueCommits);
  const f6 = factValue(facts.f6UniquePatches);
  const f7 = factValue(facts.f7WorktreeClean);
  const f8 = factValue(facts.f8DependencyClearance);
  const f9 = factValue(facts.f9GovernanceManifest);
  const f10 = factValue(facts.f10NotProtected);

  const anyIndeterminate =
    f1 === null ||
    f2 === null ||
    f3 === null ||
    f4 === null ||
    f5 === null ||
    f6 === null ||
    f7 === null ||
    f8 === null ||
    f9 === null ||
    f10 === null;

  // Containment and the unique-commit count are two readings of one truth; a
  // patch count is drawn from the commit count. A disagreement is never resolved
  // in favour of either reading.
  const contradiction =
    (f4 !== null && f5 !== null && f4 !== (f5 === 0)) || (f5 !== null && f6 !== null && f6 > f5);

  const blockingFalse =
    f1 === false || f2 === false || f3 === false || f7 === false || f8 === false || f10 === false;

  const preserve = (f5 !== null && f5 > 0) || (f6 !== null && f6 > 0) || f9 === GOVERNANCE_HOLD.HOLD;

  const everyFactClear =
    f1 === true &&
    f2 === true &&
    f3 === true &&
    f4 === true &&
    f5 === 0 &&
    f6 === 0 &&
    f7 === true &&
    f8 === true &&
    f9 === GOVERNANCE_HOLD.NO_HOLD &&
    f10 === true;

  // Which reasons apply, keyed by reason; emitted below in vocabulary order so
  // the ordering never depends on evaluation order.
  const applies: Readonly<Record<RetirementReason, boolean>> = {
    INDETERMINATE_FACT: anyIndeterminate,
    CANDIDATE_IDENTITY_MISMATCH: f1 === false,
    REMOTE_DISAGREEMENT: f2 === false,
    MAIN_UNSTABLE: f3 === false,
    NOT_CONTAINED: f4 === false,
    UNIQUE_COMMITS_PRESENT: f5 !== null && f5 > 0,
    UNIQUE_PATCHES_PRESENT: f6 !== null && f6 > 0,
    WORKTREE_NOT_CLEAN: f7 === false,
    DEPENDENCY_CLEARANCE_FAILED: f8 === false,
    GOVERNANCE_HOLD: f9 === GOVERNANCE_HOLD.HOLD,
    PROTECTED_OR_DEFAULT_BRANCH: f10 === false,
    INTERNAL_CONTRADICTION: contradiction,
  };
  const reasons: RetirementReason[] = [];
  for (let index = 0; index < RETIREMENT_REASONS.length; index += 1) {
    const reason = RETIREMENT_REASONS[index];
    if (reason !== undefined && applies[reason]) {
      append(reasons, reason);
    }
  }

  let classification: RetirementClassification;
  if (anyIndeterminate || blockingFalse || contradiction) {
    classification = RETIREMENT_CLASSIFICATION.BLOCKED;
  } else if (preserve) {
    classification = RETIREMENT_CLASSIFICATION.PRESERVE_FOR_HISTORY;
  } else if (everyFactClear) {
    classification = RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE;
  } else {
    classification = RETIREMENT_CLASSIFICATION.BLOCKED;
  }

  return freezeRecord({
    classification,
    reasonCodes: freezeList(reasons),
    gateRequested: classification === RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE,
  });
}

/* ------------------------------------------------------------------------- *
 * The serialized fact record and the immutable body
 * ------------------------------------------------------------------------- */

/**
 * One fact as it appears in a serialized body: `determinate` plus a `value`
 * that is exactly `null` when `determinate` is `false`. The mapping from the
 * in-memory union is total in both directions.
 */
export interface RetirementFactRecord {
  readonly determinate: boolean;
  readonly value: string | number | boolean | null;
}

export type RetirementFactRecords = Readonly<Record<RetirementFactKey, RetirementFactRecord>>;

/**
 * The immutable assessment body — the content an evidence pointer is bound to.
 * Every field is a string, safe integer, boolean, `null`, or a frozen record of
 * those, so it canonicalizes under AB-CJSON-1 and survives a JSON round trip.
 * There is deliberately no authority-, approval-, permission-, or
 * deletion-shaped field.
 */
export interface RetirementAssessmentBody {
  readonly repositoryId: string;
  /** Canonical `refs/heads/...` candidate ref, fixed at boot. */
  readonly candidateRef: string;
  /** 40 lowercase hex. */
  readonly candidateSha: string;
  /** 40 lowercase hex. */
  readonly authoritativeMainSha: string;
  readonly facts: RetirementFactRecords;
  readonly classification: RetirementClassification;
  readonly reasonCodes: readonly RetirementReason[];
  /** Mechanical restatement of `classification === RETIRE_ELIGIBLE`. Not authority. */
  readonly gateRequested: boolean;
  /** `sha256:` + 64 hex of the verified governance run manifest. Identity only. */
  readonly manifestDigest: string;
  /** Externally supplied assessment timestamp. Data; no clock is read here. */
  readonly generatedAt: string;
  /** The observer build identity that produced the facts. Audit only. */
  readonly observerVersion: string;
}

/** The body's exact own-key set, in declaration order. */
const BODY_KEYS: readonly string[] = objectFreeze([
  'repositoryId',
  'candidateRef',
  'candidateSha',
  'authoritativeMainSha',
  'facts',
  'classification',
  'reasonCodes',
  'gateRequested',
  'manifestDigest',
  'generatedAt',
  'observerVersion',
]);

/**
 * The admitted envelope: an evidence pointer plus the body it claims to be
 * bound to. The pointer is the authority (Invariant 6); whether the body is
 * still digest-bound to it is re-proved by the runtime on every read, never
 * assumed from the envelope's shape.
 */
export interface RetirementAssessmentEnvelope {
  readonly evidenceId: string;
  readonly body: RetirementAssessmentBody;
}

const ENVELOPE_KEYS: readonly string[] = objectFreeze(['evidenceId', 'body']);

/**
 * Flatten the in-memory fact set for serialization — the one place the union
 * is flattened, so producers cannot drift. An indeterminate fact becomes
 * `{ determinate: false, value: null }` exactly.
 */
export function toFactRecords(facts: RetirementFacts): RetirementFactRecords {
  const records: Partial<Record<RetirementFactKey, RetirementFactRecord>> = {};
  objectSetPrototypeOf(records, null);
  for (let index = 0; index < RETIREMENT_FACT_ORDER.length; index += 1) {
    const key = RETIREMENT_FACT_ORDER[index];
    if (key === undefined) {
      continue;
    }
    const fact: RetirementFact<string | number | boolean> = facts[key];
    const record: RetirementFactRecord = fact.determinate
      ? freezeRecord({ determinate: true, value: fact.value })
      : freezeRecord({ determinate: false, value: null });
    defineOwn(records, key, record, false);
  }
  return objectFreeze(records) as RetirementFactRecords;
}

/* ------------------------------------------------------------------------- *
 * Hostile readers
 * ------------------------------------------------------------------------- */

/**
 * Read one serialized fact record **for a named fact**, enforcing that fact's
 * value class: booleans for F1–F4, F7, F8, F10; a bounded count for F5 and F6;
 * the closed hold vocabulary for F9. A boolean in F5, a string in F1, or a
 * number in F9 rejects.
 */
function readFactRecord(key: RetirementFactKey, value: unknown): RetirementFactRecord | null {
  if (typeof value !== 'object' || value === null) {
    return null;
  }
  if (!hasExactOwnKeys(value, ['determinate', 'value'])) {
    return null;
  }
  const rawDeterminate = readOwnProperty(value, 'determinate');
  const rawValue = readOwnProperty(value, 'value');
  if (typeof rawDeterminate !== 'boolean') {
    return null;
  }
  if (!rawDeterminate) {
    // An indeterminate record carries exactly `null`; a present value would be
    // a stale reading a later branch could mistake for an observation.
    return rawValue === null ? freezeRecord({ determinate: false, value: null }) : null;
  }
  const kind = RETIREMENT_FACT_KIND[key];
  const accepted: string | number | boolean | null =
    kind === 'boolean'
      ? typeof rawValue === 'boolean'
        ? rawValue
        : null
      : kind === 'count'
        ? isRetirementCount(rawValue)
          ? rawValue
          : null
        : readGovernanceHold(rawValue);
  return accepted === null ? null : freezeRecord({ determinate: true, value: accepted });
}

/**
 * Read an untrusted serialized fact map: exactly the ten keys of
 * {@link RETIREMENT_FACT_ORDER} as own properties, no surplus, each record read
 * once and typed for its fact. Returns a frozen, prototype-free copy or `null`.
 */
export function readRetirementFactRecords(value: unknown): RetirementFactRecords | null {
  if (typeof value !== 'object' || value === null) {
    return null;
  }
  if (!hasExactOwnKeys(value, RETIREMENT_FACT_ORDER)) {
    return null;
  }
  const records: Partial<Record<RetirementFactKey, RetirementFactRecord>> = {};
  objectSetPrototypeOf(records, null);
  for (let index = 0; index < RETIREMENT_FACT_ORDER.length; index += 1) {
    const key = RETIREMENT_FACT_ORDER[index];
    if (key === undefined) {
      return null;
    }
    const record = readFactRecord(key, readOwnProperty(value, key));
    if (record === null) {
      return null;
    }
    defineOwn(records, key, record, false);
  }
  return objectFreeze(records) as RetirementFactRecords;
}

/** Read the closed-vocabulary reason list, all-or-nothing, bounded. */
function readReasonCodes(value: unknown): readonly RetirementReason[] | null {
  let isArray: boolean;
  try {
    isArray = arrayIsArray(value);
  } catch {
    return null;
  }
  if (!isArray) {
    return null;
  }
  const elements = value as readonly unknown[];
  let length: unknown;
  try {
    length = elements.length;
  } catch {
    return null;
  }
  if (
    typeof length !== 'number' ||
    !numberIsInteger(length) ||
    length < 0 ||
    length > RETIREMENT_BOUNDS.MAX_REASON_CODES
  ) {
    return null;
  }
  // Exactly the indices, `length`, and at most the data-free `freezeList`
  // shadow: every index is proved own below, so an equal count leaves no room
  // for a named, index-like, or symbol-keyed own property.
  let ownKeys: readonly (string | symbol)[];
  try {
    ownKeys = reflectOwnKeys(elements);
  } catch {
    return null;
  }
  if (ownKeys.length !== length + (hasBenignToJsonShadow(elements) ? 2 : 1)) {
    return null;
  }
  const reasons: RetirementReason[] = [];
  for (let index = 0; index < length; index += 1) {
    let element: unknown;
    try {
      if (!isEnumerableOwnData(elements, index)) {
        return null;
      }
      element = elements[index];
    } catch {
      return null;
    }
    const reason = readRetirementReason(element);
    if (reason === null) {
      return null;
    }
    append(reasons, reason);
  }
  return freezeList(reasons);
}

/**
 * Rebuild the typed fact set from validated records — the exact inverse of
 * {@link toFactRecords}, and the only way back. A determinate record becomes a
 * determinate fact carrying its already type-checked value; an indeterminate
 * one becomes {@link INDETERMINATE}, which carries no value at all.
 */
function factsFromRecords(records: RetirementFactRecords): RetirementFacts {
  const facts: Partial<Record<RetirementFactKey, RetirementFact<string | number | boolean>>> = {};
  objectSetPrototypeOf(facts, null);
  for (let index = 0; index < RETIREMENT_FACT_ORDER.length; index += 1) {
    const key = RETIREMENT_FACT_ORDER[index];
    if (key === undefined) {
      continue;
    }
    const record = records[key];
    const fact: RetirementFact<string | number | boolean> = record.determinate
      ? determinate(record.value as string | number | boolean)
      : INDETERMINATE;
    defineOwn(facts, key, fact, false);
  }
  return facts as RetirementFacts;
}

/**
 * Read one untrusted `{ evidenceId, body }` envelope, or `null`.
 *
 * Pure, total, deterministic, never throws. Exact own-key sets at every level,
 * each value read once, all-or-nothing acceptance, and a frozen copy built from
 * validated locals.
 *
 * The verdict fields are **derived**, never authoritative, so the body's
 * `classification`, ordered `reasonCodes` and `gateRequested` must equal
 * {@link classifyRetirementCandidate} applied to the body's own facts. A body
 * that claims a verdict its facts do not produce is rejected whole.
 *
 * This still does not verify that `evidenceId` digests `body`, because the
 * digest is a runtime concern. An envelope that reads cleanly here is still
 * unbound until the runtime proves otherwise.
 */
export function readRetirementAssessment(value: unknown): RetirementAssessmentEnvelope | null {
  if (typeof value !== 'object' || value === null) {
    return null;
  }
  if (!hasExactOwnKeys(value, ENVELOPE_KEYS)) {
    return null;
  }
  const evidenceId = readEvidenceId(readOwnProperty(value, 'evidenceId'));
  const rawBody = readOwnProperty(value, 'body');
  if (evidenceId === null || typeof rawBody !== 'object' || rawBody === null) {
    return null;
  }
  if (!hasExactOwnKeys(rawBody, BODY_KEYS)) {
    return null;
  }

  const repositoryId = readExactIdentifier(readOwnProperty(rawBody, 'repositoryId'));
  const candidateRef = readCanonicalBranchRef(readOwnProperty(rawBody, 'candidateRef'));
  const candidateSha = readFullSha(readOwnProperty(rawBody, 'candidateSha'));
  const authoritativeMainSha = readFullSha(readOwnProperty(rawBody, 'authoritativeMainSha'));
  const facts = readRetirementFactRecords(readOwnProperty(rawBody, 'facts'));
  const classification = readRetirementClassification(readOwnProperty(rawBody, 'classification'));
  const reasonCodes = readReasonCodes(readOwnProperty(rawBody, 'reasonCodes'));
  const rawGateRequested = readOwnProperty(rawBody, 'gateRequested');
  const manifestDigest = readEvidenceId(readOwnProperty(rawBody, 'manifestDigest'));
  const generatedAt = readExactIdentifier(readOwnProperty(rawBody, 'generatedAt'));
  const observerVersion = readExactIdentifier(readOwnProperty(rawBody, 'observerVersion'));

  if (
    repositoryId === null ||
    candidateRef === null ||
    candidateSha === null ||
    authoritativeMainSha === null ||
    facts === null ||
    classification === null ||
    reasonCodes === null ||
    typeof rawGateRequested !== 'boolean' ||
    manifestDigest === null ||
    generatedAt === null ||
    observerVersion === null
  ) {
    return null;
  }

  // Bind the claimed verdict to the facts it claims to summarize. Comparing the
  // claimed classification with the claimed `gateRequested` only relates two
  // claims; the classifier is the one derivation, so recompute from the facts
  // and require an exact match. A mismatch is rejected whole, never repaired by
  // preferring one side or by regenerating the fields.
  const derived = classifyRetirementCandidate(factsFromRecords(facts));
  if (
    classification !== derived.classification ||
    rawGateRequested !== derived.gateRequested ||
    reasonCodes.length !== derived.reasonCodes.length
  ) {
    return null;
  }
  for (let index = 0; index < derived.reasonCodes.length; index += 1) {
    if (reasonCodes[index] !== derived.reasonCodes[index]) {
      return null;
    }
  }

  return freezeRecord({
    evidenceId,
    body: freezeRecord({
      repositoryId,
      candidateRef,
      candidateSha,
      authoritativeMainSha,
      facts,
      classification,
      reasonCodes,
      gateRequested: rawGateRequested,
      manifestDigest,
      generatedAt,
      observerVersion,
    }),
  });
}

/* ------------------------------------------------------------------------- *
 * AB-CJSON-1 canonicalization
 * ------------------------------------------------------------------------- */

/** Compare two strings by UTF-16 code unit; `<0`, `0`, or `>0`. */
function compareCodeUnits(left: string, right: string): number {
  const shorter = left.length < right.length ? left.length : right.length;
  for (let index = 0; index < shorter; index += 1) {
    const difference = charCodeAt(left, index) - charCodeAt(right, index);
    if (difference !== 0) {
      return difference;
    }
  }
  return left.length - right.length;
}

/**
 * Sort keys by UTF-16 code unit with an explicit insertion sort over an indexed
 * list. `Array.prototype.sort` is not on the path: its comparator contract and
 * implementation are replaceable, and the ordering here must be exactly the
 * specification's in every realm.
 */
function sortKeysByCodeUnit(keys: readonly string[]): readonly string[] {
  const sorted: string[] = [];
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (key === undefined) {
      continue;
    }
    let position = sorted.length;
    while (position > 0) {
      const previous = sorted[position - 1];
      if (previous === undefined || compareCodeUnits(previous, key) <= 0) {
        break;
      }
      defineOwn(sorted, position, previous, true);
      position -= 1;
    }
    defineOwn(sorted, position, key, true);
  }
  return sorted;
}

/** Encode one string scalar or key, or `null` when it is over the bound. */
function encodeString(text: string): string | null {
  if (text.length > RETIREMENT_BOUNDS.MAX_CANONICAL_STRING_LENGTH) {
    return null;
  }
  // `JSON.stringify` of a string primitive is the canonical escaped form. It is
  // captured at load, and a string primitive has no `toJSON` to invoke.
  const encoded: unknown = jsonStringify(text);
  return typeof encoded === 'string' ? encoded : null;
}

/**
 * Canonicalize one value under **AB-CJSON-1**, or return `null`.
 *
 * The format, exactly: JSON text with no whitespace anywhere; object keys
 * sorted by UTF-16 code unit at every depth; arrays in declared order; scalars
 * limited to string, safe integer, boolean, and `null`. The text is a JavaScript
 * string; the runtime encodes it as UTF-8 before digesting.
 *
 * Anything else rejects with `null`, never a throw and never a lossy coercion:
 * a non-integer number, `NaN`, `±Infinity`, `-0`, a bigint, symbol, function,
 * `undefined`, a sparse hole, a non-plain object (Date, Map, class instance,
 * boxed primitive), a non-ordinary array (an Array subclass, a reparented
 * array, or one carrying a named own property, whose extra state the indexed
 * encoding would drop), a container carrying any own symbol key, a plain object
 * carrying any own non-enumerable string key, a cycle, a throwing getter or
 * Proxy, or a value over a {@link RETIREMENT_BOUNDS} limit. Own state the
 * encoding cannot represent rejects; it is never silently dropped. An admitted
 * object's own string keys are all enumerable, and each is read exactly once.
 * This function hashes nothing.
 */
export function canonicalizeAssessmentBody(value: unknown): string | null {
  return canonicalize(value, 0, []);
}

/** The recursive canonicalizer. `depth` counts enclosing containers; `seen` is the ancestor stack. */
function canonicalize(value: unknown, depth: number, seen: readonly object[]): string | null {
  if (value === null) {
    return 'null';
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }
  if (typeof value === 'string') {
    return encodeString(value);
  }
  if (typeof value === 'number') {
    // `-0` serializes as `0`, so two distinct inputs would share one digest.
    return numberIsSafeInteger(value) && !objectIs(value, -0) ? stringOf(value) : null;
  }
  if (typeof value !== 'object') {
    // bigint, symbol, function, undefined.
    return null;
  }

  // A container. Nesting is bounded, and a cycle is detected by identity.
  if (depth >= RETIREMENT_BOUNDS.MAX_CANONICAL_DEPTH) {
    return null;
  }
  const node: object = value;
  for (let index = 0; index < seen.length; index += 1) {
    if (seen[index] === node) {
      return null;
    }
  }
  const ancestors: object[] = [];
  for (let index = 0; index < seen.length; index += 1) {
    const ancestor = seen[index];
    if (ancestor !== undefined) {
      append(ancestors, ancestor);
    }
  }
  append(ancestors, node);

  let isArray: boolean;
  try {
    isArray = arrayIsArray(node);
  } catch {
    // `Array.isArray` throws on a revoked Proxy.
    return null;
  }
  return isArray
    ? canonicalizeArray(node as readonly unknown[], depth, ancestors)
    : canonicalizeObject(node, depth, ancestors);
}

/**
 * Is this array's own `toJSON` **exactly** the benign shadow {@link freezeList}
 * installs — a data property holding `undefined`, non-enumerable, non-writable,
 * non-configurable, with no getter and no setter?
 *
 * Only that one descriptor shape carries no data. The name alone proves
 * nothing: a `toJSON` holding a string, a function, an object, or an accessor is
 * own state the positional encoding below would silently drop, which is exactly
 * the loss the named-property check exists to prevent. Any other shape is
 * therefore not structural, and the array rejects.
 *
 * The **descriptor** is inspected; the property itself is never read. An
 * accessor is turned away by its shape, so a getter — including a throwing one —
 * is never invoked.
 */
function hasBenignToJsonShadow(elements: readonly unknown[]): boolean {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = objectGetOwnPropertyDescriptor(elements, 'toJSON');
  } catch {
    // A hostile Proxy trap.
    return false;
  }
  return (
    descriptor !== undefined &&
    !objectHasOwn(descriptor, 'get') &&
    !objectHasOwn(descriptor, 'set') &&
    descriptor.value === undefined &&
    descriptor.writable === false &&
    descriptor.enumerable === false &&
    descriptor.configurable === false
  );
}

/**
 * Any own symbol key is own state AB-CJSON-1 cannot represent. Only the key's
 * existence is observed, so a symbol accessor's getter is never invoked.
 * Unreadable (a hostile Proxy trap) rejects.
 */
function carriesOwnSymbolKey(target: object): boolean {
  try {
    return objectGetOwnPropertySymbols(target).length !== 0;
  } catch {
    return true;
  }
}

function canonicalizeArray(
  elements: readonly unknown[],
  depth: number,
  ancestors: readonly object[],
): string | null {
  // Only an ordinary array canonicalizes. `Array.isArray` is also true for a
  // subclass instance, a reparented array, and an array carrying named own
  // properties, and this function encodes indexed elements only — so without
  // this check two semantically different values share one canonical text, the
  // way a Date and a Map would both be `{}` without the object branch's own
  // prototype check.
  let prototype: unknown;
  try {
    prototype = objectGetPrototypeOf(elements);
  } catch {
    return null;
  }
  if (prototype !== arrayPrototype) {
    return null;
  }
  let length: unknown;
  try {
    length = elements.length;
  } catch {
    return null;
  }
  if (
    typeof length !== 'number' ||
    !numberIsInteger(length) ||
    length < 0 ||
    length > RETIREMENT_BOUNDS.MAX_CANONICAL_ELEMENTS
  ) {
    return null;
  }
  // Exactly the `length` index properties plus the structural names, counting
  // both enumerable and non-enumerable own properties. Every index below
  // `length` is proved own below, so matching this count leaves no room for a
  // named own property — a `secret` that the element loop would silently drop.
  //
  // There are exactly two structural names. `length` is the one every array
  // carries; a `toJSON` that is exactly the benign `freezeList` shadow is the
  // one more it may carry. A `toJSON` of any other descriptor shape is data, is
  // not counted here, and so fails the count — the name alone buys nothing.
  let ownNames: readonly string[];
  try {
    ownNames = objectGetOwnPropertyNames(elements);
  } catch {
    return null;
  }
  const toJsonIsStructural = hasBenignToJsonShadow(elements);
  let structural = 0;
  for (let index = 0; index < ownNames.length; index += 1) {
    const name = ownNames[index];
    if (name === 'length' || (name === 'toJSON' && toJsonIsStructural)) {
      structural += 1;
    }
  }
  if (ownNames.length !== length + structural) {
    return null;
  }
  if (carriesOwnSymbolKey(elements)) {
    return null;
  }
  let out = '[';
  for (let index = 0; index < length; index += 1) {
    let element: unknown;
    try {
      if (!objectHasOwn(elements, index)) {
        // A sparse hole is not `null`; it is not canonicalizable.
        return null;
      }
      element = elements[index];
    } catch {
      return null;
    }
    const encoded = canonicalize(element, depth + 1, ancestors);
    if (encoded === null) {
      return null;
    }
    out += index === 0 ? encoded : ',' + encoded;
  }
  return out + ']';
}

function canonicalizeObject(node: object, depth: number, ancestors: readonly object[]): string | null {
  // Only a plain object canonicalizes: prototype `Object.prototype` or `null`.
  // This check is load-bearing: a Date or Map has no own enumerable keys and
  // would otherwise canonicalize to `{}`, sharing one digest with every other.
  let prototype: unknown;
  try {
    prototype = objectGetPrototypeOf(node);
  } catch {
    return null;
  }
  if (prototype !== objectPrototype && prototype !== null) {
    return null;
  }
  const keys = ownKeysOf(node);
  if (keys === null || keys.length > RETIREMENT_BOUNDS.MAX_CANONICAL_KEYS) {
    return null;
  }
  // Every own key must be emitted: a symbol key, or a non-enumerable string key
  // the enumerable-key read above skips, is own state the encoding would drop.
  // (Arrays need no enumerability check: indices are emitted by position.)
  if (carriesOwnSymbolKey(node)) {
    return null;
  }
  let allNames: readonly string[];
  try {
    allNames = objectGetOwnPropertyNames(node);
  } catch {
    return null;
  }
  if (allNames.length !== keys.length) {
    return null;
  }
  const sorted = sortKeysByCodeUnit(keys);
  let out = '{';
  for (let index = 0; index < sorted.length; index += 1) {
    const key = sorted[index];
    if (key === undefined) {
      return null;
    }
    const encodedKey = encodeString(key);
    if (encodedKey === null) {
      return null;
    }
    let member: unknown;
    try {
      member = (node as Record<string, unknown>)[key];
    } catch {
      return null;
    }
    const encodedValue = canonicalize(member, depth + 1, ancestors);
    if (encodedValue === null) {
      return null;
    }
    const pair = encodedKey + ':' + encodedValue;
    out += index === 0 ? pair : ',' + pair;
  }
  return out + '}';
}

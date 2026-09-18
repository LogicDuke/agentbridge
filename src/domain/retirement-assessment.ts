/**
 * Governed retirement-candidate assessment — the pure domain kernel
 * (Autoflow Job #1, Decision 065 Revision 2 + Amendment 1).
 *
 * This module answers exactly one question — *what is the classification of this
 * candidate, given these ten observed facts?* — and it answers it as a pure,
 * total function:
 *
 *     F1..F10 (pre-classification facts)
 *       -> classifyRetirementCandidate
 *       -> { classification, reasonCodes, gateRequested }
 *
 * There is no reverse arrow and no second input. **Classifier purity is the
 * central invariant** (Decision 065 §5): no model judgment, no prose, and — this
 * one is structural, not merely documented — **no digest, admission, or
 * projection state is on the signature at all.** `classifyRetirementCandidate`
 * takes a fact set and nothing else, so an integrity outcome has nowhere to land
 * and can never be reinterpreted as a classification. A test pins the arity.
 *
 * ## Classification grants nothing
 *
 * `RETIRE_ELIGIBLE` is **not** `AUTHORIZED_TO_DELETE` (Decision 065 §8). Nothing
 * here deletes, retires, mutates, commits, pushes, or merges; nothing here opens
 * a gate. Retirement mutation remains a separate Decision-056-style authority
 * sequence, and human merge authority remains non-delegable.
 *
 * ## What lives here, and what deliberately does not
 *
 * Here: the closed classification vocabulary, the closed reason vocabulary, the
 * F1..F10 fact schema, the total classifier, the AB-CJSON-1 canonicalizer, and
 * the hostile envelope reader.
 *
 * Not here, on purpose: SHA-256 (the digest is computed in the *runtime* layer,
 * never in the domain, D1, or D4 — Decision 065 §3 of the integrity sequence),
 * Git, GitHub, process, network, filesystem, clock, environment, persistence,
 * and identifier generation. This module performs no I/O of any kind.
 *
 * ## Hostile-data discipline
 *
 * {@link readRetirementAssessment} re-reads an envelope of unknown provenance, so
 * it follows the same discipline as the domain boundaries beside it: intrinsics
 * captured at load, own-properties only, every value read exactly once into a
 * local, all-or-nothing acceptance, deterministic rejection, and a frozen result.
 */

import { readExactIdentifier, readOwnProperty } from './repair-job.js';

/**
 * Intrinsics captured at module load, before any untrusted property access is
 * possible. A hostile getter or Proxy trap runs *during* validation and could
 * otherwise repoint the prototype methods this module would rely on afterwards.
 */
const objectFreeze = Object.freeze;
const objectHasOwn = Object.hasOwn;
const objectKeys = Object.keys;
const objectSetPrototypeOf = Object.setPrototypeOf;
const objectDefineProperty = Object.defineProperty;
const arrayIsArray = Array.isArray;
const numberIsInteger = Number.isInteger;
const numberIsSafeInteger = Number.isSafeInteger;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectPrototype: unknown = Object.prototype;
const jsonStringify = JSON.stringify;
// Captured unbound on purpose and invoked through `Reflect.apply`, so a poisoned
// `Function.prototype.call` is not on the path.
const reflectApply = Reflect.apply;
// eslint-disable-next-line @typescript-eslint/unbound-method
const stringCharCodeAt = String.prototype.charCodeAt;

/**
 * Membership test that touches no prototype method. A plain indexed scan uses
 * only `===` and own-property reads, so poisoning `Set.prototype.has`,
 * `Array.prototype.includes`, `indexOf`, or the array iterator cannot influence
 * vocabulary validation.
 */
function containsValue(list: readonly string[], value: unknown): boolean {
  for (let index = 0; index < list.length; index += 1) {
    if (list[index] === value) {
      return true;
    }
  }
  return false;
}

/**
 * Append by defining an own element, bypassing inherited index setters. The
 * descriptor is detached from a possibly-poisoned `Object.prototype` first:
 * `ToPropertyDescriptor` walks the prototype chain, so an ordinary `{...}`
 * descriptor could present inherited accessor keys beside its own data keys and
 * be rejected, throwing on a never-throws path.
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

/** Detach a returned record from the live `Object.prototype`, then freeze it. */
function freezeRecord<T extends object>(record: T): Readonly<T> {
  objectSetPrototypeOf(record, null);
  return objectFreeze(record);
}

/**
 * Freeze a returned list. Lists keep `Array.prototype` for consumers, so the
 * inherited `toJSON` is shadowed by an own, non-enumerable, non-callable
 * `undefined` that `JSON.stringify` skips.
 */
function freezeList<T>(list: T[]): readonly T[] {
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

/* ------------------------------------------------------------------------- *
 * Bounds
 * ------------------------------------------------------------------------- */

/** Bounds for every otherwise-unbounded dimension this kernel reads. */
export const RETIREMENT_BOUNDS = objectFreeze({
  /** Maximum reason codes on one assessment. The vocabulary is smaller than this. */
  MAX_REASON_CODES: 16,
  /** Maximum commits/patches a count fact may report before it is indeterminate. */
  MAX_COUNT: 100_000,
  /** Maximum nesting depth AB-CJSON-1 will canonicalize. */
  MAX_CANONICAL_DEPTH: 8,
  /** Maximum own keys on one canonicalized object node. */
  MAX_CANONICAL_KEYS: 64,
  /** Maximum elements in one canonicalized array node. */
  MAX_CANONICAL_ELEMENTS: 256,
  /** Maximum length of one canonicalized string scalar. */
  MAX_CANONICAL_STRING_LENGTH: 4_096,
  /** Maximum assessments a Cockpit snapshot may carry. */
  MAX_ASSESSMENTS: 8,
} as const);

/* ------------------------------------------------------------------------- *
 * Classification vocabulary
 * ------------------------------------------------------------------------- */

/**
 * The closed classification vocabulary.
 *
 * `BLOCKED` is the fail-closed member: ambiguity, indeterminacy, and internal
 * contradiction all land here, never on a permissive value.
 */
export const RETIREMENT_CLASSIFICATION = objectFreeze({
  PRESERVE_FOR_HISTORY: 'PRESERVE_FOR_HISTORY',
  RETIRE_ELIGIBLE: 'RETIRE_ELIGIBLE',
  BLOCKED: 'BLOCKED',
} as const);

export type RetirementClassification =
  (typeof RETIREMENT_CLASSIFICATION)[keyof typeof RETIREMENT_CLASSIFICATION];

/** Every member of the {@link RetirementClassification} union. Frozen: validation reads it. */
export const RETIREMENT_CLASSIFICATIONS: readonly RetirementClassification[] = objectFreeze([
  RETIREMENT_CLASSIFICATION.PRESERVE_FOR_HISTORY,
  RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE,
  RETIREMENT_CLASSIFICATION.BLOCKED,
]);

/**
 * The closed reason vocabulary.
 *
 * A reason explains a classification; it never widens one. There is deliberately
 * no free-text reason field anywhere on an assessment — prose is not a classifier
 * input and must not become one by the back door.
 */
export const RETIREMENT_REASON = objectFreeze({
  /** At least one fact was not determinate. Always BLOCKED. */
  INDETERMINATE_FACT: 'INDETERMINATE_FACT',
  /** F1: the observed candidate ref/SHA is not the configured immutable identity. */
  CANDIDATE_IDENTITY_MISMATCH: 'CANDIDATE_IDENTITY_MISMATCH',
  /** F2: the remote does not agree with the configured candidate SHA. */
  REMOTE_DISAGREEMENT: 'REMOTE_DISAGREEMENT',
  /** F3: authoritative main moved, or does not equal the configured value. */
  MAIN_UNSTABLE: 'MAIN_UNSTABLE',
  /** F4: the candidate is not contained in authoritative main. */
  NOT_CONTAINED: 'NOT_CONTAINED',
  /** F5: the candidate carries commits not reachable from main. */
  UNIQUE_COMMITS_PRESENT: 'UNIQUE_COMMITS_PRESENT',
  /** F6: the candidate carries patches not upstream. */
  UNIQUE_PATCHES_PRESENT: 'UNIQUE_PATCHES_PRESENT',
  /** F7: a registered worktree on the candidate is dirty or prunable. */
  WORKTREE_NOT_CLEAN: 'WORKTREE_NOT_CLEAN',
  /** F8: GitHub dependency clearance did not clear. */
  DEPENDENCY_CLEARANCE_FAILED: 'DEPENDENCY_CLEARANCE_FAILED',
  /** F9: the verified governance manifest reports a hold. */
  GOVERNANCE_HOLD: 'GOVERNANCE_HOLD',
  /** F10: the candidate is main, the default branch, or protected. */
  PROTECTED_OR_DEFAULT_BRANCH: 'PROTECTED_OR_DEFAULT_BRANCH',
  /** Two determinate facts disagree. Always BLOCKED; never resolved by preference. */
  INTERNAL_CONTRADICTION: 'INTERNAL_CONTRADICTION',
} as const);

export type RetirementReason = (typeof RETIREMENT_REASON)[keyof typeof RETIREMENT_REASON];

/** Every member of the {@link RetirementReason} union, in report order. */
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

/* ------------------------------------------------------------------------- *
 * Governance hold vocabulary (F9)
 * ------------------------------------------------------------------------- */

/**
 * The governance manifest's verdict. A third state is not modelled: a manifest
 * that failed verification makes F9 **indeterminate**, which is BLOCKED — it is
 * never folded into `NO_HOLD`.
 */
export const GOVERNANCE_HOLD = objectFreeze({
  HOLD: 'HOLD',
  NO_HOLD: 'NO_HOLD',
} as const);

export type GovernanceHold = (typeof GOVERNANCE_HOLD)[keyof typeof GOVERNANCE_HOLD];

/** Every member of the {@link GovernanceHold} union. */
export const GOVERNANCE_HOLDS: readonly GovernanceHold[] = objectFreeze([
  GOVERNANCE_HOLD.HOLD,
  GOVERNANCE_HOLD.NO_HOLD,
]);

/** Narrow an untrusted value to a governance-hold member, or `null`. */
export function readGovernanceHold(value: unknown): GovernanceHold | null {
  return typeof value === 'string' && containsValue(GOVERNANCE_HOLDS, value)
    ? (value as GovernanceHold)
    : null;
}

/* ------------------------------------------------------------------------- *
 * The F1..F10 fact schema
 * ------------------------------------------------------------------------- */

/**
 * One observed fact.
 *
 * Every fact is **either** determinate with a value **or** indeterminate — there
 * is no third shape and no default. An observation failure, a truncated output,
 * a timeout, a non-zero exit, a malformed body, or a contradiction folds to
 * `determinate: false` (Decision 065 §4 and Amendment 1 C-2), and any
 * indeterminate fact forces `BLOCKED`.
 *
 * `determinate: false` carries **no** value field at all, so there is no stale or
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
 * The ten pre-classification facts, and the **entire** classifier input.
 *
 * This interface is the classifier's whole signature. It carries no
 * `evidenceId`, no digest, no admission pointer, no projection state, no
 * timestamp, and no prose — those cannot be classifier inputs, so they are not
 * typed here and have nowhere to land.
 */
export interface RetirementFacts {
  /** F1 — observed candidate ref and SHA equal the configured immutable identity. */
  readonly f1CandidateIdentity: RetirementFact<boolean>;
  /** F2 — the remote's candidate ref agrees with the configured candidate SHA. */
  readonly f2RemoteAgreement: RetirementFact<boolean>;
  /** F3 — authoritative main equals the configured value and did not move. */
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

/** Every fact key, in declaration order. Report order is this order. */
export const RETIREMENT_FACT_ORDER: readonly (keyof RetirementFacts)[] = objectFreeze([
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

/* ------------------------------------------------------------------------- *
 * The classifier
 * ------------------------------------------------------------------------- */

/**
 * The classifier's answer. `gateRequested` is a mechanical restatement of
 * `classification === RETIRE_ELIGIBLE`, stored once so no consumer re-derives it
 * differently; it is a *request*, never an authority.
 */
export interface RetirementAssessmentVerdict {
  readonly classification: RetirementClassification;
  /** Closed-vocabulary reasons, in {@link RETIREMENT_REASONS} order. */
  readonly reasonCodes: readonly RetirementReason[];
  /** `true` exactly when the classification is `RETIRE_ELIGIBLE`. Not authority. */
  readonly gateRequested: boolean;
}

/** Read a boolean fact, or `null` when it is indeterminate. */
function boolFact(fact: RetirementFact<boolean>): boolean | null {
  return fact.determinate ? fact.value : null;
}

/** Read a count fact, or `null` when it is indeterminate. */
function countFact(fact: RetirementFact<number>): number | null {
  return fact.determinate ? fact.value : null;
}

/**
 * Classify one retirement candidate from the pre-classification facts F1..F10.
 *
 * **Pure and total.** Every input combination — including combinations that
 * cannot arise from a correct observer — yields exactly one classification, and
 * anything not positively matching `PRESERVE_FOR_HISTORY` or `RETIRE_ELIGIBLE`
 * is `BLOCKED`. There is no throw, no I/O, no clock, and no randomness, and
 * equal inputs always yield an equal verdict.
 *
 * Precedence is `BLOCKED` > `PRESERVE_FOR_HISTORY` > `RETIRE_ELIGIBLE`
 * (Decision 065). The order below implements exactly that:
 *
 * 1. any indeterminate fact → `BLOCKED`;
 * 2. F1, F2, F3, F7, F8, or F10 false → `BLOCKED`;
 * 3. an internal contradiction between two determinate facts → `BLOCKED`;
 * 4. F5 > 0, F6 > 0, or F9 = `HOLD` → `PRESERVE_FOR_HISTORY`;
 * 5. every fact determinate, F1/F2/F3/F4/F7/F8/F10 true, F5 = 0, F6 = 0,
 *    F9 = `NO_HOLD` → `RETIRE_ELIGIBLE`;
 * 6. anything else → `BLOCKED` (ambiguity is always BLOCKED).
 *
 * @param facts The ten pre-classification facts. The **only** input.
 */
export function classifyRetirementCandidate(facts: RetirementFacts): RetirementAssessmentVerdict {
  const reasons: RetirementReason[] = [];

  const f1 = boolFact(facts.f1CandidateIdentity);
  const f2 = boolFact(facts.f2RemoteAgreement);
  const f3 = boolFact(facts.f3StableMain);
  const f4 = boolFact(facts.f4Containment);
  const f5 = countFact(facts.f5UniqueCommits);
  const f6 = countFact(facts.f6UniquePatches);
  const f7 = boolFact(facts.f7WorktreeClean);
  const f8 = boolFact(facts.f8DependencyClearance);
  const f9 = facts.f9GovernanceManifest.determinate ? facts.f9GovernanceManifest.value : null;
  const f10 = boolFact(facts.f10NotProtected);

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

  if (anyIndeterminate) {
    append(reasons, RETIREMENT_REASON.INDETERMINATE_FACT);
  }

  // Blocking false facts. Collected even alongside indeterminacy so the reason
  // list explains everything that is wrong, not only the first thing.
  if (f1 === false) {
    append(reasons, RETIREMENT_REASON.CANDIDATE_IDENTITY_MISMATCH);
  }
  if (f2 === false) {
    append(reasons, RETIREMENT_REASON.REMOTE_DISAGREEMENT);
  }
  if (f3 === false) {
    append(reasons, RETIREMENT_REASON.MAIN_UNSTABLE);
  }
  if (f4 === false) {
    append(reasons, RETIREMENT_REASON.NOT_CONTAINED);
  }
  if (f5 !== null && f5 > 0) {
    append(reasons, RETIREMENT_REASON.UNIQUE_COMMITS_PRESENT);
  }
  if (f6 !== null && f6 > 0) {
    append(reasons, RETIREMENT_REASON.UNIQUE_PATCHES_PRESENT);
  }
  if (f7 === false) {
    append(reasons, RETIREMENT_REASON.WORKTREE_NOT_CLEAN);
  }
  if (f8 === false) {
    append(reasons, RETIREMENT_REASON.DEPENDENCY_CLEARANCE_FAILED);
  }
  if (f9 === GOVERNANCE_HOLD.HOLD) {
    append(reasons, RETIREMENT_REASON.GOVERNANCE_HOLD);
  }
  if (f10 === false) {
    append(reasons, RETIREMENT_REASON.PROTECTED_OR_DEFAULT_BRANCH);
  }

  // Internal contradictions between two *determinate* facts. Containment and the
  // unique-commit count are two readings of one truth: a candidate contained in
  // main has no unique commits, and one with unique commits is not contained. A
  // disagreement is never resolved in favour of either reading — it is BLOCKED.
  // Likewise a patch count may never exceed the commit count it is drawn from.
  const contradiction =
    (f4 !== null && f5 !== null && f4 !== (f5 === 0)) || (f5 !== null && f6 !== null && f6 > f5);
  if (contradiction) {
    append(reasons, RETIREMENT_REASON.INTERNAL_CONTRADICTION);
  }

  // The two blocking predicates are computed in their own statements, over the
  // still-nullable locals. Folding them into one chain beside `anyIndeterminate`
  // would let TypeScript's aliased-condition narrowing prove each `=== false`
  // redundant — and a comparison the compiler has already decided is a comparison
  // a later edit can change the meaning of without anything noticing.
  const blockingFalseFact =
    f1 === false ||
    f2 === false ||
    f3 === false ||
    f7 === false ||
    f8 === false ||
    f10 === false;

  // Stated in full, exactly as Decision 065 states the RETIRE_ELIGIBLE condition,
  // and likewise evaluated before any branch narrows the locals.
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

  const blocked = anyIndeterminate || contradiction || blockingFalseFact;
  const preserve = (f5 !== null && f5 > 0) || (f6 !== null && f6 > 0) || f9 === GOVERNANCE_HOLD.HOLD;
  const eligible = !blocked && everyFactClear;

  // Precedence, in one place: BLOCKED > PRESERVE_FOR_HISTORY > RETIRE_ELIGIBLE.
  // Ambiguity is always BLOCKED — any residue that is neither a positive preserve
  // nor a complete eligibility match falls to the final branch, never to a
  // permissive value.
  if (blocked) {
    return verdict(RETIREMENT_CLASSIFICATION.BLOCKED, reasons);
  }
  if (preserve) {
    return verdict(RETIREMENT_CLASSIFICATION.PRESERVE_FOR_HISTORY, reasons);
  }
  return eligible
    ? verdict(RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE, reasons)
    : verdict(RETIREMENT_CLASSIFICATION.BLOCKED, reasons);
}

/** Build the frozen verdict, deriving `gateRequested` in exactly one place. */
function verdict(
  classification: RetirementClassification,
  reasons: RetirementReason[],
): RetirementAssessmentVerdict {
  return freezeRecord({
    classification,
    reasonCodes: freezeList(reasons),
    gateRequested: classification === RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE,
  });
}

/* ------------------------------------------------------------------------- *
 * The immutable assessment body
 * ------------------------------------------------------------------------- */

/**
 * One fact as it appears in the serialized body.
 *
 * The in-memory {@link RetirementFact} discriminated union is not JSON-shaped, so
 * the body carries the flattened form: `determinate` plus a `value` that is
 * `null` exactly when `determinate` is `false`. The mapping is total in both
 * directions and is pinned by a test.
 */
export interface RetirementFactRecord {
  readonly determinate: boolean;
  /** `null` exactly when `determinate` is `false`. */
  readonly value: string | number | boolean | null;
}

/**
 * The immutable assessment body — the content the evidence pointer is bound to.
 *
 * Every field is a string, a safe integer, a boolean, `null`, or a frozen record
 * of those, so the body canonicalizes under AB-CJSON-1 and survives a plain-JSON
 * round trip unchanged. There is deliberately **no** authority-, approval-,
 * permission-, or deletion-shaped field: an authority value has nowhere to land.
 */
export interface RetirementAssessmentBody {
  /** The one repository this assessment is about. D1 cross-checks it. */
  readonly repositoryId: string;
  /** The immutable, human-configured candidate ref. */
  readonly candidateRef: string;
  /** The immutable, human-configured candidate SHA. D4 cross-checks it. */
  readonly candidateSha: string;
  /** The authoritative main SHA this assessment was reconciled against. */
  readonly authoritativeMainSha: string;
  /** The ten facts, flattened for serialization, in `RETIREMENT_FACT_ORDER`. */
  readonly facts: Readonly<Record<string, RetirementFactRecord>>;
  readonly classification: RetirementClassification;
  readonly reasonCodes: readonly RetirementReason[];
  /** Mechanical restatement of `classification === RETIRE_ELIGIBLE`. Not authority. */
  readonly gateRequested: boolean;
  /** `sha256:` + 64 hex of the verified governance run manifest. Identity only. */
  readonly manifestDigest: string;
  /** Externally supplied assessment timestamp. Data; no clock is read here. */
  readonly generatedAt: string;
  /** The observer build identity that produced the facts. Audit only, inert. */
  readonly observerVersion: string;
}

/**
 * The admitted envelope: an evidence pointer plus the body it is bound to.
 *
 * The pointer is the authority (Decision 065 §6); the body is shown only while it
 * is digest-bound to that pointer. The binding is re-proved on every store read
 * (I3) and again before projection (I4) — never assumed from the envelope's own
 * shape.
 */
export interface RetirementAssessmentEnvelope {
  /** `sha256:` + exactly 64 lowercase hex characters. */
  readonly evidenceId: string;
  readonly body: RetirementAssessmentBody;
}

/* ------------------------------------------------------------------------- *
 * Evidence-id format
 * ------------------------------------------------------------------------- */

/** The one accepted evidence-id prefix. */
export const EVIDENCE_ID_PREFIX = 'sha256:';

/** Hex characters in a SHA-256 digest. */
const SHA256_HEX_LENGTH = 64;

const CODE_ZERO = 0x30;
const CODE_NINE = 0x39;
const CODE_LOWER_A = 0x61;
const CODE_LOWER_F = 0x66;

/** Character code at `index`, or `-1` if the read is unusable. */
function charCodeAt(value: string, index: number): number {
  const code: unknown = reflectApply(stringCharCodeAt, value, [index]);
  return typeof code === 'number' && numberIsInteger(code) ? code : -1;
}

/** Is this a lowercase hex digit? Uppercase is rejected: the format is exact. */
function isLowerHex(code: number): boolean {
  return (code >= CODE_ZERO && code <= CODE_NINE) || (code >= CODE_LOWER_A && code <= CODE_LOWER_F);
}

/**
 * Narrow an untrusted value to a well-formed evidence id, or `null`.
 *
 * The format is exact: the literal prefix `sha256:` followed by exactly 64
 * **lowercase** hex characters, and nothing else. The value is returned
 * unmodified — never trimmed, lowercased, or truncated, because normalising an
 * identifier before comparison is a bypass vector on a binding boundary.
 */
export function readEvidenceId(value: unknown): string | null {
  if (typeof value !== 'string' || value.length !== EVIDENCE_ID_PREFIX.length + SHA256_HEX_LENGTH) {
    return null;
  }
  for (let index = 0; index < EVIDENCE_ID_PREFIX.length; index += 1) {
    if (charCodeAt(value, index) !== charCodeAt(EVIDENCE_ID_PREFIX, index)) {
      return null;
    }
  }
  for (let index = EVIDENCE_ID_PREFIX.length; index < value.length; index += 1) {
    if (!isLowerHex(charCodeAt(value, index))) {
      return null;
    }
  }
  return value;
}

/* ------------------------------------------------------------------------- *
 * AB-CJSON-1 canonicalization
 * ------------------------------------------------------------------------- */

/**
 * Sort keys by UTF-16 code unit.
 *
 * An explicit insertion sort over a plain indexed list, comparing code units
 * directly: no `Array.prototype.sort` (whose comparator contract and
 * implementation are replaceable) and no locale-aware comparison is on the path,
 * so the ordering is exactly the specification's and cannot be influenced by a
 * mutated realm.
 */
function sortKeysByCodeUnit(keys: readonly string[]): string[] {
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
      objectDefineProperty(sorted, position, {
        value: previous,
        writable: true,
        enumerable: true,
        configurable: true,
      });
      position -= 1;
    }
    objectDefineProperty(sorted, position, {
      value: key,
      writable: true,
      enumerable: true,
      configurable: true,
    });
  }
  return sorted;
}

/** Compare two strings by UTF-16 code unit. Returns <0, 0, or >0. */
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
 * Canonicalize one value under **AB-CJSON-1**, or return `null`.
 *
 * The format, exactly:
 *
 * - UTF-8 JSON text with **no** whitespace anywhere;
 * - object keys sorted by **UTF-16 code unit**, at every depth;
 * - arrays serialized in **declared order** (never sorted);
 * - scalars limited to **string**, **safe integer**, **boolean**, and **null**.
 *
 * Anything else **rejects**: a non-integer number, `NaN`, `±Infinity`, `-0`, a
 * `bigint`, a `symbol`, a function, `undefined`, a Date, a Map, a class
 * instance with behaviour, a getter, a Proxy that throws, a cycle, or a value
 * exceeding a {@link RETIREMENT_BOUNDS} limit. Rejection is `null`, never a
 * throw and never a lossy coercion: a body that cannot be canonicalized has no
 * digest, so the runtime fails closed rather than digesting an approximation.
 *
 * Only **own enumerable** string keys are canonicalized, and each value is read
 * exactly once, so an inherited or accessor property can neither enter the
 * canonical bytes nor differ between the digest and the stored body.
 *
 * @returns The canonical JSON text, or `null` when the value is not canonicalizable.
 */
export function canonicalizeAssessmentBody(value: unknown): string | null {
  return canonicalize(value, 0, []);
}

/** The recursive canonicalizer. `seen` is the ancestor stack: it detects cycles. */
function canonicalize(value: unknown, depth: number, seen: readonly object[]): string | null {
  if (depth > RETIREMENT_BOUNDS.MAX_CANONICAL_DEPTH) {
    return null;
  }

  if (value === null) {
    return 'null';
  }

  const valueType = typeof value;

  if (valueType === 'boolean') {
    return value === true ? 'true' : 'false';
  }

  if (valueType === 'string') {
    const text = value as string;
    if (text.length > RETIREMENT_BOUNDS.MAX_CANONICAL_STRING_LENGTH) {
      return null;
    }
    // `JSON.stringify` of a string produces the canonical escaped form. It is
    // captured at load, and a string has no `toJSON` to invoke, so no
    // caller-controlled code runs here.
    const encoded: unknown = jsonStringify(text);
    return typeof encoded === 'string' ? encoded : null;
  }

  if (valueType === 'number') {
    const numeric = value as number;
    // Safe integers only. `-0` is rejected explicitly: it serializes as `0` and
    // would make two distinct inputs share one digest.
    if (!numberIsSafeInteger(numeric) || Object.is(numeric, -0)) {
      return null;
    }
    return String(numeric);
  }

  if (valueType !== 'object') {
    // bigint, symbol, function, undefined.
    return null;
  }

  const node = value as object;

  // Cycle detection by reference identity over the ancestor stack.
  for (let index = 0; index < seen.length; index += 1) {
    if (seen[index] === node) {
      return null;
    }
  }
  const nextSeen: object[] = [];
  for (let index = 0; index < seen.length; index += 1) {
    const ancestor = seen[index];
    if (ancestor !== undefined) {
      append(nextSeen, ancestor);
    }
  }
  append(nextSeen, node);

  let isArray: boolean;
  try {
    isArray = arrayIsArray(node);
  } catch {
    // `Array.isArray` throws on a revoked Proxy.
    return null;
  }

  if (isArray) {
    const elements = node as readonly unknown[];
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
    let out = '[';
    for (let index = 0; index < length; index += 1) {
      let element: unknown;
      try {
        if (!objectHasOwn(elements, index)) {
          // A sparse hole is not `null`; it is not canonicalizable.
          return null;
        }
        element = (elements as Record<number, unknown>)[index];
      } catch {
        return null;
      }
      const encoded = canonicalize(element, depth + 1, nextSeen);
      if (encoded === null) {
        return null;
      }
      out += index === 0 ? encoded : ',' + encoded;
    }
    return out + ']';
  }

  // Only a **plain** object node canonicalizes: one whose prototype is
  // `Object.prototype` or `null`. Anything else — a Date, a Map, a Set, a
  // RegExp, an Error, a class instance, a boxed primitive — is rejected.
  //
  // This check is load-bearing, not defensive. Such an object typically has no
  // own enumerable keys, so without it a `Date` would canonicalize to `{}` and
  // every distinct Date in a body would share one digest with every other, and
  // with an empty object. Two different bodies sharing a digest is precisely the
  // failure the evidence pointer exists to prevent.
  let prototype: unknown;
  try {
    prototype = objectGetPrototypeOf(node);
  } catch {
    return null;
  }
  if (prototype !== objectPrototype && prototype !== null) {
    return null;
  }

  // Own enumerable string keys only, sorted by code unit.
  let ownKeys: readonly string[];
  try {
    ownKeys = objectKeys(node);
  } catch {
    return null;
  }
  if (ownKeys.length > RETIREMENT_BOUNDS.MAX_CANONICAL_KEYS) {
    return null;
  }
  const sorted = sortKeysByCodeUnit(ownKeys);

  let out = '{';
  for (let index = 0; index < sorted.length; index += 1) {
    const key = sorted[index];
    if (key === undefined) {
      return null;
    }
    if (key.length > RETIREMENT_BOUNDS.MAX_CANONICAL_STRING_LENGTH) {
      return null;
    }
    let member: unknown;
    try {
      member = (node as Record<string, unknown>)[key];
    } catch {
      return null;
    }
    const encodedValue = canonicalize(member, depth + 1, nextSeen);
    if (encodedValue === null) {
      return null;
    }
    const encodedKey: unknown = jsonStringify(key);
    if (typeof encodedKey !== 'string') {
      return null;
    }
    const pair = encodedKey + ':' + encodedValue;
    out += index === 0 ? pair : ',' + pair;
  }
  return out + '}';
}

/* ------------------------------------------------------------------------- *
 * The hostile envelope reader
 * ------------------------------------------------------------------------- */

/** Read one flattened fact record, or `null` when malformed. */
function readFactRecord(value: unknown): RetirementFactRecord | null {
  if (typeof value !== 'object' || value === null) {
    return null;
  }
  const rawDeterminate = readOwnProperty(value, 'determinate');
  if (typeof rawDeterminate !== 'boolean') {
    return null;
  }
  const rawValue = readOwnProperty(value, 'value');

  if (!rawDeterminate) {
    // An indeterminate fact carries exactly `null`. A present value would be a
    // stale reading a later branch could mistake for an observation.
    return rawValue === null ? freezeRecord({ determinate: false, value: null }) : null;
  }

  if (typeof rawValue === 'boolean') {
    return freezeRecord({ determinate: true, value: rawValue });
  }
  if (typeof rawValue === 'number') {
    return numberIsSafeInteger(rawValue) &&
      !Object.is(rawValue, -0) &&
      rawValue >= 0 &&
      rawValue <= RETIREMENT_BOUNDS.MAX_COUNT
      ? freezeRecord({ determinate: true, value: rawValue })
      : null;
  }
  if (typeof rawValue === 'string') {
    // The only string-valued fact is F9, whose vocabulary is closed.
    return readGovernanceHold(rawValue) === null
      ? null
      : freezeRecord({ determinate: true, value: rawValue });
  }
  return null;
}

/** Read the facts map: every key in {@link RETIREMENT_FACT_ORDER}, and no other. */
function readFactsMap(value: unknown): Readonly<Record<string, RetirementFactRecord>> | null {
  if (typeof value !== 'object' || value === null) {
    return null;
  }
  let ownKeys: readonly string[];
  try {
    ownKeys = objectKeys(value);
  } catch {
    return null;
  }
  // Exactly the ten known keys: a surplus key would enter the canonical bytes and
  // change the digest, and a missing key would leave a fact unstated.
  if (ownKeys.length !== RETIREMENT_FACT_ORDER.length) {
    return null;
  }

  const facts: Record<string, RetirementFactRecord> = {};
  objectSetPrototypeOf(facts, null);
  for (let index = 0; index < RETIREMENT_FACT_ORDER.length; index += 1) {
    const key = RETIREMENT_FACT_ORDER[index];
    if (key === undefined) {
      return null;
    }
    let present: boolean;
    try {
      present = objectHasOwn(value, key);
    } catch {
      return null;
    }
    if (!present) {
      return null;
    }
    const record = readFactRecord(readOwnProperty(value, key));
    if (record === null) {
      return null;
    }
    objectDefineProperty(facts, key, {
      value: record,
      writable: false,
      enumerable: true,
      configurable: false,
    });
  }
  return objectFreeze(facts);
}

/** Read the closed-vocabulary reason list, all-or-nothing. */
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
  const reasons: RetirementReason[] = [];
  for (let index = 0; index < length; index += 1) {
    let element: unknown;
    try {
      if (!objectHasOwn(elements, index)) {
        return null;
      }
      element = (elements as Record<number, unknown>)[index];
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
 * Read one untrusted `{ evidenceId, body }` envelope, or `null`.
 *
 * Pure, total, and deterministic; never throws. Every value is read exactly once
 * into a local and never re-read, so a getter or Proxy that returns a different
 * value on each access cannot validate one value and hand a different one to the
 * accepted envelope. Only **own** properties are consulted. The accepted envelope
 * is a frozen copy built from validated locals — never the caller's objects — so
 * later mutation of the input cannot change it.
 *
 * This reader checks **shape**, not binding: it deliberately does **not** verify
 * that `evidenceId` is the digest of `body`. That is the runtime layer's job
 * (I1/I3), because the digest may not be computed in the domain. An envelope
 * that reads cleanly here is still unbound until a digest check proves otherwise.
 */
export function readRetirementAssessment(value: unknown): RetirementAssessmentEnvelope | null {
  if (typeof value !== 'object' || value === null) {
    return null;
  }

  const evidenceId = readEvidenceId(readOwnProperty(value, 'evidenceId'));
  const rawBody = readOwnProperty(value, 'body');
  if (evidenceId === null || typeof rawBody !== 'object' || rawBody === null) {
    return null;
  }

  const repositoryId = readExactIdentifier(readOwnProperty(rawBody, 'repositoryId'));
  const candidateRef = readExactIdentifier(readOwnProperty(rawBody, 'candidateRef'));
  const candidateSha = readExactIdentifier(readOwnProperty(rawBody, 'candidateSha'));
  const authoritativeMainSha = readExactIdentifier(
    readOwnProperty(rawBody, 'authoritativeMainSha'),
  );
  const facts = readFactsMap(readOwnProperty(rawBody, 'facts'));
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

  // `gateRequested` is a mechanical restatement of the classification, so a body
  // whose two disagree is internally inconsistent and is rejected whole. It is
  // never "repaired" by preferring one side: that would let a crafted body turn a
  // BLOCKED assessment into a gate request.
  if (rawGateRequested !== (classification === RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE)) {
    return null;
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

/**
 * Build the serialized facts map from the in-memory fact set.
 *
 * The one place the discriminated union is flattened for serialization, so the
 * mapping cannot drift between producers. An indeterminate fact becomes
 * `{ determinate: false, value: null }` exactly.
 */
export function toFactRecords(
  facts: RetirementFacts,
): Readonly<Record<string, RetirementFactRecord>> {
  const records: Record<string, RetirementFactRecord> = {};
  objectSetPrototypeOf(records, null);
  for (let index = 0; index < RETIREMENT_FACT_ORDER.length; index += 1) {
    const key = RETIREMENT_FACT_ORDER[index];
    if (key === undefined) {
      continue;
    }
    const fact: RetirementFact<string | number | boolean> = facts[key];
    objectDefineProperty(records, key, {
      value: fact.determinate
        ? freezeRecord({ determinate: true, value: fact.value })
        : freezeRecord({ determinate: false, value: null }),
      writable: false,
      enumerable: true,
      configurable: false,
    });
  }
  return objectFreeze(records);
}

/**
 * Pure capability-registry eligibility evaluator.
 *
 * A capability registry answers exactly one question: *has an operator
 * explicitly admitted this one (providerId, agentId) pair, for this one
 * purpose, in this one pinned registry version?* Nothing else. The evaluator is
 * a total function over a registry version supplied by value and a query
 * supplied by value, and it returns a verdict.
 *
 * The protected invariant, stated once:
 *
 * > No `(providerId, agentId)` pair is eligible for an invocation purpose
 * > unless one pinned, immutable, operator-admitted capability-registry version
 * > contains exactly one entry for that exact pair, in state `APPROVED`, whose
 * > explicit canonical purpose set contains exactly that purpose — and no other
 * > input, parameter, default, hierarchy, human approval record, or outward
 * > reach can create, widen, or substitute for that approval.
 *
 * What that rules out, permanently: provider-level approval, agent-level
 * approval, wildcards, purpose implication (`audit` never implies `review`),
 * inheritance from a parent registry, "latest" or "default" version resolution,
 * and any fallback that turns an unreadable or malformed registry into a
 * permissive answer. Every failure is a refusal.
 *
 * `registryVersion` is read here as an **opaque exact identifier** and echoed.
 * This module does not derive it from content, does not hash, does not
 * canonically serialize, and does not detect a mismatch between an identifier
 * and the entries beside it. Binding an identifier to its content is
 * admission-boundary work and deliberately lives elsewhere; an evaluator that
 * also minted identity could be talked into accepting one it minted itself.
 *
 * The module imports only from `./agent-invocation.js`, reads no clock, no
 * environment, no filesystem, and no network, holds no module-level mutable
 * state, caches nothing, and mutates no input. It never throws: every hostile
 * shape — throwing getters, Proxy traps, poisoned prototypes, inherited
 * properties, cycles, getters that answer differently on each read — resolves
 * to a refusing verdict. It also always returns: no input can loop it, because
 * the entry walk is capped by {@link CAPABILITY_REGISTRY_BOUNDS} before it
 * begins, and the purpose walk is self-limiting.
 *
 * Nothing on an authority path resolves a prototype method at call time. There
 * is deliberately no `Map` and no `Set`: an entry getter runs *before* the pair
 * lookup does, and `Map.prototype.get` is replaceable in exactly that window,
 * so a keyed container could be made to hand back an entry no operator ever
 * wrote. Same reasoning, and the same resolution, as `resolveJobOperation` in
 * `job-operation.ts`: a plain indexed scan can only return a value this module
 * already validated itself.
 */

import {
  INVOCATION_PURPOSES,
  isInvocationPurpose,
  readExactIdentifier,
  readOwnProperty,
  type InvocationPurpose,
} from './agent-invocation.js';

/**
 * Intrinsics captured at module load.
 *
 * Registry versions and queries are read through getters and Proxy traps that
 * run during evaluation, and such a trap can repoint globals afterwards.
 * Capturing first removes that lever. Same pattern as `agent-invocation.ts`.
 *
 * The list is short because this module leans on almost nothing else: no keyed
 * container and no `Array.prototype` call sits on an authority path. What is
 * never reached cannot be repointed.
 */
const objectFreeze = Object.freeze;
const objectDefineProperty = Object.defineProperty;
const objectSetPrototypeOf = Object.setPrototypeOf;
const arrayIsArray = Array.isArray;
const stringOf = String;

/**
 * Append by defining an own element, bypassing inherited index setters.
 *
 * A payload that plants a setter on `Array.prototype[0]` would otherwise
 * intercept the first write to any fresh array built here.
 */
function append<T>(list: T[], value: T): void {
  // The descriptor object would inherit from `Object.prototype`, and
  // `Object.defineProperty` consults inherited `get`/`set` while reading it, so
  // a poisoned `Object.prototype.get` would be honoured. Detaching the
  // descriptor's prototype leaves only its own data attributes visible.
  const descriptor: PropertyDescriptor = {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  };
  objectSetPrototypeOf(descriptor, null);
  objectDefineProperty(list, list.length, descriptor);
}

/**
 * Operator admission state of one registry entry.
 *
 * Exactly three members, and no `PENDING`, `UNKNOWN`, or `PROVISIONAL`. A state
 * this evaluator does not recognise invalidates the whole registry version
 * rather than degrading to a weaker meaning, so there is no value an author can
 * write that means "not sure yet, treat as fine".
 */
export const CAPABILITY_APPROVAL_STATE = objectFreeze({
  APPROVED: 'APPROVED',
  SUSPENDED: 'SUSPENDED',
  WITHDRAWN: 'WITHDRAWN',
} as const);

export type CapabilityApprovalState =
  (typeof CAPABILITY_APPROVAL_STATE)[keyof typeof CAPABILITY_APPROVAL_STATE];

/** Every member of the {@link CapabilityApprovalState} union. */
export const CAPABILITY_APPROVAL_STATES: readonly CapabilityApprovalState[] = objectFreeze([
  CAPABILITY_APPROVAL_STATE.APPROVED,
  CAPABILITY_APPROVAL_STATE.SUSPENDED,
  CAPABILITY_APPROVAL_STATE.WITHDRAWN,
]);

/**
 * Why the evaluator answered the way it did.
 *
 * `ELIGIBLE` is the only permissive member; the other seven are distinct
 * refusals. They are distinct on purpose — "the registry could not be read",
 * "the registry is malformed", "you asked badly", "that pair was never
 * admitted", "that pair is suspended", "that pair is withdrawn", and "that pair
 * is admitted but not for this purpose" call for very different operator
 * responses, and collapsing them would hide a broken registry behind what looks
 * like a routine denial.
 */
export const CAPABILITY_ELIGIBILITY_REASON = objectFreeze({
  /** Exactly one APPROVED entry for the exact pair lists exactly this purpose. */
  ELIGIBLE: 'ELIGIBLE',
  /** The query itself was unusable; no pair was resolved. */
  QUERY_INVALID: 'QUERY_INVALID',
  /** The registry version's own identity or entry list could not be read. */
  REGISTRY_UNREADABLE: 'REGISTRY_UNREADABLE',
  /** The registry was readable but its content violates the entry contract. */
  REGISTRY_INVALID: 'REGISTRY_INVALID',
  /** No entry exists for that exact pair. */
  PAIR_NOT_APPROVED: 'PAIR_NOT_APPROVED',
  /** The pair exists but its admission is suspended. */
  PAIR_SUSPENDED: 'PAIR_SUSPENDED',
  /** The pair exists but its admission is withdrawn. */
  PAIR_WITHDRAWN: 'PAIR_WITHDRAWN',
  /** The pair is APPROVED, but this purpose is not in its explicit set. */
  PURPOSE_NOT_APPROVED: 'PURPOSE_NOT_APPROVED',
} as const);

export type CapabilityEligibilityReason =
  (typeof CAPABILITY_ELIGIBILITY_REASON)[keyof typeof CAPABILITY_ELIGIBILITY_REASON];

/** Every member of the {@link CapabilityEligibilityReason} union. */
export const CAPABILITY_ELIGIBILITY_REASONS: readonly CapabilityEligibilityReason[] = objectFreeze(
  [
    CAPABILITY_ELIGIBILITY_REASON.ELIGIBLE,
    CAPABILITY_ELIGIBILITY_REASON.QUERY_INVALID,
    CAPABILITY_ELIGIBILITY_REASON.REGISTRY_UNREADABLE,
    CAPABILITY_ELIGIBILITY_REASON.REGISTRY_INVALID,
    CAPABILITY_ELIGIBILITY_REASON.PAIR_NOT_APPROVED,
    CAPABILITY_ELIGIBILITY_REASON.PAIR_SUSPENDED,
    CAPABILITY_ELIGIBILITY_REASON.PAIR_WITHDRAWN,
    CAPABILITY_ELIGIBILITY_REASON.PURPOSE_NOT_APPROVED,
  ],
);

/**
 * Bounds for one registry version.
 *
 * A registry holds one entry per `(providerId, agentId)` pair an operator
 * admitted individually, so it is a curated list rather than machine-generated
 * data, and 1024 is far past any real one.
 *
 * The cap exists because `entries` is only ever *reported* to be a given
 * length. A real array cannot lie about it, but a Proxy can claim `2 ** 31` and
 * synthesise a fresh valid entry for every index, and an evaluator that walked
 * that would never return. Checking the count first turns it into a
 * constant-time refusal, and keeps the duplicate scan bounded as a side effect.
 *
 * Exported because the tests pin behaviour at exactly the bound and at one past
 * it; a literal copied into the test file would keep passing while silently
 * asserting a stale boundary. Same reason `INVOCATION_BOUNDS` is exported. A
 * frozen integer confers no authority.
 */
export const CAPABILITY_REGISTRY_BOUNDS = objectFreeze({
  /** Entries examined in one registry version. Above this, the version refuses. */
  MAX_ENTRIES: 1_024,
} as const);

/**
 * One operator-admitted capability.
 *
 * `approvedPurposes` is an explicit, non-empty, duplicate-free list in
 * {@link INVOCATION_PURPOSES} declaration order. Canonical order is required
 * rather than sorted on read so that two registry versions listing the same
 * purposes are identical at this boundary, and so an author cannot smuggle
 * meaning into ordering.
 */
export interface CapabilityRegistryEntry {
  readonly providerId: string;
  readonly agentId: string;
  readonly approvedPurposes: readonly InvocationPurpose[];
  readonly approvalState: CapabilityApprovalState;
}

/**
 * One pinned, immutable registry version, supplied whole and by value.
 *
 * There is no "current" registry to look up and no store to consult: the caller
 * has already pinned the version it wants evaluated, and this module cannot
 * reach a different one.
 */
export interface CapabilityRegistryVersion {
  readonly registryVersion: string;
  readonly entries: readonly CapabilityRegistryEntry[];
}

/** The exact triple being asked about. No wildcards, no optional fields. */
export interface CapabilityQuery {
  readonly providerId: string;
  readonly agentId: string;
  readonly purpose: InvocationPurpose;
}

/**
 * The verdict.
 *
 * Every field is always present; unavailable ones are `null` rather than
 * omitted, so a consumer can never mistake an absent key for a permissive
 * default. `eligible` is derived from `reason` and is true only for
 * `ELIGIBLE`. Deliberately absent: the matched entry, its purpose set, its
 * index, and any entry count — nothing here lets a caller re-derive authority
 * from the registry's interior.
 */
export interface CapabilityEligibility {
  readonly eligible: boolean;
  readonly reason: CapabilityEligibilityReason;
  readonly registryVersion: string | null;
  readonly providerId: string | null;
  readonly agentId: string | null;
  readonly purpose: InvocationPurpose | null;
}

/** A validated entry, read exactly once into an immutable snapshot. */
interface EntrySnapshot {
  readonly providerId: string;
  readonly agentId: string;
  readonly approvedPurposes: readonly InvocationPurpose[];
  readonly approvalState: CapabilityApprovalState;
}

/** Build the verdict, deriving `eligible` so the two can never disagree. */
function verdict(
  reason: CapabilityEligibilityReason,
  registryVersion: string | null,
  providerId: string | null,
  agentId: string | null,
  purpose: InvocationPurpose | null,
): CapabilityEligibility {
  return objectFreeze({
    eligible: reason === CAPABILITY_ELIGIBILITY_REASON.ELIGIBLE,
    reason,
    registryVersion,
    providerId,
    agentId,
    purpose,
  });
}

/** The registry could not be read at all, so nothing about it is echoed. */
function unreadable(): CapabilityEligibility {
  return verdict(CAPABILITY_ELIGIBILITY_REASON.REGISTRY_UNREADABLE, null, null, null, null);
}

/** Registry content is malformed. Identity was readable, so it is echoed. */
function registryInvalid(versionId: string): CapabilityEligibility {
  return verdict(CAPABILITY_ELIGIBILITY_REASON.REGISTRY_INVALID, versionId, null, null, null);
}

/** Position of a value in {@link INVOCATION_PURPOSES}, or `-1` if unknown. */
function purposeIndex(value: unknown): number {
  for (let index = 0; index < INVOCATION_PURPOSES.length; index += 1) {
    if (INVOCATION_PURPOSES[index] === value) {
      return index;
    }
  }
  return -1;
}

/** Narrow to an exact approval state. Case-sensitive; `'approved'` is not one. */
function readApprovalState(value: unknown): CapabilityApprovalState | null {
  if (typeof value !== 'string') {
    return null;
  }
  for (let index = 0; index < CAPABILITY_APPROVAL_STATES.length; index += 1) {
    const member = CAPABILITY_APPROVAL_STATES[index];
    if (member !== undefined && member === value) {
      return member;
    }
  }
  return null;
}

/**
 * Read an array's own `length` as a non-negative integer, or `null`.
 *
 * Guarded because a Proxy's `getOwnPropertyDescriptor` or `get` trap can throw
 * or lie about `length`.
 */
function readLength(list: object): number | null {
  const raw = readOwnProperty(list, 'length');
  if (typeof raw !== 'number' || !Number.isInteger(raw) || raw < 0) {
    return null;
  }
  return raw;
}

/**
 * Read an entry's purpose set: a non-empty, duplicate-free list in canonical
 * declaration order.
 *
 * One strictly-increasing index walk enforces all three at once — an unknown
 * purpose yields `-1`, a repeat yields an equal index, and a swap yields a
 * smaller one — so none of the three can be satisfied at another's expense.
 */
function readApprovedPurposes(value: unknown): readonly InvocationPurpose[] | null {
  if (!arrayIsArray(value)) {
    return null;
  }
  const list: object = value;
  const length = readLength(list);
  if (length === null || length === 0) {
    return null;
  }
  const purposes: InvocationPurpose[] = [];
  let previous = -1;
  for (let index = 0; index < length; index += 1) {
    const position = purposeIndex(readOwnProperty(list, stringOf(index)));
    if (position <= previous) {
      return null;
    }
    const member = INVOCATION_PURPOSES[position];
    if (member === undefined) {
      return null;
    }
    previous = position;
    append(purposes, member);
  }
  return objectFreeze(purposes);
}

/**
 * Read one entry into a snapshot, or `null` if it violates the contract.
 *
 * Every field is read exactly once. A getter that answers differently on each
 * read therefore cannot have one value validated and a different one matched.
 */
function readEntry(value: unknown): EntrySnapshot | null {
  if (typeof value !== 'object' || value === null || arrayIsArray(value)) {
    return null;
  }
  const providerId = readExactIdentifier(readOwnProperty(value, 'providerId'));
  if (providerId === null) {
    return null;
  }
  const agentId = readExactIdentifier(readOwnProperty(value, 'agentId'));
  if (agentId === null) {
    return null;
  }
  const approvedPurposes = readApprovedPurposes(readOwnProperty(value, 'approvedPurposes'));
  if (approvedPurposes === null) {
    return null;
  }
  const approvalState = readApprovalState(readOwnProperty(value, 'approvalState'));
  if (approvalState === null) {
    return null;
  }
  return objectFreeze({ providerId, agentId, approvedPurposes, approvalState });
}

/**
 * Find the validated snapshot for one exact pair, or `null`.
 *
 * A plain indexed scan over the evaluator's own array, touching no prototype
 * method. Deliberately not a keyed container: `Map.prototype.get` and `.has`
 * are resolved at call time, and an entry getter earlier in this same
 * evaluation can replace either one — a poisoned `get` would hand back a
 * fabricated APPROVED entry for a pair no operator admitted, and a poisoned
 * `has` would slip a duplicate pair past the check meant to refuse it. The
 * value returned on a hit is one {@link readEntry} already validated and froze,
 * never one a container produced.
 *
 * Comparing the two fields directly also retires the length-prefixed pair key
 * this module used to build. There is no encoding left to decode, so a
 * separator planted inside an identifier cannot make two distinct pairs share a
 * slot: collision safety is structural now rather than argued.
 */
function findSnapshot(
  snapshots: readonly EntrySnapshot[],
  providerId: string,
  agentId: string,
): EntrySnapshot | null {
  for (let index = 0; index < snapshots.length; index += 1) {
    const snapshot = snapshots[index];
    if (
      snapshot !== undefined &&
      snapshot.providerId === providerId &&
      snapshot.agentId === agentId
    ) {
      return snapshot;
    }
  }
  return null;
}

/** Membership test over a purpose set that touches no prototype method. */
function includesPurpose(
  purposes: readonly InvocationPurpose[],
  purpose: InvocationPurpose,
): boolean {
  for (let index = 0; index < purposes.length; index += 1) {
    if (purposes[index] === purpose) {
      return true;
    }
  }
  return false;
}

/**
 * Decide whether one exact `(providerId, agentId, purpose)` triple is eligible
 * under one pinned registry version.
 *
 * Pure, total, and deterministic. The whole registry version is validated
 * before the query is even looked at, so a malformed entry anywhere refuses
 * every query — a registry that cannot be trusted as a whole cannot be trusted
 * for the one row someone happens to be asking about.
 *
 * Refusal precedence, highest first: `REGISTRY_UNREADABLE`,
 * `REGISTRY_INVALID`, `QUERY_INVALID`, `PAIR_NOT_APPROVED`, `PAIR_SUSPENDED`,
 * `PAIR_WITHDRAWN`, `PURPOSE_NOT_APPROVED`, then `ELIGIBLE`. Pair *state* is
 * decided before purpose, so a suspended pair reads as `PAIR_SUSPENDED` even
 * when the purpose is listed: the operator revoked the pair, and reporting a
 * purpose problem would suggest the wrong remedy.
 */
export function evaluateCapabilityEligibility(
  registryVersion: CapabilityRegistryVersion,
  query: CapabilityQuery,
): CapabilityEligibility {
  const registry: unknown = registryVersion;
  if (typeof registry !== 'object' || registry === null || arrayIsArray(registry)) {
    return unreadable();
  }

  const versionId = readExactIdentifier(readOwnProperty(registry, 'registryVersion'));
  if (versionId === null) {
    return unreadable();
  }

  const rawEntries = readOwnProperty(registry, 'entries');
  if (!arrayIsArray(rawEntries)) {
    return unreadable();
  }
  const entries: object = rawEntries;
  const entryCount = readLength(entries);
  if (entryCount === null) {
    return unreadable();
  }
  if (entryCount > CAPABILITY_REGISTRY_BOUNDS.MAX_ENTRIES) {
    // Checked before a single entry is read, so a list that merely *reports* a
    // colossal length is refused in constant time rather than walked. Identity
    // and the entry list were both readable, so this is malformed content — not
    // an unreadable registry — and the version identifier is echoed with it.
    return registryInvalid(versionId);
  }

  // Call-local, so nothing survives the call and no two calls can interfere.
  const snapshots: EntrySnapshot[] = [];
  for (let index = 0; index < entryCount; index += 1) {
    const entry = readEntry(readOwnProperty(entries, stringOf(index)));
    if (entry === null) {
      return registryInvalid(versionId);
    }
    if (findSnapshot(snapshots, entry.providerId, entry.agentId) !== null) {
      // Two entries for one pair: which one is authoritative is undecidable, so
      // neither is. Widening to "any APPROVED wins" is exactly the hole here.
      return registryInvalid(versionId);
    }
    append(snapshots, entry);
  }

  const request: unknown = query;
  let providerId: string | null = null;
  let agentId: string | null = null;
  let purpose: InvocationPurpose | null = null;
  if (typeof request === 'object' && request !== null && !arrayIsArray(request)) {
    providerId = readExactIdentifier(readOwnProperty(request, 'providerId'));
    agentId = readExactIdentifier(readOwnProperty(request, 'agentId'));
    const rawPurpose = readOwnProperty(request, 'purpose');
    purpose = isInvocationPurpose(rawPurpose) ? rawPurpose : null;
  }
  if (providerId === null || agentId === null || purpose === null) {
    // Invalid fields echo `null`, never a raw or truncated value: an oversized
    // identifier must not reach the output even as a prefix.
    return verdict(
      CAPABILITY_ELIGIBILITY_REASON.QUERY_INVALID,
      versionId,
      providerId,
      agentId,
      purpose,
    );
  }

  const entry = findSnapshot(snapshots, providerId, agentId);
  if (entry === null) {
    return verdict(
      CAPABILITY_ELIGIBILITY_REASON.PAIR_NOT_APPROVED,
      versionId,
      providerId,
      agentId,
      purpose,
    );
  }
  if (entry.approvalState === CAPABILITY_APPROVAL_STATE.SUSPENDED) {
    return verdict(
      CAPABILITY_ELIGIBILITY_REASON.PAIR_SUSPENDED,
      versionId,
      providerId,
      agentId,
      purpose,
    );
  }
  if (entry.approvalState === CAPABILITY_APPROVAL_STATE.WITHDRAWN) {
    return verdict(
      CAPABILITY_ELIGIBILITY_REASON.PAIR_WITHDRAWN,
      versionId,
      providerId,
      agentId,
      purpose,
    );
  }
  if (!includesPurpose(entry.approvedPurposes, purpose)) {
    return verdict(
      CAPABILITY_ELIGIBILITY_REASON.PURPOSE_NOT_APPROVED,
      versionId,
      providerId,
      agentId,
      purpose,
    );
  }
  return verdict(CAPABILITY_ELIGIBILITY_REASON.ELIGIBLE, versionId, providerId, agentId, purpose);
}

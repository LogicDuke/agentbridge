/**
 * Governance run manifest — schema, hostile reader, and verification
 * (Autoflow Job #1, Decision 065 Revision 2).
 *
 * Job #1 must consult the authoritative deferred-obligation register, but the
 * runtime has **no Drive access, no token, and no network credential** and will
 * never acquire one. The manifest is how that squares: a separately authorized
 * **PRE-RUN GATE**, performed by an agent that *does* have Drive read access,
 * distils the register and the newest Current State checkpoint into one frozen
 * document and hands the runtime two things — the manifest text, and its digest
 * out of band.
 *
 *     PRE-RUN gate (has Drive)  ->  manifest text  +  AGENTBRIDGE_JOB1_MANIFEST_SHA256
 *                                        |                        |
 *                                        +----> verify -----------+
 *                                                  |
 *                                                  v
 *                                          F9 (HOLD | NO_HOLD | indeterminate)
 *
 * **There is no second ledger** (Decision 065 §13). This module stores nothing,
 * decides no obligation, and re-derives no hold: it verifies that the document in
 * front of it is exactly the one the gate froze, and then echoes the hold result
 * that gate recorded.
 *
 * ## Fail-closed, always
 *
 * Every verification failure — a digest mismatch, a drifted candidate or main
 * SHA, a stale or future `generatedAt`, a missing source, a malformed document —
 * makes **F9 indeterminate**, which the classifier turns into `BLOCKED`. A failed
 * manifest is *never* folded into `NO_HOLD`: "we could not check the register"
 * and "the register says go ahead" must not collapse into one answer. Only a
 * fully verified `NO_HOLD` can satisfy F9 for `RETIRE_ELIGIBLE`.
 *
 * ## No I/O
 *
 * This module reads no file, no environment, no clock, and no network. The
 * manifest **text**, the expected **digest**, the configured SHAs, and the boot
 * instant are all supplied by the caller, so verification is a pure function and
 * is exhaustively testable without a filesystem.
 */

import {
  GOVERNANCE_HOLD,
  readEvidenceId,
  readGovernanceHold,
  type GovernanceHold,
} from '../domain/retirement-assessment.js';
import { readExactIdentifier, readOwnProperty } from '../domain/repair-job.js';
import { sha256Canonical } from './retirement-assessment-store.js';

const objectFreeze = Object.freeze;
const objectHasOwn = Object.hasOwn;
const objectSetPrototypeOf = Object.setPrototypeOf;
const objectDefineProperty = Object.defineProperty;
const arrayIsArray = Array.isArray;
const numberIsInteger = Number.isInteger;
const jsonParse = JSON.parse;

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
  const descriptor: PropertyDescriptor = {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  };
  objectSetPrototypeOf(descriptor, null);
  objectDefineProperty(list, list.length, descriptor);
}

function freezeRecord<T extends object>(record: T): Readonly<T> {
  objectSetPrototypeOf(record, null);
  return objectFreeze(record);
}

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

/** Bounds for every otherwise-unbounded manifest dimension. */
export const MANIFEST_BOUNDS = objectFreeze({
  /** Sources the manifest may carry. Exactly two roles are required. */
  MAX_SOURCES: 8,
  /** Hold reason codes the manifest may carry. */
  MAX_REASON_CODES: 16,
  /** Verbatim matching entries the manifest may quote. */
  MAX_MATCHING_ENTRIES: 32,
  /** Characters in one verbatim quoted entry. */
  MAX_ENTRY_LENGTH: 4_000,
  /** Characters of manifest text that will be parsed at all. */
  MAX_MANIFEST_TEXT_LENGTH: 256_000,
  /** Freshness window before boot, in milliseconds. 24 hours. */
  FRESHNESS_WINDOW_MS: 24 * 60 * 60 * 1000,
} as const);

/* ------------------------------------------------------------------------- *
 * Source roles
 * ------------------------------------------------------------------------- */

/**
 * The two authoritative sources a manifest must quote. Both are **required**: a
 * manifest that consulted only one did not establish the obligation picture, so
 * F9 is indeterminate.
 */
export const GOVERNANCE_SOURCE_ROLE = objectFreeze({
  DEFERRED_FINDINGS_REGISTER: 'deferred-findings-register',
  CURRENT_STATE_CHECKPOINT: 'current-state-checkpoint',
} as const);

export type GovernanceSourceRole =
  (typeof GOVERNANCE_SOURCE_ROLE)[keyof typeof GOVERNANCE_SOURCE_ROLE];

/** Every member of the {@link GovernanceSourceRole} union. */
export const GOVERNANCE_SOURCE_ROLES: readonly GovernanceSourceRole[] = objectFreeze([
  GOVERNANCE_SOURCE_ROLE.DEFERRED_FINDINGS_REGISTER,
  GOVERNANCE_SOURCE_ROLE.CURRENT_STATE_CHECKPOINT,
]);

/** Narrow an untrusted value to a source role, or `null`. */
export function readGovernanceSourceRole(value: unknown): GovernanceSourceRole | null {
  return typeof value === 'string' && containsValue(GOVERNANCE_SOURCE_ROLES, value)
    ? (value as GovernanceSourceRole)
    : null;
}

/* ------------------------------------------------------------------------- *
 * Hold reason vocabulary
 * ------------------------------------------------------------------------- */

/**
 * The closed vocabulary of reasons the PRE-RUN gate may record for a hold.
 *
 * This is the gate's vocabulary, not the classifier's: it explains *why the
 * register holds this candidate*, and it reaches the classifier only as F9's
 * `HOLD`. Free text is deliberately impossible here.
 */
export const MANIFEST_HOLD_REASON = objectFreeze({
  /** An open obligation in the register names this candidate. */
  REGISTER_OPEN_OBLIGATION: 'REGISTER_OPEN_OBLIGATION',
  /** The register preserves this candidate as historical evidence. */
  REGISTER_PRESERVE_FOR_HISTORY: 'REGISTER_PRESERVE_FOR_HISTORY',
  /** An active binding constraint covers this candidate. */
  REGISTER_BINDING_CONSTRAINT: 'REGISTER_BINDING_CONSTRAINT',
  /** The newest Current State checkpoint records this candidate as in-flight. */
  CHECKPOINT_LINE_ACTIVE: 'CHECKPOINT_LINE_ACTIVE',
  /** The checkpoint records an unresolved carry against this candidate. */
  CHECKPOINT_UNRESOLVED_CARRY: 'CHECKPOINT_UNRESOLVED_CARRY',
  /** A family breaker is in a state that forbids retirement of this candidate. */
  FAMILY_BREAKER_ACTIVE: 'FAMILY_BREAKER_ACTIVE',
} as const);

export type ManifestHoldReason =
  (typeof MANIFEST_HOLD_REASON)[keyof typeof MANIFEST_HOLD_REASON];

/** Every member of the {@link ManifestHoldReason} union. */
export const MANIFEST_HOLD_REASONS: readonly ManifestHoldReason[] = objectFreeze([
  MANIFEST_HOLD_REASON.REGISTER_OPEN_OBLIGATION,
  MANIFEST_HOLD_REASON.REGISTER_PRESERVE_FOR_HISTORY,
  MANIFEST_HOLD_REASON.REGISTER_BINDING_CONSTRAINT,
  MANIFEST_HOLD_REASON.CHECKPOINT_LINE_ACTIVE,
  MANIFEST_HOLD_REASON.CHECKPOINT_UNRESOLVED_CARRY,
  MANIFEST_HOLD_REASON.FAMILY_BREAKER_ACTIVE,
]);

/** Narrow an untrusted value to a hold reason, or `null`. */
export function readManifestHoldReason(value: unknown): ManifestHoldReason | null {
  return typeof value === 'string' && containsValue(MANIFEST_HOLD_REASONS, value)
    ? (value as ManifestHoldReason)
    : null;
}

/* ------------------------------------------------------------------------- *
 * Failure vocabulary
 * ------------------------------------------------------------------------- */

/**
 * The closed vocabulary of verification failures.
 *
 * Every member has the same consequence — F9 indeterminate, hence `BLOCKED` — so
 * no member is "softer" than another. They exist to make the Cockpit able to say
 * *which* check failed, never to grade them.
 */
export const MANIFEST_FAILURE = objectFreeze({
  /** The supplied text is absent, oversized, or not parseable JSON. */
  TEXT_UNPARSEABLE: 'TEXT_UNPARSEABLE',
  /** The parsed document does not satisfy the manifest schema. */
  SCHEMA_INVALID: 'SCHEMA_INVALID',
  /** The document is not canonicalizable under AB-CJSON-1, so it has no digest. */
  NOT_CANONICALIZABLE: 'NOT_CANONICALIZABLE',
  /** The expected digest is absent or malformed. */
  EXPECTED_DIGEST_INVALID: 'EXPECTED_DIGEST_INVALID',
  /** The computed digest does not equal the out-of-band expected digest. */
  DIGEST_MISMATCH: 'DIGEST_MISMATCH',
  /** The manifest's candidate ref is not the configured candidate ref. */
  CANDIDATE_REF_MISMATCH: 'CANDIDATE_REF_MISMATCH',
  /** The manifest's candidate SHA is not the configured candidate SHA. */
  CANDIDATE_SHA_MISMATCH: 'CANDIDATE_SHA_MISMATCH',
  /** The manifest's authoritative main SHA is not the configured one. */
  MAIN_SHA_MISMATCH: 'MAIN_SHA_MISMATCH',
  /** `generatedAt` is unparseable, in the future, or older than the window. */
  GENERATED_AT_OUT_OF_WINDOW: 'GENERATED_AT_OUT_OF_WINDOW',
  /** One of the two required source roles is missing. */
  REQUIRED_SOURCE_MISSING: 'REQUIRED_SOURCE_MISSING',
} as const);

export type ManifestFailure = (typeof MANIFEST_FAILURE)[keyof typeof MANIFEST_FAILURE];

/** Every member of the {@link ManifestFailure} union, in report order. */
export const MANIFEST_FAILURES: readonly ManifestFailure[] = objectFreeze([
  MANIFEST_FAILURE.TEXT_UNPARSEABLE,
  MANIFEST_FAILURE.SCHEMA_INVALID,
  MANIFEST_FAILURE.NOT_CANONICALIZABLE,
  MANIFEST_FAILURE.EXPECTED_DIGEST_INVALID,
  MANIFEST_FAILURE.DIGEST_MISMATCH,
  MANIFEST_FAILURE.CANDIDATE_REF_MISMATCH,
  MANIFEST_FAILURE.CANDIDATE_SHA_MISMATCH,
  MANIFEST_FAILURE.MAIN_SHA_MISMATCH,
  MANIFEST_FAILURE.GENERATED_AT_OUT_OF_WINDOW,
  MANIFEST_FAILURE.REQUIRED_SOURCE_MISSING,
]);

/* ------------------------------------------------------------------------- *
 * The manifest shape
 * ------------------------------------------------------------------------- */

/** One authoritative Drive source the PRE-RUN gate consulted. */
export interface GovernanceManifestSource {
  readonly role: GovernanceSourceRole;
  /** The Drive file id, recorded so the source is identifiable after the fact. */
  readonly driveFileId: string;
  readonly title: string;
  /** The Drive `modifiedTime` at the moment the gate read it. */
  readonly modifiedTime: string;
  /** `sha256:` + 64 hex of the exported plain text the gate actually read. */
  readonly sha256: string;
}

/** The git executable identity the observer must match at boot. */
export interface GovernanceManifestGit {
  /** Absolute path to the git executable. The observer never PATH-searches. */
  readonly path: string;
  /** `sha256:` + 64 hex of that file's bytes. */
  readonly sha256: string;
}

/**
 * The frozen governance run manifest.
 *
 * Every field is a string, a boolean, or a frozen list/record of those, so the
 * document canonicalizes under AB-CJSON-1 and has a stable digest.
 */
export interface GovernanceRunManifest {
  readonly candidateRef: string;
  readonly candidateSha: string;
  readonly authoritativeMainSha: string;
  /** ISO-8601 UTC instant at which the PRE-RUN gate produced this manifest. */
  readonly generatedAt: string;
  /** The identity of the PRE-RUN gate run that produced it. Audit only, inert. */
  readonly gateId: string;
  readonly sources: readonly GovernanceManifestSource[];
  readonly holdResult: GovernanceHold;
  readonly reasonCodes: readonly ManifestHoldReason[];
  /** Register/checkpoint text quoted **verbatim**. Display evidence, never parsed. */
  readonly matchingEntries: readonly string[];
  readonly git: GovernanceManifestGit;
}

/* ------------------------------------------------------------------------- *
 * The hostile reader
 * ------------------------------------------------------------------------- */

/** Read one source entry, or `null` when malformed. */
function readSource(element: unknown): GovernanceManifestSource | null {
  if (typeof element !== 'object' || element === null) {
    return null;
  }
  const role = readGovernanceSourceRole(readOwnProperty(element, 'role'));
  const driveFileId = readExactIdentifier(readOwnProperty(element, 'driveFileId'));
  const title = readExactIdentifier(readOwnProperty(element, 'title'));
  const modifiedTime = readExactIdentifier(readOwnProperty(element, 'modifiedTime'));
  const sha256 = readEvidenceId(readOwnProperty(element, 'sha256'));
  if (
    role === null ||
    driveFileId === null ||
    title === null ||
    modifiedTime === null ||
    sha256 === null
  ) {
    return null;
  }
  return freezeRecord({ role, driveFileId, title, modifiedTime, sha256 });
}

/**
 * Read a bounded list all-or-nothing. One malformed, missing, or inherited entry
 * rejects the whole list; an oversized list is rejected rather than truncated.
 */
function readBoundedList<T>(
  value: unknown,
  maxLength: number,
  read: (element: unknown) => T | null,
): readonly T[] | null {
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
    length > maxLength
  ) {
    return null;
  }
  const parsed: T[] = [];
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
    const value_ = read(element);
    if (value_ === null) {
      return null;
    }
    append(parsed, value_);
  }
  return freezeList(parsed);
}

/** Read one verbatim quoted entry: bounded text, echoed unmodified. */
function readQuotedEntry(element: unknown): string | null {
  return typeof element === 'string' &&
    element.length > 0 &&
    element.length <= MANIFEST_BOUNDS.MAX_ENTRY_LENGTH
    ? element
    : null;
}

/**
 * Read one untrusted manifest document, or `null`.
 *
 * Pure, total, deterministic; never throws. Own properties only, each read
 * exactly once into a local, all-or-nothing acceptance, frozen result built from
 * validated locals.
 */
export function readGovernanceRunManifest(value: unknown): GovernanceRunManifest | null {
  if (typeof value !== 'object' || value === null) {
    return null;
  }

  const candidateRef = readExactIdentifier(readOwnProperty(value, 'candidateRef'));
  const candidateSha = readExactIdentifier(readOwnProperty(value, 'candidateSha'));
  const authoritativeMainSha = readExactIdentifier(
    readOwnProperty(value, 'authoritativeMainSha'),
  );
  const generatedAt = readExactIdentifier(readOwnProperty(value, 'generatedAt'));
  const gateId = readExactIdentifier(readOwnProperty(value, 'gateId'));
  const sources = readBoundedList(
    readOwnProperty(value, 'sources'),
    MANIFEST_BOUNDS.MAX_SOURCES,
    readSource,
  );
  const holdResult = readGovernanceHold(readOwnProperty(value, 'holdResult'));
  const reasonCodes = readBoundedList(
    readOwnProperty(value, 'reasonCodes'),
    MANIFEST_BOUNDS.MAX_REASON_CODES,
    readManifestHoldReason,
  );
  const matchingEntries = readBoundedList(
    readOwnProperty(value, 'matchingEntries'),
    MANIFEST_BOUNDS.MAX_MATCHING_ENTRIES,
    readQuotedEntry,
  );

  const rawGit = readOwnProperty(value, 'git');
  let git: GovernanceManifestGit | null = null;
  if (typeof rawGit === 'object' && rawGit !== null) {
    const gitPath = readExactIdentifier(readOwnProperty(rawGit, 'path'));
    const gitSha = readEvidenceId(readOwnProperty(rawGit, 'sha256'));
    if (gitPath !== null && gitSha !== null) {
      git = freezeRecord({ path: gitPath, sha256: gitSha });
    }
  }

  if (
    candidateRef === null ||
    candidateSha === null ||
    authoritativeMainSha === null ||
    generatedAt === null ||
    gateId === null ||
    sources === null ||
    holdResult === null ||
    reasonCodes === null ||
    matchingEntries === null ||
    git === null
  ) {
    return null;
  }

  // A HOLD with no reason is unexplained, and a NO_HOLD carrying hold reasons is
  // self-contradictory. Both are rejected rather than reconciled: the gate must
  // say one coherent thing, and reconciling here would invent the missing half.
  if (holdResult === GOVERNANCE_HOLD.HOLD && reasonCodes.length === 0) {
    return null;
  }
  if (holdResult === GOVERNANCE_HOLD.NO_HOLD && reasonCodes.length > 0) {
    return null;
  }

  return freezeRecord({
    candidateRef,
    candidateSha,
    authoritativeMainSha,
    generatedAt,
    gateId,
    sources,
    holdResult,
    reasonCodes,
    matchingEntries,
    git,
  });
}

/* ------------------------------------------------------------------------- *
 * Verification
 * ------------------------------------------------------------------------- */

/** Everything verification needs. No environment, clock, or file is read here. */
export interface ManifestVerificationInput {
  /** The manifest document as supplied to the runtime. */
  readonly manifestText: string;
  /** `AGENTBRIDGE_JOB1_MANIFEST_SHA256`, supplied out of band from the text. */
  readonly expectedDigest: string;
  /**
   * The configured immutable candidate ref.
   *
   * Candidate identity is the **pair** (ref, SHA) — Decision 065 INVARIANT 2 —
   * so the manifest must be bound to both. Binding the SHA alone would let a
   * manifest prepared for one ref satisfy F9 for a *different* ref that happens
   * to point at the same commit, consuming governance research that was never
   * done for the candidate actually being assessed. Two refs at one commit is
   * an ordinary state, not an exotic one.
   */
  readonly candidateRef: string;
  /** The configured immutable candidate SHA. */
  readonly candidateSha: string;
  /** The configured authoritative main SHA. */
  readonly authoritativeMainSha: string;
  /** Boot instant in epoch milliseconds. Supplied; no clock is read here. */
  readonly bootEpochMs: number;
}

/**
 * The verification outcome.
 *
 * `holdResult` is `null` when **anything** failed — that `null` is F9's
 * indeterminacy, and it is the only channel by which a verification failure
 * reaches the classifier. The classifier never sees a failure code.
 */
export interface ManifestVerification {
  /** The verified manifest, or `null` when any check failed. */
  readonly manifest: GovernanceRunManifest | null;
  /** The digest computed over the manifest's canonical bytes, or `null`. */
  readonly digest: string | null;
  /** Failures in {@link MANIFEST_FAILURES} order. Empty exactly when verified. */
  readonly failures: readonly ManifestFailure[];
  /** The verified hold result, or `null` for indeterminate. */
  readonly holdResult: GovernanceHold | null;
}

/**
 * Strict ISO-8601 UTC instant: `YYYY-MM-DDTHH:MM:SS(.mmm)?Z`.
 *
 * Deliberately strict. `Date.parse` accepts a wide, implementation-varying set of
 * spellings — local-time strings without a zone, two-digit years, `Date`'s legacy
 * fallback parser — and a freshness window computed from a leniently parsed
 * timestamp is not a window at all. Anything that does not match this exact shape
 * is out of window.
 */
const ISO_UTC_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{3}))?Z$/;

/**
 * Parse a strict ISO-8601 UTC instant to epoch milliseconds, or `null`.
 *
 * Round-tripping through `Date.UTC` and re-checking each component rejects
 * out-of-range values that would otherwise silently roll over (`2026-02-31`
 * becoming March 3, `25:00` becoming the next day).
 */
function parseIsoUtc(value: string): number | null {
  const match = ISO_UTC_INSTANT.exec(value);
  if (match === null) {
    return null;
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const millis = match[7] === undefined ? 0 : Number(match[7]);
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) {
    return null;
  }
  const epochMs = Date.UTC(year, month - 1, day, hour, minute, second, millis);
  if (!numberIsInteger(epochMs)) {
    return null;
  }
  // Reject rollover: the components must survive the round trip unchanged.
  const roundTrip = new Date(epochMs);
  if (
    roundTrip.getUTCFullYear() !== year ||
    roundTrip.getUTCMonth() !== month - 1 ||
    roundTrip.getUTCDate() !== day ||
    roundTrip.getUTCHours() !== hour ||
    roundTrip.getUTCMinutes() !== minute ||
    roundTrip.getUTCSeconds() !== second
  ) {
    return null;
  }
  return epochMs;
}

/** Build the frozen verification result, with `holdResult` null unless clean. */
function verification(
  manifest: GovernanceRunManifest | null,
  digest: string | null,
  failures: ManifestFailure[],
): ManifestVerification {
  const clean = failures.length === 0 && manifest !== null;
  return freezeRecord({
    manifest: clean ? manifest : null,
    digest,
    failures: freezeList(failures),
    holdResult: clean ? manifest.holdResult : null,
  });
}

/**
 * Verify one governance run manifest against its out-of-band digest and the
 * configured run identity.
 *
 * Pure, total, deterministic; never throws. Every check runs and every failure is
 * collected, so the Cockpit can say everything that was wrong rather than only
 * the first thing — but **any** failure yields `holdResult: null` (F9
 * indeterminate → `BLOCKED`).
 *
 * The checks, exactly (Decision 065, "Freshness"):
 *
 * 1. the text parses and satisfies the schema;
 * 2. the document canonicalizes under AB-CJSON-1 and its digest equals the
 *    out-of-band expected digest;
 * 3. `candidateRef` and `candidateSha` equal the configured candidate identity;
 * 4. `authoritativeMainSha` equals the configured main SHA;
 * 5. `generatedAt` is within the 24-hour window before boot, and not in the
 *    future;
 * 6. both required source roles are present.
 */
export function verifyGovernanceRunManifest(
  input: ManifestVerificationInput,
): ManifestVerification {
  const failures: ManifestFailure[] = [];

  const text = input.manifestText;
  if (typeof text !== 'string' || text.length === 0 || text.length > MANIFEST_BOUNDS.MAX_MANIFEST_TEXT_LENGTH) {
    append(failures, MANIFEST_FAILURE.TEXT_UNPARSEABLE);
    return verification(null, null, failures);
  }

  let parsed: unknown;
  try {
    parsed = jsonParse(text) as unknown;
  } catch {
    append(failures, MANIFEST_FAILURE.TEXT_UNPARSEABLE);
    return verification(null, null, failures);
  }

  const manifest = readGovernanceRunManifest(parsed);
  if (manifest === null) {
    append(failures, MANIFEST_FAILURE.SCHEMA_INVALID);
    return verification(null, null, failures);
  }

  // The digest is computed over the **re-canonicalized accepted manifest**, not
  // over the supplied bytes. Digesting the raw text would bind the pointer to
  // incidental whitespace and key order, so two byte-different spellings of one
  // document would have two digests; digesting the accepted value binds it to the
  // document's content, which is what the PRE-RUN gate signed.
  const digest = sha256Canonical(manifest);
  if (digest === null) {
    append(failures, MANIFEST_FAILURE.NOT_CANONICALIZABLE);
    return verification(manifest, null, failures);
  }

  const expected = readEvidenceId(input.expectedDigest);
  if (expected === null) {
    append(failures, MANIFEST_FAILURE.EXPECTED_DIGEST_INVALID);
  } else if (expected !== digest) {
    append(failures, MANIFEST_FAILURE.DIGEST_MISMATCH);
  }

  // Candidate identity is bound as (ref, SHA). Both halves are compared against
  // the configured values; a manifest prepared under the PRE-RUN gate for some
  // other ref is not this run's manifest, whatever commit it names
  // (Decision 065 INVARIANT 2 and INVARIANT 13).
  if (manifest.candidateRef !== input.candidateRef) {
    append(failures, MANIFEST_FAILURE.CANDIDATE_REF_MISMATCH);
  }
  if (manifest.candidateSha !== input.candidateSha) {
    append(failures, MANIFEST_FAILURE.CANDIDATE_SHA_MISMATCH);
  }
  if (manifest.authoritativeMainSha !== input.authoritativeMainSha) {
    append(failures, MANIFEST_FAILURE.MAIN_SHA_MISMATCH);
  }

  const generatedEpochMs = parseIsoUtc(manifest.generatedAt);
  const bootEpochMs = input.bootEpochMs;
  const windowValid =
    generatedEpochMs !== null &&
    numberIsInteger(bootEpochMs) &&
    generatedEpochMs <= bootEpochMs &&
    bootEpochMs - generatedEpochMs <= MANIFEST_BOUNDS.FRESHNESS_WINDOW_MS;
  if (!windowValid) {
    append(failures, MANIFEST_FAILURE.GENERATED_AT_OUT_OF_WINDOW);
  }

  let hasRegister = false;
  let hasCheckpoint = false;
  for (let index = 0; index < manifest.sources.length; index += 1) {
    const source = manifest.sources[index];
    if (source === undefined) {
      continue;
    }
    // The role vocabulary is closed and has exactly two members, so the `else`
    // is total. A future third role would fail to compile here rather than be
    // silently counted as a checkpoint.
    if (source.role === GOVERNANCE_SOURCE_ROLE.DEFERRED_FINDINGS_REGISTER) {
      hasRegister = true;
    } else {
      hasCheckpoint = true;
    }
  }
  if (!hasRegister || !hasCheckpoint) {
    append(failures, MANIFEST_FAILURE.REQUIRED_SOURCE_MISSING);
  }

  return verification(manifest, digest, failures);
}

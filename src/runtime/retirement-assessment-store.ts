/**
 * In-process retirement-assessment store — Decision 065 Revision 2 integrity
 * steps I2 and I3 (Autoflow Job #1, WF3 clean rebuild slice 2;
 * DDR-SLICE2-TIER3 Revision 1).
 *
 * The evidence **pointer** is the authority; a body is served only while it is
 * digest-bound to that pointer (Invariants 6 and 14). This store keeps that
 * binding honest by **owning** what it holds:
 *
 *     put(input)  -> read (hostile) -> canonicalize -> digest -> bind -> hold
 *     get(id)     -> I3 on the held entry, every call -> the held copy or null
 *     list()      -> I3 on the held entry, every call -> [held copy] or []
 *
 * ## Ownership
 *
 * `put` accepts `unknown` and admits it only through
 * {@link readRetirementAssessment}, which returns a deep-frozen,
 * prototype-free copy built from validated values — accessors are rejected
 * without being run, and a Proxy contributes only the values its traps returned
 * once. That copy, and the AB-CJSON-1 text canonicalized **from that copy**, are
 * the only things held. No caller object is ever retained or returned, so a
 * caller cannot reach held state before, during, or after admission.
 *
 * ## Idempotency is byte equality
 *
 * A retry is `ALREADY_STORED` only when its canonical bytes equal the held bytes
 * **and** the held entry has just passed I3. Evidence-id equality alone decides
 * nothing (PRRT_kwDOTzqfcs6kL8MT). Any other second assessment is refused and
 * never clobbers the first (Invariant 1).
 *
 * ## Integrity failure latches, I3 never stops
 *
 * Every `get` and every `list` re-canonicalizes and re-digests the held entry
 * (Decision 065: "every get(id) re-digests"; "re-digests on every read"), before
 * and after a failure. The first mismatch latches the store FAULTED and records
 * the one integrity fault. FAULTED fixes outcomes — `get` null, `list` empty,
 * `put` refused — permanently; a later matching digest never resurrects the
 * store, and held bytes are never replaced or deleted. An integrity failure is
 * never a classification.
 *
 * ## Scope
 *
 * In-process and in-memory only: no persistence, filesystem, network, process,
 * clock, or environment access (Decision 065, Exclusions). SHA-256 is computed
 * here, in the runtime layer (integrity step 3). The only canonicalization input
 * is the reader's fixed-schema frozen copy, so total canonical output is bounded
 * by construction.
 */

import { createHash } from 'node:crypto';

import {
  canonicalizeAssessmentBody,
  EVIDENCE_ID_PREFIX,
  readEvidenceId,
  readRetirementAssessment,
  type RetirementAssessmentEnvelope,
} from '../domain/retirement-assessment.js';

const objectFreeze = Object.freeze;
const objectSetPrototypeOf = Object.setPrototypeOf;

/** Detach a record from the live `Object.prototype`, then freeze it. */
function freezeRecord<T extends object>(record: T): Readonly<T> {
  objectSetPrototypeOf(record, null);
  return objectFreeze(record);
}

/** The outcome of one {@link RetirementAssessmentStore.put}. No member is a classification. */
export const PUT_OUTCOME = freezeRecord({
  /** The envelope is now held, digest-bound. */
  STORED: 'STORED',
  /** The identical bytes are already held and just re-proved. */
  ALREADY_STORED: 'ALREADY_STORED',
  /** Nothing changed; see the refusal. */
  REFUSED: 'REFUSED',
} as const);

export type PutOutcome = (typeof PUT_OUTCOME)[keyof typeof PUT_OUTCOME];

/** Why a put was refused. A closed vocabulary; no member is a classification. */
export const STORE_REFUSAL = freezeRecord({
  /** The hostile reader rejected the input. */
  MALFORMED_ENVELOPE: 'MALFORMED_ENVELOPE',
  /** The admitted body has no AB-CJSON-1 form. Fail-closed; unreachable for reader output. */
  NOT_CANONICALIZABLE: 'NOT_CANONICALIZABLE',
  /** The body does not digest to the envelope's own `evidenceId`. */
  UNBOUND_ENVELOPE: 'UNBOUND_ENVELOPE',
  /** A different assessment is already held; one runtime assesses one candidate. */
  SECOND_ASSESSMENT_REFUSED: 'SECOND_ASSESSMENT_REFUSED',
  /** The store has recorded an integrity fault and is permanently fail-closed. */
  INTEGRITY_FAULT: 'INTEGRITY_FAULT',
} as const);

export type StoreRefusal = (typeof STORE_REFUSAL)[keyof typeof STORE_REFUSAL];

/** One put result: `refusal` is non-null exactly when `outcome` is `REFUSED`. */
export interface StorePutResult {
  readonly outcome: PutOutcome;
  readonly refusal: StoreRefusal | null;
}

/**
 * The append-only assessment store: exactly these four verbs. There is no
 * delete, replace, reset, or clear, and the held cell and fault state never
 * escape.
 */
export interface RetirementAssessmentStore {
  /** I2 — admit one untrusted envelope, keyed by its `evidenceId`. Never throws. */
  put(input: unknown): StorePutResult;
  /** I3 — re-digest the held entry, then return it only if bound and `evidenceId` names it. */
  get(evidenceId: unknown): RetirementAssessmentEnvelope | null;
  /** I3 — re-digest the held entry, then return it (frozen, at most one) only if bound. */
  list(): readonly RetirementAssessmentEnvelope[];
  /** 0 until the first integrity mismatch, then 1 for the life of the store. */
  integrityFaultCount(): number;
}

function refused(refusal: StoreRefusal): StorePutResult {
  return freezeRecord({ outcome: PUT_OUTCOME.REFUSED, refusal });
}

const STORED_RESULT: StorePutResult = freezeRecord({ outcome: PUT_OUTCOME.STORED, refusal: null });
const ALREADY_STORED_RESULT: StorePutResult = freezeRecord({
  outcome: PUT_OUTCOME.ALREADY_STORED,
  refusal: null,
});
const MALFORMED_RESULT = refused(STORE_REFUSAL.MALFORMED_ENVELOPE);
const NOT_CANONICALIZABLE_RESULT = refused(STORE_REFUSAL.NOT_CANONICALIZABLE);
const UNBOUND_RESULT = refused(STORE_REFUSAL.UNBOUND_ENVELOPE);
const SECOND_ASSESSMENT_RESULT = refused(STORE_REFUSAL.SECOND_ASSESSMENT_REFUSED);
const INTEGRITY_FAULT_RESULT = refused(STORE_REFUSAL.INTEGRITY_FAULT);

const EMPTY_LIST: readonly RetirementAssessmentEnvelope[] = objectFreeze([]);

/**
 * `sha256:` + hex SHA-256 over the UTF-8 encoding of AB-CJSON-1 text, or `null`
 * when the digest cannot be computed. The encoding is explicit so no default
 * can repoint the digest; AB-CJSON-1 escapes lone surrogates, so the UTF-8
 * encoding is lossless.
 */
function digestCanonical(canonical: string): string | null {
  try {
    return EVIDENCE_ID_PREFIX + createHash('sha256').update(canonical, 'utf8').digest('hex');
  } catch {
    return null;
  }
}

/** The one held entry: the reader's frozen copy and the canonical bytes of that copy. */
interface HeldEntry {
  readonly envelope: RetirementAssessmentEnvelope;
  readonly bytes: string;
}

/** Create the one in-process store. Takes nothing: there is no injectable digest. */
export function createRetirementAssessmentStore(): RetirementAssessmentStore {
  let held: HeldEntry | null = null;
  let integrityFaults = 0;

  /**
   * I3 over the held entry, run on every read whether or not the store is
   * FAULTED: re-canonicalize the held copy, require the held bytes, re-digest
   * them, require the held id. A mismatch or exception records the one fault;
   * a match never clears it. Returns whether the entry may be served.
   */
  const verifyHeld = (entry: HeldEntry): boolean => {
    let intact = false;
    try {
      const canonical = canonicalizeAssessmentBody(entry.envelope.body);
      intact =
        canonical !== null &&
        canonical === entry.bytes &&
        digestCanonical(canonical) === entry.envelope.evidenceId;
    } catch {
      intact = false;
    }
    if (!intact) {
      integrityFaults = 1;
    }
    return intact && integrityFaults === 0;
  };

  const put = (input: unknown): StorePutResult => {
    // FAULTED is permanent. I2 requires no re-digest here, so nothing is read.
    if (integrityFaults !== 0) {
      return INTEGRITY_FAULT_RESULT;
    }
    const envelope = readRetirementAssessment(input);
    if (envelope === null) {
      return MALFORMED_RESULT;
    }
    const canonical = canonicalizeAssessmentBody(envelope.body);
    if (canonical === null) {
      return NOT_CANONICALIZABLE_RESULT;
    }
    if (digestCanonical(canonical) !== envelope.evidenceId) {
      return UNBOUND_RESULT;
    }
    // Read after admission: the reader may have run a Proxy trap.
    const current = held;
    if (current === null) {
      held = freezeRecord({ envelope, bytes: canonical });
      return STORED_RESULT;
    }
    // A clean incoming envelope never masks a held entry that no longer proves.
    if (!verifyHeld(current)) {
      return INTEGRITY_FAULT_RESULT;
    }
    return canonical === current.bytes && envelope.evidenceId === current.envelope.evidenceId
      ? ALREADY_STORED_RESULT
      : SECOND_ASSESSMENT_RESULT;
  };

  const get = (evidenceId: unknown): RetirementAssessmentEnvelope | null => {
    const current = held;
    if (current === null) {
      return null;
    }
    const servable = verifyHeld(current);
    if (!servable || readEvidenceId(evidenceId) === null || evidenceId !== current.envelope.evidenceId) {
      return null;
    }
    return current.envelope;
  };

  const list = (): readonly RetirementAssessmentEnvelope[] => {
    const current = held;
    if (current === null) {
      return EMPTY_LIST;
    }
    return verifyHeld(current) ? objectFreeze([current.envelope]) : EMPTY_LIST;
  };

  return freezeRecord({
    put,
    get,
    list,
    integrityFaultCount: (): number => integrityFaults,
  });
}

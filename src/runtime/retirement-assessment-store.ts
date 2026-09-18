/**
 * In-process retirement-assessment store, and the one runtime digest primitive
 * (Autoflow Job #1, Decision 065 Revision 2 — integrity steps I2 and I3).
 *
 * The evidence **pointer** is the authority; the **body** is shown only while it
 * is digest-bound to that pointer (Decision 065 §6). This store is where that
 * binding is kept honest:
 *
 *     put(envelope)   ->  I2: re-canonicalize, re-digest, accept only if bound
 *     get(evidenceId) ->  I3: re-canonicalize, re-digest, return only if bound
 *
 * The binding is re-proved on **every** read. It is never cached, never trusted
 * from the previous check, and never inferred from the envelope's own shape: a
 * body mutated in memory after admission stops being returned the very next time
 * it is asked for, and the store records one integrity fault instead.
 *
 * ## Integrity failure is not a classification
 *
 * A mismatch returns **nothing** (Decision 065, integrity-failure semantics). It
 * is never downgraded to `BLOCKED`, never upgraded to any classification, and
 * never reinterpreted at all — those are the classifier's vocabulary, and the
 * classifier never saw a digest. The Cockpit renders the honest
 * "No verified assessment (integrity failure recorded)" copy instead.
 *
 * ## Single assessment per runtime
 *
 * One workflow instance assesses exactly one candidate (Decision 065 §1). The
 * store enforces that as a hard guard: a second **distinct** envelope is refused,
 * never clobbered. Re-putting the identical envelope is idempotent, so a retry
 * that re-derives the same bytes is not an error.
 *
 * ## Scope
 *
 * In-process and in-memory only. No persistence, no replay across restart, no
 * external Evidence Store, no filesystem, no network, no clock, and no
 * environment read (Decision 065, Exclusions). SHA-256 comes from `node:crypto`;
 * it is computed **here, in the runtime layer**, never in the domain, D1, or D4.
 */

import { createHash } from 'node:crypto';

import {
  canonicalizeAssessmentBody,
  EVIDENCE_ID_PREFIX,
  readEvidenceId,
  type RetirementAssessmentEnvelope,
} from '../domain/retirement-assessment.js';

const objectFreeze = Object.freeze;
const objectSetPrototypeOf = Object.setPrototypeOf;
const objectDefineProperty = Object.defineProperty;

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

/**
 * The **single** runtime digest primitive: SHA-256 over one value's AB-CJSON-1
 * canonical bytes, formatted as `sha256:` + 64 lowercase hex.
 *
 * Returns `null` when the value is not canonicalizable — a value with no
 * canonical form has no digest, and inventing one over an approximation would
 * bind a pointer to bytes nobody agreed on. Callers fail closed on `null`.
 *
 * This is deliberately the only place SHA-256 is computed for Job #1. The domain
 * may not compute it (Decision 065, integrity step 3), and D1/D4 may not either,
 * so a single exported function keeps the algorithm, the encoding, and the
 * canonical form from drifting between the self-check, the store, and the
 * manifest verifier.
 */
export function sha256Canonical(value: unknown): string | null {
  const canonical = canonicalizeAssessmentBody(value);
  if (canonical === null) {
    return null;
  }
  // `update(text, 'utf8')` fixes the encoding explicitly: AB-CJSON-1 is defined
  // as UTF-8 JSON text, and relying on a default would let a platform or runtime
  // change silently repoint the digest.
  return EVIDENCE_ID_PREFIX + createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Why a store operation was refused. A closed vocabulary: the store never
 * explains itself in prose, and no member of this vocabulary is a classification.
 */
export const STORE_REFUSAL = objectFreeze({
  /** The envelope's body does not digest to the envelope's own `evidenceId`. */
  UNBOUND_ENVELOPE: 'UNBOUND_ENVELOPE',
  /** The body is not canonicalizable, so it has no digest at all. */
  NOT_CANONICALIZABLE: 'NOT_CANONICALIZABLE',
  /** A different assessment is already held; one runtime assesses one candidate. */
  SECOND_ASSESSMENT_REFUSED: 'SECOND_ASSESSMENT_REFUSED',
} as const);

export type StoreRefusal = (typeof STORE_REFUSAL)[keyof typeof STORE_REFUSAL];

/** The outcome of one {@link RetirementAssessmentStore.put}. */
export interface StorePutResult {
  /** `true` exactly when the envelope is now held and digest-bound. */
  readonly stored: boolean;
  /** Non-null exactly when `stored` is `false`. */
  readonly refusal: StoreRefusal | null;
}

/**
 * The append-only assessment store.
 *
 * `list()` is what the composition root hands to the producer: the already
 * verified envelopes, re-proved at the moment of the call. The producer receives
 * **data**, never this store, never a handle, and never a callback (Amendment 1
 * B-4) — it could not re-read or re-verify anything if it wanted to.
 */
export interface RetirementAssessmentStore {
  /** I2 — admit one envelope, keyed by its `evidenceId`. Idempotent on identical bytes. */
  put(envelope: RetirementAssessmentEnvelope): StorePutResult;
  /** I3 — return the envelope only if it still digests to its id; otherwise nothing. */
  get(evidenceId: string): RetirementAssessmentEnvelope | null;
  /** Every currently verified envelope, re-proved on this call. Frozen, detached. */
  list(): readonly RetirementAssessmentEnvelope[];
  /** How many reads have failed the binding check. Monotonic, never reset. */
  integrityFaultCount(): number;
}

/**
 * Create the one in-process store.
 *
 * The returned object is frozen and exposes only the four verbs above; the
 * internal cell never escapes, so no consumer can replace a held envelope or
 * suppress a fault count.
 */
export function createRetirementAssessmentStore(): RetirementAssessmentStore {
  /**
   * The single held entry. `null` until the first successful put; never replaced
   * by a distinct envelope afterwards. One runtime assesses one candidate, so a
   * map would model a capability this milestone does not have.
   */
  let held: RetirementAssessmentEnvelope | null = null;
  let integrityFaults = 0;

  /**
   * Re-prove the digest binding of one envelope, right now.
   *
   * This is the whole integrity contract in one place: canonicalize the body,
   * digest it, and compare against the pointer the envelope claims. Nothing is
   * cached between calls — that is the point of I3.
   */
  const isBound = (envelope: RetirementAssessmentEnvelope): boolean => {
    const digest = sha256Canonical(envelope.body);
    return digest !== null && digest === envelope.evidenceId;
  };

  const put = (envelope: RetirementAssessmentEnvelope): StorePutResult => {
    const digest = sha256Canonical(envelope.body);
    if (digest === null) {
      return freezeRecord({ stored: false, refusal: STORE_REFUSAL.NOT_CANONICALIZABLE });
    }
    if (digest !== envelope.evidenceId) {
      return freezeRecord({ stored: false, refusal: STORE_REFUSAL.UNBOUND_ENVELOPE });
    }
    if (held !== null) {
      // Idempotent on identical content: the same id over a body that still
      // digests to it is the same assessment, so a retry is not a second one.
      // Any other envelope is a second assessment and is refused, never
      // clobbering the one already held.
      const sameId = held.evidenceId === envelope.evidenceId;
      return sameId
        ? freezeRecord({ stored: true, refusal: null })
        : freezeRecord({ stored: false, refusal: STORE_REFUSAL.SECOND_ASSESSMENT_REFUSED });
    }
    held = envelope;
    return freezeRecord({ stored: true, refusal: null });
  };

  const get = (evidenceId: string): RetirementAssessmentEnvelope | null => {
    const current = held;
    if (current === null) {
      return null;
    }
    // The requested id is validated for shape before it is compared, so a
    // malformed lookup key can never match by coincidence of type coercion.
    if (readEvidenceId(evidenceId) === null || current.evidenceId !== evidenceId) {
      return null;
    }
    if (!isBound(current)) {
      // I3: the binding failed. Return nothing and record exactly one fault. The
      // held entry is deliberately NOT deleted — the pointer remains a true
      // historical fact, and deleting it would erase the evidence that something
      // went wrong. It simply stops being projectable.
      integrityFaults += 1;
      return null;
    }
    return current;
  };

  const list = (): readonly RetirementAssessmentEnvelope[] => {
    const current = held;
    const verified: RetirementAssessmentEnvelope[] = [];
    if (current !== null) {
      if (isBound(current)) {
        objectDefineProperty(verified, 0, {
          value: current,
          writable: true,
          enumerable: true,
          configurable: true,
        });
      } else {
        integrityFaults += 1;
      }
    }
    return freezeList(verified);
  };

  return objectFreeze<RetirementAssessmentStore>({
    put,
    get,
    list,
    integrityFaultCount: (): number => integrityFaults,
  });
}

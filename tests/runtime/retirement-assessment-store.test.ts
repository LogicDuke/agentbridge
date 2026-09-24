import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  canonicalizeAssessmentBody,
  classifyRetirementCandidate,
  determinate,
  GOVERNANCE_HOLD,
  INDETERMINATE,
  MAX_COUNT,
  RETIREMENT_CLASSIFICATIONS,
  RETIREMENT_FACT_ORDER,
  RETIREMENT_REASONS,
  toFactRecords,
  type RetirementAssessmentEnvelope,
  type RetirementFacts,
} from '../../src/domain/retirement-assessment.js';
import {
  createRetirementAssessmentStore,
  PUT_OUTCOME,
  STORE_REFUSAL,
  type RetirementAssessmentStore,
  type StorePutResult,
} from '../../src/runtime/retirement-assessment-store.js';

/* ------------------------------------------------------------------------- *
 * node:crypto seam — test file only (DDR-SLICE2-TIER3 Rev 1, R-2)
 *
 * `createHash` passes through to the real implementation and only counts calls
 * until a test installs `hex`, which then answers every digest the store asks
 * for. The production store has no seam of its own.
 * ------------------------------------------------------------------------- */

const cryptoSeam = vi.hoisted(() => ({
  calls: 0,
  texts: [] as string[],
  hex: null as ((text: string) => string) | null,
}));

vi.mock('node:crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:crypto')>();
  return {
    ...actual,
    createHash: (...params: Parameters<typeof actual.createHash>): unknown => {
      cryptoSeam.calls += 1;
      const override = cryptoSeam.hex;
      if (override === null) {
        return actual.createHash(...params);
      }
      let text = '';
      interface FakeHash {
        update(value: string): FakeHash;
        digest(): string;
      }
      const fake: FakeHash = {
        update(value: string): FakeHash {
          text = value;
          cryptoSeam.texts.push(value);
          return fake;
        },
        digest(): string {
          return override(text);
        },
      };
      return fake;
    },
  };
});

const { createHash: realCreateHash } = await vi.importActual<typeof import('node:crypto')>('node:crypto');

afterEach(() => {
  cryptoSeam.calls = 0;
  cryptoSeam.texts = [];
  cryptoSeam.hex = null;
});

/* ------------------------------------------------------------------------- *
 * Fixtures — independent of the module under test
 * ------------------------------------------------------------------------- */

type Plain = Record<string, unknown>;

const CANDIDATE_SHA = 'a'.repeat(40);
const MAIN_SHA = 'b'.repeat(40);
const CANDIDATE_REF = 'refs/heads/repair/example-candidate';
const MANIFEST_DIGEST = 'sha256:' + 'f'.repeat(64);
const OBSERVER = 'agentbridge-job1-observer/2';
const WRONG_HEX = '0'.repeat(64);

function eligibleFacts(): RetirementFacts {
  return {
    f1CandidateIdentity: determinate(true),
    f2RemoteAgreement: determinate(true),
    f3StableMain: determinate(true),
    f4Containment: determinate(true),
    f5UniqueCommits: determinate(0),
    f6UniquePatches: determinate(0),
    f7WorktreeClean: determinate(true),
    f8DependencyClearance: determinate(true),
    f9GovernanceManifest: determinate(GOVERNANCE_HOLD.NO_HOLD),
    f10NotProtected: determinate(true),
  };
}

/** Every fact indeterminate: BLOCKED with a non-empty reason list. */
function indeterminateFacts(): RetirementFacts {
  const facts: Record<string, unknown> = {};
  for (const key of RETIREMENT_FACT_ORDER) {
    facts[key] = INDETERMINATE;
  }
  return facts as unknown as RetirementFacts;
}

/** Every blocking fact false, both counts maximal, HOLD: the longest reason list. */
function mostReasonsFacts(): RetirementFacts {
  return {
    f1CandidateIdentity: determinate(false),
    f2RemoteAgreement: determinate(false),
    f3StableMain: determinate(false),
    f4Containment: determinate(false),
    f5UniqueCommits: determinate(MAX_COUNT),
    f6UniquePatches: determinate(MAX_COUNT),
    f7WorktreeClean: determinate(false),
    f8DependencyClearance: determinate(false),
    f9GovernanceManifest: determinate(GOVERNANCE_HOLD.HOLD),
    f10NotProtected: determinate(false),
  };
}

/** A fresh, fully mutable, plain-JSON body — what an untrusted caller hands in. */
function plainBody(facts: RetirementFacts = eligibleFacts(), overrides: Plain = {}): Plain {
  const verdict = classifyRetirementCandidate(facts);
  const body = {
    repositoryId: 'LogicDuke/agentbridge',
    candidateRef: CANDIDATE_REF,
    candidateSha: CANDIDATE_SHA,
    authoritativeMainSha: MAIN_SHA,
    facts: toFactRecords(facts),
    classification: verdict.classification,
    reasonCodes: verdict.reasonCodes,
    gateRequested: verdict.gateRequested,
    manifestDigest: MANIFEST_DIGEST,
    generatedAt: '2026-09-21T00:00:00Z',
    observerVersion: OBSERVER,
  };
  return { ...(JSON.parse(JSON.stringify(body)) as Plain), ...overrides };
}

function must<T>(value: T | null | undefined): T {
  if (value === null || value === undefined) {
    throw new Error('fixture expected a value');
  }
  return value;
}

function canonicalOf(value: unknown): string {
  return must(canonicalizeAssessmentBody(value));
}

function realHex(text: string): string {
  return realCreateHash('sha256').update(text, 'utf8').digest('hex');
}

/** The independent evidence id: SHA-256 over the UTF-8 AB-CJSON-1 text. */
function idOf(body: unknown): string {
  return 'sha256:' + realHex(canonicalOf(body));
}

function envelopeOf(body: Plain): Plain {
  return { evidenceId: idOf(body), body };
}

function child(target: unknown, key: string): Plain {
  const value: unknown = Reflect.get(target as object, key);
  if (typeof value !== 'object' || value === null) {
    throw new Error(`fixture expected an object at ${key}`);
  }
  return value as Plain;
}

function list(target: unknown, key: string): unknown[] {
  const value: unknown = Reflect.get(target as object, key);
  if (!Array.isArray(value)) {
    throw new Error(`fixture expected an array at ${key}`);
  }
  return value;
}

/** Replace an own data property with an enumerable getter returning the same value. */
function installGetter(target: object, key: string | number): () => number {
  const value: unknown = Reflect.get(target, key);
  let calls = 0;
  Reflect.deleteProperty(target, key);
  Object.defineProperty(target, key, {
    enumerable: true,
    configurable: true,
    get(): unknown {
      calls += 1;
      return value;
    },
  });
  return () => calls;
}

/** A store holding one eligible assessment, plus that assessment's id and bytes. */
function heldStore(): { store: RetirementAssessmentStore; id: string; bytes: string; env: Plain } {
  const store = createRetirementAssessmentStore();
  const body = plainBody();
  const env = { evidenceId: idOf(body), body };
  expect(store.put(env).outcome).toBe(PUT_OUTCOME.STORED);
  return { store, id: env.evidenceId, bytes: canonicalOf(body), env };
}

/** Digest the first `passing` calls correctly, then answer a wrong digest. */
function failAfter(passing: number): void {
  let calls = 0;
  cryptoSeam.hex = (text) => {
    calls += 1;
    return calls <= passing ? realHex(text) : WRONG_HEX;
  };
}

/** Visit every value reachable through own properties (the envelope is a small tree). */
function walk(value: unknown, visit: (node: object) => void): void {
  if (typeof value !== 'object' || value === null) {
    return;
  }
  visit(value);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor !== undefined && 'value' in descriptor) {
      walk(descriptor.value, visit);
    }
  }
}

/* ------------------------------------------------------------------------- *
 * T1-T5 — ownership, the kL8MT witness, and idempotent retry
 * ------------------------------------------------------------------------- */

describe('retirement assessment store — ownership and retry (Rev 1 T1-T5)', () => {
  it('T1 kL8MT: caller mutation after admission cannot corrupt held state or be masked by a retry', () => {
    const store = createRetirementAssessmentStore();
    const body = plainBody();
    const env = { evidenceId: idOf(body), body };
    const cleanBytes = canonicalOf(body);
    expect(store.put(env)).toEqual({ outcome: PUT_OUTCOME.STORED, refusal: null });

    // Mutate the caller's own object in every region after admission.
    body.observerVersion = 'tampered';
    child(child(body, 'facts'), 'f1CandidateIdentity').value = false;

    const got = must(store.get(env.evidenceId));
    expect(canonicalOf(got.body)).toBe(cleanBytes);
    expect(store.integrityFaultCount()).toBe(0);

    // A byte-identical valid retry is idempotent against the intact held entry.
    expect(store.put({ evidenceId: env.evidenceId, body: plainBody() })).toEqual({
      outcome: PUT_OUTCOME.ALREADY_STORED,
      refusal: null,
    });
    expect(canonicalOf(must(store.get(env.evidenceId)).body)).toBe(cleanBytes);

    // Retrying with the mutated original is a refusal, never stored.
    const unboundOnly = plainBody();
    const unbound = { evidenceId: idOf(unboundOnly), body: { ...unboundOnly, observerVersion: 'tampered' } };
    expect(store.put(unbound)).toEqual({ outcome: PUT_OUTCOME.REFUSED, refusal: STORE_REFUSAL.UNBOUND_ENVELOPE });
    expect(store.put(env)).toEqual({ outcome: PUT_OUTCOME.REFUSED, refusal: STORE_REFUSAL.MALFORMED_ENVELOPE });
    const verdictTampered = plainBody();
    const verdictEnv = { evidenceId: idOf(verdictTampered), body: verdictTampered };
    verdictTampered.classification = 'BLOCKED';
    expect(store.put(verdictEnv).refusal).toBe(STORE_REFUSAL.MALFORMED_ENVELOPE);
    expect(store.integrityFaultCount()).toBe(0);
  });

  it('T2 get/list return the owned deep-frozen copy; writing through them throws and changes nothing', () => {
    const { store, id, bytes, env } = heldStore();
    const got = must(store.get(id));
    const listed = store.list();

    expect(got).not.toBe(env);
    expect(got.body).not.toBe(env.body);
    expect(listed).toHaveLength(1);
    expect(listed[0]).toBe(got);
    expect(Object.isFrozen(listed)).toBe(true);
    walk(got, (node) => {
      expect(Object.isFrozen(node)).toBe(true);
    });
    expect(Object.getPrototypeOf(got)).toBeNull();
    expect(Object.getPrototypeOf(got.body)).toBeNull();

    expect(() => {
      (got.body as unknown as { observerVersion: string }).observerVersion = 'mutated';
    }).toThrow(TypeError);
    expect(() => {
      (got.body.facts.f1CandidateIdentity as unknown as { value: boolean }).value = false;
    }).toThrow(TypeError);
    expect(() => {
      (got.body.reasonCodes as unknown as string[]).push('INDETERMINATE_FACT');
    }).toThrow(TypeError);
    expect(() => {
      (listed as unknown as unknown[]).push(got);
    }).toThrow(TypeError);

    expect(canonicalOf(must(store.get(id)).body)).toBe(bytes);
    expect(store.integrityFaultCount()).toBe(0);
  });

  it('T3 a getter at any schema slot is refused MALFORMED_ENVELOPE without being invoked', () => {
    const slots: { name: string; install: (env: Plain) => () => number }[] = [
      { name: 'envelope.evidenceId', install: (env) => installGetter(env, 'evidenceId') },
      { name: 'envelope.body', install: (env) => installGetter(env, 'body') },
      ...Object.keys(plainBody()).map((key) => ({
        name: `body.${key}`,
        install: (env: Plain) => installGetter(child(env, 'body'), key),
      })),
      { name: 'facts.f5UniqueCommits', install: (env) => installGetter(child(child(env, 'body'), 'facts'), 'f5UniqueCommits') },
      {
        name: 'record.value',
        install: (env) => installGetter(child(child(child(env, 'body'), 'facts'), 'f1CandidateIdentity'), 'value'),
      },
    ];
    for (const slot of slots) {
      const store = createRetirementAssessmentStore();
      const env = envelopeOf(plainBody());
      const calls = slot.install(env);
      expect(store.put(env), slot.name).toEqual({
        outcome: PUT_OUTCOME.REFUSED,
        refusal: STORE_REFUSAL.MALFORMED_ENVELOPE,
      });
      expect(calls(), slot.name).toBe(0);
      expect(store.list(), slot.name).toHaveLength(0);
    }

    // A reasonCodes index getter (the list is non-empty only for a BLOCKED body).
    const store = createRetirementAssessmentStore();
    const env = envelopeOf(plainBody(indeterminateFacts()));
    const calls = installGetter(list(child(env, 'body'), 'reasonCodes'), 0);
    expect(store.put(env).refusal).toBe(STORE_REFUSAL.MALFORMED_ENVELOPE);
    expect(calls()).toBe(0);
  });

  it('T4 mutating the facts map, a record, reasonCodes, or the envelope id after put changes nothing', () => {
    const store = createRetirementAssessmentStore();
    const body = plainBody(indeterminateFacts());
    const env: Plain = { evidenceId: idOf(body), body };
    const id = idOf(body);
    const bytes = canonicalOf(body);
    expect(store.put(env).outcome).toBe(PUT_OUTCOME.STORED);

    const facts = child(body, 'facts');
    facts.f2RemoteAgreement = { determinate: true, value: true };
    child(facts, 'f3StableMain').determinate = true;
    list(body, 'reasonCodes').push('GOVERNANCE_HOLD');
    list(body, 'reasonCodes').splice(0, 1);
    env.evidenceId = 'sha256:' + WRONG_HEX;

    expect(canonicalOf(must(store.get(id)).body)).toBe(bytes);
    expect(store.list().map((entry) => canonicalOf(entry.body))).toEqual([bytes]);
    expect(store.get('sha256:' + WRONG_HEX)).toBeNull();
    expect(store.put({ evidenceId: id, body: plainBody(indeterminateFacts()) }).outcome).toBe(
      PUT_OUTCOME.ALREADY_STORED,
    );
    expect(store.integrityFaultCount()).toBe(0);
  });

  it('T5 repeated byte-identical retries with fresh objects stay ALREADY_STORED', () => {
    const { store, id, bytes } = heldStore();
    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect(store.put({ evidenceId: id, body: plainBody() })).toEqual({
        outcome: PUT_OUTCOME.ALREADY_STORED,
        refusal: null,
      });
    }
    expect(canonicalOf(must(store.get(id)).body)).toBe(bytes);
    expect(store.integrityFaultCount()).toBe(0);
  });
});

/* ------------------------------------------------------------------------- *
 * T6-T8, T22, T23 — I3 and the permanent FAULTED latch
 * ------------------------------------------------------------------------- */

describe('retirement assessment store — I3 and the FAULTED latch (Rev 1 T6-T8, T22, T23)', () => {
  it('T6 a retry whose incoming envelope verifies cannot mask a held entry that no longer proves', () => {
    const { store, id } = heldStore();
    // Call 1 digests the incoming envelope correctly; call 2 is the held I3 re-digest.
    failAfter(1);
    cryptoSeam.calls = 0;
    expect(store.put({ evidenceId: id, body: plainBody() })).toEqual({
      outcome: PUT_OUTCOME.REFUSED,
      refusal: STORE_REFUSAL.INTEGRITY_FAULT,
    });
    expect(cryptoSeam.calls).toBe(2);
    expect(store.integrityFaultCount()).toBe(1);
  });

  it('T7 FAULTED is permanent: a restored digest never resurrects the store', () => {
    const { store, id } = heldStore();
    failAfter(0);
    expect(store.get(id)).toBeNull();
    expect(store.integrityFaultCount()).toBe(1);

    cryptoSeam.hex = null; // I3 matches again from here on
    for (let attempt = 0; attempt < 3; attempt += 1) {
      expect(store.get(id)).toBeNull();
      expect(store.list()).toEqual([]);
      expect(Object.isFrozen(store.list())).toBe(true);
    }
    expect(store.put({ evidenceId: id, body: plainBody() })).toEqual({
      outcome: PUT_OUTCOME.REFUSED,
      refusal: STORE_REFUSAL.INTEGRITY_FAULT,
    });
    const other = plainBody(eligibleFacts(), { observerVersion: 'other-observer' });
    expect(store.put(envelopeOf(other)).refusal).toBe(STORE_REFUSAL.INTEGRITY_FAULT);
    expect(store.integrityFaultCount()).toBe(1);
  });

  it('T8 a throwing digest fails closed and never escapes', () => {
    const throwing = (): string => {
      throw new Error('digest unavailable');
    };

    const { store, id } = heldStore();
    cryptoSeam.hex = throwing;
    expect(() => store.get(id)).not.toThrow();
    expect(store.integrityFaultCount()).toBe(1);
    expect(() => store.list()).not.toThrow();
    expect(store.list()).toEqual([]);
    expect(store.get(id)).toBeNull();
    expect(store.integrityFaultCount()).toBe(1);

    const fresh = createRetirementAssessmentStore();
    let result: StorePutResult | undefined;
    expect(() => {
      result = fresh.put(envelopeOf(plainBody()));
    }).not.toThrow();
    expect(result).toEqual({ outcome: PUT_OUTCOME.REFUSED, refusal: STORE_REFUSAL.UNBOUND_ENVELOPE });
    cryptoSeam.hex = null;
    expect(fresh.list()).toEqual([]);
    expect(fresh.integrityFaultCount()).toBe(0);
  });

  it('T22 every get(id) and every list() re-digests the held entry exactly once, before and after FAULTED', () => {
    const store = createRetirementAssessmentStore();
    const body = plainBody();
    const id = idOf(body);

    cryptoSeam.calls = 0;
    expect(store.get(id)).toBeNull();
    expect(store.list()).toEqual([]);
    expect(cryptoSeam.calls).toBe(0); // nothing held: no evidence to re-digest

    expect(store.put({ evidenceId: id, body }).outcome).toBe(PUT_OUTCOME.STORED);
    const reads: (() => unknown)[] = [
      () => store.get(id),
      () => store.get('sha256:' + 'e'.repeat(64)),
      () => store.get('not-an-evidence-id'),
      () => store.get(42),
      () => store.list(),
    ];
    for (const read of reads) {
      cryptoSeam.calls = 0;
      read();
      expect(cryptoSeam.calls).toBe(1);
    }

    failAfter(0);
    for (const read of reads) {
      cryptoSeam.calls = 0;
      read();
      expect(cryptoSeam.calls).toBe(1);
    }
    expect(store.integrityFaultCount()).toBe(1);

    cryptoSeam.hex = null;
    for (const read of reads) {
      cryptoSeam.calls = 0;
      read();
      expect(cryptoSeam.calls).toBe(1);
    }

    cryptoSeam.calls = 0;
    expect(store.put({ evidenceId: id, body: plainBody() }).refusal).toBe(STORE_REFUSAL.INTEGRITY_FAULT);
    expect(cryptoSeam.calls).toBe(0); // put on a FAULTED store refuses before any digest
  });

  it('T23 repeated post-latch mismatches keep the count at 1 and never alter held bytes', () => {
    const { store, id, bytes } = heldStore();
    const before = must(store.get(id));

    failAfter(0);
    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect(store.get(id)).toBeNull();
      expect(store.list()).toEqual([]);
      expect(store.integrityFaultCount()).toBe(1);
    }
    // Every I3 re-digest was over exactly the held bytes.
    expect(cryptoSeam.texts).toHaveLength(10);
    for (const text of cryptoSeam.texts) {
      expect(text).toBe(bytes);
    }
    expect(Object.isFrozen(before)).toBe(true);
    expect(canonicalOf(before.body)).toBe(bytes);
  });
});

/* ------------------------------------------------------------------------- *
 * T9-T18 — admission boundary
 * ------------------------------------------------------------------------- */

describe('retirement assessment store — hostile admission (Rev 1 T9-T18)', () => {
  it('T9 a different assessment is refused and never clobbers the held one', () => {
    const { store, id, bytes } = heldStore();
    const other = plainBody(indeterminateFacts());
    expect(store.put(envelopeOf(other))).toEqual({
      outcome: PUT_OUTCOME.REFUSED,
      refusal: STORE_REFUSAL.SECOND_ASSESSMENT_REFUSED,
    });
    expect(store.get(idOf(other))).toBeNull();
    expect(canonicalOf(must(store.get(id)).body)).toBe(bytes);
    expect(store.list()).toHaveLength(1);
  });

  it('T9 byte equality, not id equality, decides idempotency (forced digest collision)', () => {
    // Every digest answers the same value, so two different bodies share one id
    // and the held entry still passes I3: only the byte comparison can refuse.
    cryptoSeam.hex = () => WRONG_HEX;
    const collidingId = 'sha256:' + WRONG_HEX;
    const store = createRetirementAssessmentStore();
    const first = plainBody();
    const second = plainBody(indeterminateFacts());
    expect(store.put({ evidenceId: collidingId, body: first }).outcome).toBe(PUT_OUTCOME.STORED);
    expect(store.put({ evidenceId: collidingId, body: second })).toEqual({
      outcome: PUT_OUTCOME.REFUSED,
      refusal: STORE_REFUSAL.SECOND_ASSESSMENT_REFUSED,
    });
    expect(store.put({ evidenceId: collidingId, body: plainBody() }).outcome).toBe(PUT_OUTCOME.ALREADY_STORED);
    expect(canonicalOf(must(store.get(collidingId)).body)).toBe(canonicalOf(first));
    expect(store.integrityFaultCount()).toBe(0);
  });

  it('T10 a forged id is UNBOUND_ENVELOPE; a malformed id is MALFORMED_ENVELOPE; nothing is held', () => {
    const store = createRetirementAssessmentStore();
    const hex = realHex(canonicalOf(plainBody()));
    expect(store.put({ evidenceId: 'sha256:' + 'f'.repeat(64), body: plainBody() }).refusal).toBe(
      STORE_REFUSAL.UNBOUND_ENVELOPE,
    );
    for (const malformed of [
      'SHA256:' + hex,
      'sha256:' + hex.slice(1),
      'sha256:' + hex + '0',
      'sha256:' + hex.toUpperCase(),
      'sha256: ' + hex.slice(1),
      hex,
    ]) {
      expect(store.put({ evidenceId: malformed, body: plainBody() }).refusal, malformed).toBe(
        STORE_REFUSAL.MALFORMED_ENVELOPE,
      );
    }
    expect(store.list()).toEqual([]);
    expect(store.integrityFaultCount()).toBe(0);
  });

  it('T11 a body whose verdict is not derived from its facts is MALFORMED_ENVELOPE even when digest-bound', () => {
    const forgedClassification = plainBody(eligibleFacts(), { classification: 'BLOCKED' });
    const forgedGate = plainBody(eligibleFacts(), { gateRequested: false });
    const forgedReasons = plainBody(eligibleFacts(), { reasonCodes: ['GOVERNANCE_HOLD'] });
    for (const body of [forgedClassification, forgedGate, forgedReasons]) {
      const store = createRetirementAssessmentStore();
      expect(store.put(envelopeOf(body)).refusal).toBe(STORE_REFUSAL.MALFORMED_ENVELOPE);
      expect(store.list()).toEqual([]);
    }
  });

  it('T12 a Proxy is held only as its single read; throwing and revoked Proxies fail closed', () => {
    const base = plainBody();
    const id = idOf(base);
    let reads = 0;
    const shifting = new Proxy(base, {
      get(target, key, receiver): unknown {
        if (key === 'observerVersion') {
          reads += 1;
          return reads === 1 ? OBSERVER : 'shifted';
        }
        return Reflect.get(target, key, receiver) as unknown;
      },
    });
    const store = createRetirementAssessmentStore();
    expect(store.put({ evidenceId: id, body: shifting }).outcome).toBe(PUT_OUTCOME.STORED);
    expect(must(store.get(id)).body.observerVersion).toBe(OBSERVER);
    expect(must(store.get(id)).body.observerVersion).toBe(OBSERVER);
    expect(reads).toBe(1);

    const throwingOwnKeys = new Proxy(plainBody(), {
      ownKeys(): never {
        throw new Error('trap');
      },
    });
    const revokedBody = Proxy.revocable(plainBody(), {});
    revokedBody.revoke();
    const revokedEnvelope = Proxy.revocable({ evidenceId: id, body: plainBody() }, {});
    revokedEnvelope.revoke();
    for (const input of [
      { evidenceId: id, body: throwingOwnKeys },
      { evidenceId: id, body: revokedBody.proxy },
      revokedEnvelope.proxy,
    ]) {
      const fresh = createRetirementAssessmentStore();
      let result: StorePutResult | undefined;
      expect(() => {
        result = fresh.put(input);
      }).not.toThrow();
      expect(result?.refusal).toBe(STORE_REFUSAL.MALFORMED_ENVELOPE);
    }
  });

  it('T13 extra-key and shared-subgraph DAG bodies are refused before canonicalization', () => {
    const shared = plainBody();
    shared.extra = { left: shared.facts, right: shared.facts };
    let dag: unknown[] = [];
    for (let level = 0; level < 40; level += 1) {
      dag = [dag, dag];
    }
    const deep = plainBody(eligibleFacts(), { dag });
    const inFacts = plainBody();
    child(inFacts, 'facts').extra = dag;
    for (const body of [shared, deep, inFacts]) {
      const store = createRetirementAssessmentStore();
      cryptoSeam.calls = 0;
      expect(store.put({ evidenceId: 'sha256:' + WRONG_HEX, body }).refusal).toBe(
        STORE_REFUSAL.MALFORMED_ENVELOPE,
      );
      expect(cryptoSeam.calls).toBe(0);
    }
  });

  it('T14 immutable body: every returned node is frozen and carries no accessor', () => {
    const store = createRetirementAssessmentStore();
    const env = envelopeOf(plainBody(indeterminateFacts()));
    expect(store.put(env).outcome).toBe(PUT_OUTCOME.STORED);
    const got = must(store.get(env.evidenceId));
    let nodes = 0;
    walk(got, (node) => {
      nodes += 1;
      expect(Object.isFrozen(node)).toBe(true);
      for (const key of Reflect.ownKeys(node)) {
        const descriptor = must(Object.getOwnPropertyDescriptor(node, key));
        expect('get' in descriptor || 'set' in descriptor).toBe(false);
      }
    });
    // envelope, body, facts, ten records, reasonCodes
    expect(nodes).toBe(14);
  });

  it('T15 the stored id is SHA-256 over UTF-8 AB-CJSON-1; a custom-prototype body binds like its plain twin', () => {
    const plain = plainBody();
    const store = createRetirementAssessmentStore();
    expect(store.put(envelopeOf(plain)).outcome).toBe(PUT_OUTCOME.STORED);
    const got = must(store.list()[0]);
    expect(got.evidenceId).toBe('sha256:' + realHex(canonicalOf(got.body)));
    expect(got.evidenceId).toBe(idOf(plain));

    const custom = Object.assign(Object.create({ inherited: 'not own state' }) as Plain, plainBody());
    const other = createRetirementAssessmentStore();
    expect(other.put({ evidenceId: idOf(plain), body: custom }).outcome).toBe(PUT_OUTCOME.STORED);
    const copy = must(other.get(idOf(plain)));
    expect(canonicalOf(copy.body)).toBe(canonicalOf(plain));
    expect(Object.getPrototypeOf(copy.body)).toBeNull();
  });

  it('T16 a lone surrogate and its U+FFFD twin bind to different ids', () => {
    const lone = plainBody(eligibleFacts(), { observerVersion: 'observer-\uD800' });
    const replaced = plainBody(eligibleFacts(), { observerVersion: 'observer-�' });
    expect(canonicalOf(lone)).toContain('\\ud800');
    expect(idOf(lone)).not.toBe(idOf(replaced));
    for (const body of [lone, replaced]) {
      const store = createRetirementAssessmentStore();
      expect(store.put(envelopeOf(body)).outcome).toBe(PUT_OUTCOME.STORED);
      expect(store.get(idOf(body))).not.toBeNull();
    }
  });

  it('T17 lookups that name nothing return null and record no fault', () => {
    const empty = createRetirementAssessmentStore();
    expect(empty.get(idOf(plainBody()))).toBeNull();
    expect(empty.list()).toEqual([]);
    expect(Object.isFrozen(empty.list())).toBe(true);

    const { store, id } = heldStore();
    for (const lookup of [
      'sha256:' + 'e'.repeat(64),
      id.toUpperCase(),
      id + ' ',
      '',
      42,
      null,
      undefined,
      { toString: () => id },
      [id],
    ]) {
      expect(store.get(lookup)).toBeNull();
    }
    expect(store.integrityFaultCount()).toBe(0);
    expect(store.get(id)).not.toBeNull();
  });

  it('T18 hostile non-envelopes are MALFORMED_ENVELOPE and never throw', () => {
    const env = envelopeOf(plainBody());
    const withSymbol = { ...env, [Symbol('hidden')]: 1 };
    const withHidden = { ...env };
    Object.defineProperty(withHidden, 'hidden', { value: 1, enumerable: false });
    const withExtra = { ...env, extra: 1 };
    for (const input of [null, undefined, 0, 'envelope', true, [], [env], withSymbol, withHidden, withExtra]) {
      const store = createRetirementAssessmentStore();
      let result: StorePutResult | undefined;
      expect(() => {
        result = store.put(input);
      }).not.toThrow();
      expect(result).toEqual({ outcome: PUT_OUTCOME.REFUSED, refusal: STORE_REFUSAL.MALFORMED_ENVELOPE });
      expect(store.list()).toEqual([]);
    }
  });
});

/* ------------------------------------------------------------------------- *
 * T19-T21 — total budget and surface
 * ------------------------------------------------------------------------- */

describe('retirement assessment store — budget and surface (Rev 1 T19-T21)', () => {
  it('T19 the worst admissible body canonicalizes to at most 8192 UTF-8 bytes', () => {
    const escapeHeavy = '\u0001'.repeat(256); // six output units per input unit
    for (const facts of [indeterminateFacts(), mostReasonsFacts()]) {
      const body = plainBody(facts, {
        repositoryId: escapeHeavy,
        candidateRef: 'refs/heads/' + 'z'.repeat(245),
        generatedAt: escapeHeavy,
        observerVersion: escapeHeavy,
      });
      const store = createRetirementAssessmentStore();
      expect(store.put(envelopeOf(body)).outcome).toBe(PUT_OUTCOME.STORED);
      const held = canonicalOf(must(store.list()[0]).body);
      expect(Buffer.byteLength(held, 'utf8')).toBeLessThanOrEqual(8192);
    }
  });

  it('T20 the surface is exactly four verbs on a frozen object; results are frozen and consistent', () => {
    const store = createRetirementAssessmentStore();
    expect(createRetirementAssessmentStore.length).toBe(0);
    expect(Object.isFrozen(store)).toBe(true);
    expect(Reflect.ownKeys(store).sort()).toEqual(['get', 'integrityFaultCount', 'list', 'put']);

    expect(Object.isFrozen(PUT_OUTCOME)).toBe(true);
    expect(Object.entries(PUT_OUTCOME)).toEqual([
      ['STORED', 'STORED'],
      ['ALREADY_STORED', 'ALREADY_STORED'],
      ['REFUSED', 'REFUSED'],
    ]);
    expect(Object.isFrozen(STORE_REFUSAL)).toBe(true);
    expect(Object.entries(STORE_REFUSAL)).toEqual([
      ['MALFORMED_ENVELOPE', 'MALFORMED_ENVELOPE'],
      ['NOT_CANONICALIZABLE', 'NOT_CANONICALIZABLE'],
      ['UNBOUND_ENVELOPE', 'UNBOUND_ENVELOPE'],
      ['SECOND_ASSESSMENT_REFUSED', 'SECOND_ASSESSMENT_REFUSED'],
      ['INTEGRITY_FAULT', 'INTEGRITY_FAULT'],
    ]);

    const env = envelopeOf(plainBody());
    const results: StorePutResult[] = [
      store.put(null),
      store.put({ evidenceId: 'sha256:' + WRONG_HEX, body: plainBody() }),
      store.put(env),
      store.put(env),
      store.put(envelopeOf(plainBody(indeterminateFacts()))),
    ];
    failAfter(0);
    store.get(idOf(plainBody()));
    results.push(store.put(env));
    expect(results.map((result) => result.outcome)).toEqual([
      'REFUSED',
      'REFUSED',
      'STORED',
      'ALREADY_STORED',
      'REFUSED',
      'REFUSED',
    ]);
    for (const result of results) {
      expect(Object.isFrozen(result)).toBe(true);
      expect(Object.getPrototypeOf(result)).toBeNull();
      expect(Reflect.ownKeys(result).sort()).toEqual(['outcome', 'refusal']);
      expect(result.refusal === null).toBe(result.outcome !== PUT_OUTCOME.REFUSED);
    }
  });

  it('T21 no store vocabulary member is a classification or a reason', () => {
    const storeVocabulary: string[] = [...Object.values(PUT_OUTCOME), ...Object.values(STORE_REFUSAL)];
    const domainVocabulary: string[] = [...RETIREMENT_CLASSIFICATIONS, ...RETIREMENT_REASONS];
    for (const member of storeVocabulary) {
      expect(domainVocabulary).not.toContain(member);
    }
    const got: RetirementAssessmentEnvelope | null = createRetirementAssessmentStore().get(idOf(plainBody()));
    expect(got).toBeNull();
  });
});

/**
 * D4 Stage B: the serialized Autoflow provenance contract at the D1 boundary.
 *
 * D1 is the single hostile-input boundary. Under schema version 2 the snapshot
 * carries a required `autoflow` field — a serialized PR 007 `WorkflowState`, or
 * an explicit `null`. The reader accepts version 2 only, requires the property to
 * be present, and reconstructs a value through the domain's own `readWorkflowState`
 * reader. Absent, null, malformed, and unsupported-version are four distinct
 * conditions and are never folded together.
 */

import { afterEach, describe, expect, it } from 'vitest';

import { projectCockpitAutoflow } from '../../src/cockpit/autoflow-projection.js';
import {
  COCKPIT_SNAPSHOT_FIELD_ORDER,
  COCKPIT_SNAPSHOT_SCHEMA_VERSION,
  readCockpitSnapshot,
  type CockpitSnapshot,
} from '../../src/cockpit/index.js';
import { REPO_A, buildRepository, buildSnapshot } from './read-model-fixtures.js';

const HEAD = 'c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00';

/**
 * A repository identity distinct from the envelope's {@link REPO_A}, used to
 * forge an internally valid workflow that belongs to a *different* repository.
 */
const REPO_B = 'github.com/other/repository';

/**
 * A fresh, valid serialized WorkflowState (OPEN, one REQUESTED invocation).
 *
 * `repositoryId` defaults to the envelope's own {@link REPO_A} so a plain
 * `validAutoflow()` describes a workflow that legitimately belongs to the
 * snapshot built by {@link buildSnapshot}; pass a different id to forge a
 * cross-repository state.
 */
function validAutoflow(repositoryId: string = REPO_A): Record<string, unknown> {
  return {
    workflowId: 'wf-1',
    repositoryId,
    pullRequestId: 'pr-1',
    boundCommitSha: HEAD,
    revision: 0,
    sequence: 1,
    status: 'OPEN',
    closureReason: null,
    humanGateOpenedAtRevision: null,
    invocations: [
      {
        invocationId: 'inv-1',
        targetCommitSha: HEAD,
        purpose: 'review',
        providerId: 'claude',
        agentId: 'agent-1',
        requestedAtRevision: 0,
        requestedAtSequence: 1,
        state: 'REQUESTED',
        reportedStatus: null,
        reportedAtRevision: null,
        reportedAtSequence: null,
      },
    ],
    evidence: [],
    reviews: [],
  };
}

/** A structurally malformed autoflow value (present, non-null, not a valid state). */
function malformedAutoflow(): unknown {
  return { workflowId: 'wf-1', status: 'NOT_A_STATUS' };
}

/** Build a raw snapshot object, then set/remove `autoflow` and `schemaVersion` exactly. */
function raw(
  schemaVersion: unknown,
  autoflow: 'absent' | { readonly value: unknown },
): unknown {
  const snapshot = buildSnapshot() as unknown as Record<string, unknown>;
  snapshot.schemaVersion = schemaVersion;
  if (autoflow === 'absent') {
    delete snapshot.autoflow;
  } else {
    snapshot.autoflow = autoflow.value;
  }
  return snapshot;
}

describe('D1 strict schema-v2 / autoflow compatibility matrix', () => {
  it('the reader defines version 2', () => {
    expect(COCKPIT_SNAPSHOT_SCHEMA_VERSION).toBe(2);
  });

  // Cases 1–4: version 1 is unsupported, whatever autoflow carries.
  it('1. v1 + autoflow absent → REJECT (schemaVersion)', () => {
    const r = readCockpitSnapshot(raw(1, 'absent'));
    expect(r.snapshot).toBeNull();
    expect(r.invalidFields).toContain('schemaVersion');
  });
  it('2. v1 + autoflow null → REJECT', () => {
    const r = readCockpitSnapshot(raw(1, { value: null }));
    expect(r.snapshot).toBeNull();
    expect(r.invalidFields).toContain('schemaVersion');
  });
  it('3. v1 + autoflow valid → REJECT', () => {
    const r = readCockpitSnapshot(raw(1, { value: validAutoflow() }));
    expect(r.snapshot).toBeNull();
    expect(r.invalidFields).toContain('schemaVersion');
  });
  it('4. v1 + autoflow malformed → REJECT', () => {
    const r = readCockpitSnapshot(raw(1, { value: malformedAutoflow() }));
    expect(r.snapshot).toBeNull();
    expect(r.invalidFields).toContain('schemaVersion');
  });

  // Cases 5–8: version 2 discriminates absent / null / valid / malformed.
  it('5. v2 + autoflow absent → REJECT (autoflow), distinct from null', () => {
    const r = readCockpitSnapshot(raw(2, 'absent'));
    expect(r.snapshot).toBeNull();
    expect(r.invalidFields).toContain('autoflow');
    expect(r.invalidFields).not.toContain('schemaVersion');
  });
  it('6. v2 + autoflow null → ACCEPT with trusted null', () => {
    const r = readCockpitSnapshot(raw(2, { value: null }));
    expect(r.invalidFields).toEqual([]);
    expect(r.snapshot).not.toBeNull();
    expect(r.snapshot?.autoflow).toBeNull();
  });
  it('7. v2 + autoflow valid → ACCEPT with a trusted, frozen, detached WorkflowState', () => {
    const input = validAutoflow();
    const r = readCockpitSnapshot(raw(2, { value: input }));
    expect(r.invalidFields).toEqual([]);
    const state = r.snapshot?.autoflow ?? null;
    expect(state).not.toBeNull();
    expect(state?.workflowId).toBe('wf-1');
    expect(state?.status).toBe('OPEN');
    expect(Object.isFrozen(state)).toBe(true);
    expect(Object.isFrozen(state?.invocations)).toBe(true);
    // Detached: it is not the input object, and mutating the input is inert.
    expect(state).not.toBe(input);
    input.workflowId = 'mutated';
    expect(state?.workflowId).toBe('wf-1');
    // The trusted state projects through the unchanged D4 projector.
    const projection = projectCockpitAutoflow(state as NonNullable<typeof state>);
    expect(projection.workflowId).toBe('wf-1');
    expect(projection.counts.invocationsTotal).toBe(1);
  });
  it('8. v2 + autoflow malformed → REJECT (autoflow), whole snapshot', () => {
    const r = readCockpitSnapshot(raw(2, { value: malformedAutoflow() }));
    expect(r.snapshot).toBeNull();
    expect(r.invalidFields).toContain('autoflow');
  });

  // Cases 9–12: every other schemaVersion form is rejected whole.
  it('9. v0 → REJECT', () => {
    expect(readCockpitSnapshot(raw(0, { value: null })).snapshot).toBeNull();
  });
  it('10. v3 → REJECT', () => {
    expect(readCockpitSnapshot(raw(3, { value: null })).snapshot).toBeNull();
  });
  it('11. non-integer schemaVersion → REJECT', () => {
    expect(readCockpitSnapshot(raw(1.5, { value: null })).snapshot).toBeNull();
  });
  it('12. hostile/unreadable schemaVersion → REJECT, never throwing', () => {
    const snapshot = buildSnapshot() as unknown as Record<string, unknown>;
    Object.defineProperty(snapshot, 'schemaVersion', {
      get() {
        throw new Error('hostile');
      },
      enumerable: true,
      configurable: true,
    });
    const r = readCockpitSnapshot(snapshot);
    expect(r.snapshot).toBeNull();
    expect(r.invalidFields).toContain('schemaVersion');
  });
});

describe('D1 autoflow determinism and round trip', () => {
  it('reports autoflow after repairJobs in the deterministic field order', () => {
    expect(COCKPIT_SNAPSHOT_FIELD_ORDER.indexOf('autoflow')).toBe(
      COCKPIT_SNAPSHOT_FIELD_ORDER.indexOf('repairJobs') + 1,
    );
  });

  it('a populated-autoflow snapshot survives a plain-JSON round trip', () => {
    const first = readCockpitSnapshot(raw(2, { value: validAutoflow() })).snapshot;
    expect(first).not.toBeNull();
    const revived: unknown = JSON.parse(JSON.stringify(first));
    const second = readCockpitSnapshot(revived);
    expect(second.invalidFields).toEqual([]);
    expect(second.snapshot).toEqual(first as CockpitSnapshot);
  });
});

describe('D1 snapshot serialization is safe with a non-null autoflow (PR74-F1)', () => {
  const objectToJSON = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');

  afterEach(() => {
    if (objectToJSON !== undefined) {
      Object.defineProperty(Object.prototype, 'toJSON', objectToJSON);
    } else {
      delete (Object.prototype as unknown as Record<string, unknown>).toJSON;
    }
  });

  /** A valid autoflow whose `workflowId` getter installs `Object.prototype.toJSON` mid-read. */
  function autoflowPoisoningDuringRead(): Record<string, unknown> {
    const base = validAutoflow();
    let installed = false;
    Object.defineProperty(base, 'workflowId', {
      get(): string {
        if (!installed) {
          installed = true;
          (Object.prototype as unknown as Record<string, unknown>).toJSON = () => ({
            HIJACKED: true,
          });
        }
        return 'wf-1';
      },
      enumerable: true,
      configurable: true,
    });
    return base;
  }

  it('serializing a snapshot whose autoflow was ingested under a poisoned toJSON is safe', () => {
    const read = readCockpitSnapshot(raw(2, { value: autoflowPoisoningDuringRead() }));
    expect(read.snapshot).not.toBeNull();
    expect(read.snapshot?.autoflow).not.toBeNull();
    // The poison is live; serializing the D1 snapshot must not execute it.
    let json = '';
    expect(() => {
      json = JSON.stringify(read.snapshot);
    }).not.toThrow();
    expect(json).not.toContain('HIJACKED');
    const parsed = JSON.parse(json) as { autoflow: { workflowId: string } | null };
    expect(parsed.autoflow?.workflowId).toBe('wf-1');
  });
});

describe('D1 autoflow repository-binding invariant (PR74-F2)', () => {
  // Envelope contract: one CockpitSnapshot represents exactly one repository. A
  // serialized WorkflowState may be internally valid yet describe a *different*
  // repository; readWorkflowState cannot see the envelope, so readCockpitSnapshot
  // owns the cross-field check `snapshot.repository.repositoryId ==
  // snapshot.autoflow.repositoryId`. The trusted side of that comparison is the
  // envelope identity already captured while reading `repository.repositoryId`.

  it('1. repository=A + autoflow.repositoryId=B → whole snapshot REJECT', () => {
    const r = readCockpitSnapshot(raw(2, { value: validAutoflow(REPO_B) }));
    expect(r.snapshot).toBeNull();
  });

  it('2. the mismatch flags exactly `autoflow`, leaving the valid envelope repository untouched', () => {
    const r = readCockpitSnapshot(raw(2, { value: validAutoflow(REPO_B) }));
    expect(r.invalidFields).toContain('autoflow');
    // The envelope's own repository identity is valid: the cross-field check adds
    // no second repository source of truth and does not corrupt envelope reads.
    expect(r.invalidFields).not.toContain('repository.repositoryId');
    expect(r.invalidFields).not.toContain('schemaVersion');
  });

  it('3. repository=A + autoflow.repositoryId=A → ACCEPT (matching binds)', () => {
    const r = readCockpitSnapshot(raw(2, { value: validAutoflow(REPO_A) }));
    expect(r.invalidFields).toEqual([]);
    expect(r.snapshot).not.toBeNull();
    expect(r.snapshot?.repository.repositoryId).toBe(REPO_A);
    expect(r.snapshot?.autoflow?.repositoryId).toBe(REPO_A);
  });

  it('4. null autoflow still ACCEPTs under the binding check (null semantics unchanged)', () => {
    const r = readCockpitSnapshot(raw(2, { value: null }));
    expect(r.invalidFields).toEqual([]);
    expect(r.snapshot).not.toBeNull();
    expect(r.snapshot?.autoflow).toBeNull();
  });

  it('5. malformed autoflow still REJECTs as `autoflow` (malformed semantics unchanged)', () => {
    const r = readCockpitSnapshot(raw(2, { value: malformedAutoflow() }));
    expect(r.snapshot).toBeNull();
    expect(r.invalidFields).toContain('autoflow');
  });

  it('6. a matching-autoflow snapshot survives a plain-JSON round trip unchanged', () => {
    const first = readCockpitSnapshot(raw(2, { value: validAutoflow(REPO_A) })).snapshot;
    expect(first).not.toBeNull();
    const revived: unknown = JSON.parse(JSON.stringify(first));
    const second = readCockpitSnapshot(revived);
    expect(second.invalidFields).toEqual([]);
    expect(second.snapshot).toEqual(first as CockpitSnapshot);
  });

  it('7. neither the workflow nor the envelope repositoryId is mutated or coerced', () => {
    // Mismatch: the foreign input keeps its own id; nothing is rewritten to A.
    const foreign = validAutoflow(REPO_B);
    readCockpitSnapshot(raw(2, { value: foreign }));
    expect(foreign.repositoryId).toBe(REPO_B);

    // Match: the reconstructed state reports A because the input already said A,
    // not because the envelope id was injected over some other value.
    const owned = validAutoflow(REPO_A);
    const r = readCockpitSnapshot(raw(2, { value: owned }));
    expect(owned.repositoryId).toBe(REPO_A);
    expect(r.snapshot?.autoflow?.repositoryId).toBe(REPO_A);
    expect(r.snapshot?.repository.repositoryId).toBe(REPO_A);
  });

  it('8. a repository.repositoryId that flips after capture cannot rebind a foreign workflow (TOCTOU)', () => {
    const base = buildRepository();
    const hostileRepository: Record<string, unknown> = {
      observedHeadSha: base.observedHeadSha,
      defaultBranchRef: base.defaultBranchRef,
    };
    let reads = 0;
    Object.defineProperty(hostileRepository, 'repositoryId', {
      get(): string {
        reads += 1;
        // Trusted A on the first (capturing) read; a *repeated* untrusted read
        // would see B and wrongly "match" the forged workflow below.
        return reads === 1 ? REPO_A : REPO_B;
      },
      enumerable: true,
      configurable: true,
    });
    const snapshot = buildSnapshot() as unknown as Record<string, unknown>;
    snapshot.schemaVersion = COCKPIT_SNAPSHOT_SCHEMA_VERSION;
    snapshot.repository = hostileRepository;
    snapshot.autoflow = validAutoflow(REPO_B);

    const r = readCockpitSnapshot(snapshot);
    expect(r.snapshot).toBeNull();
    expect(r.invalidFields).toContain('autoflow');
    // The identity captured as A stays valid and is never re-read as B.
    expect(r.invalidFields).not.toContain('repository.repositoryId');
  });
});

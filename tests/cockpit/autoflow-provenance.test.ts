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

import { describe, expect, it } from 'vitest';

import { projectCockpitAutoflow } from '../../src/cockpit/autoflow-projection.js';
import {
  COCKPIT_SNAPSHOT_FIELD_ORDER,
  COCKPIT_SNAPSHOT_SCHEMA_VERSION,
  readCockpitSnapshot,
  type CockpitSnapshot,
} from '../../src/cockpit/index.js';
import { buildSnapshot } from './read-model-fixtures.js';

const HEAD = 'c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00';

/** A fresh, valid serialized WorkflowState (OPEN, one REQUESTED invocation). */
function validAutoflow(): Record<string, unknown> {
  return {
    workflowId: 'wf-1',
    repositoryId: 'owner/repo',
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

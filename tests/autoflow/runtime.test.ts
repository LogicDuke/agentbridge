import { describe, expect, it } from 'vitest';

import {
  AUTOFLOW_APPLY_NO_WORKFLOW,
  AUTOFLOW_OPEN_ALREADY_ACTIVE,
  AutoflowRuntime,
  type AutoflowStateReader,
} from '../../src/autoflow/runtime.js';
import {
  openWorkflow,
  TRANSITION_OUTCOME,
  type WorkflowBinding,
  type WorkflowEvent,
} from '../../src/domain/index.js';

const REPO = 'repo-agentbridge';
const SHA_A = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
const SHA_B = 'ffeeddccbbaa99887766554433221100aabbccdd';

const BINDING: WorkflowBinding = {
  workflowId: 'wf-live-0001',
  repositoryId: REPO,
  boundCommitSha: SHA_A,
};
const BINDING_BAD: WorkflowBinding = {
  workflowId: 'wf-live-0001',
  repositoryId: REPO,
  boundCommitSha: '',
};
const HEAD_OBSERVED_B: WorkflowEvent = { kind: 'HEAD_OBSERVED', observedCommitSha: SHA_B };
const HEAD_OBSERVED_BAD: WorkflowEvent = { kind: 'HEAD_OBSERVED', observedCommitSha: '' };

describe('AutoflowRuntime', () => {
  it('current() starts null', () => {
    const runtime = new AutoflowRuntime();
    expect(runtime.current()).toBeNull();
  });

  it('open(APPLIED) advances the current state', () => {
    const runtime = new AutoflowRuntime();
    const result = runtime.open(BINDING);
    expect(result.outcome).toBe(TRANSITION_OUTCOME.APPLIED);
    const state = runtime.current();
    expect(state).not.toBeNull();
    expect(state?.workflowId).toBe('wf-live-0001');
    expect(state?.repositoryId).toBe(REPO);
    expect(state?.status).toBe('OPEN');
  });

  it('open(REJECTED) does not replace the current state', () => {
    const runtime = new AutoflowRuntime();
    const result = runtime.open(BINDING_BAD);
    expect(result.outcome).toBe(TRANSITION_OUTCOME.REJECTED);
    expect(runtime.current()).toBeNull();
  });

  it('apply(APPLIED) advances the current state', () => {
    const runtime = new AutoflowRuntime();
    runtime.open(BINDING);
    const result = runtime.apply(HEAD_OBSERVED_B);
    expect(result.outcome).toBe(TRANSITION_OUTCOME.APPLIED);
    expect(runtime.current()?.boundCommitSha).toBe(SHA_B);
  });

  it('apply(REJECTED) leaves the current state unchanged (identical reference)', () => {
    const runtime = new AutoflowRuntime();
    runtime.open(BINDING);
    const before = runtime.current();
    const result = runtime.apply(HEAD_OBSERVED_BAD);
    expect(result.outcome).toBe(TRANSITION_OUTCOME.REJECTED);
    expect(runtime.current()).toBe(before);
    expect(runtime.current()?.boundCommitSha).toBe(SHA_A);
  });

  it('the previous state object is left frozen and unmutated across a transition', () => {
    const runtime = new AutoflowRuntime();
    runtime.open(BINDING);
    const before = runtime.current();
    expect(before).not.toBeNull();
    expect(Object.isFrozen(before)).toBe(true);
    runtime.apply(HEAD_OBSERVED_B);
    // The prior reference still reads SHA_A; the transition replaced, not mutated.
    expect(before?.boundCommitSha).toBe(SHA_A);
    expect(runtime.current()).not.toBe(before);
  });

  it('apply() with no open workflow returns the bounded NO_WORKFLOW result and touches nothing', () => {
    const runtime = new AutoflowRuntime();
    const result = runtime.apply(HEAD_OBSERVED_B);
    expect(result.outcome).toBe(AUTOFLOW_APPLY_NO_WORKFLOW);
    expect(result.state).toBeNull();
    expect(runtime.current()).toBeNull();
  });

  it('open/apply delegate to the real pure domain transitions', () => {
    const runtime = new AutoflowRuntime();
    runtime.open(BINDING);
    // openWorkflow is pure/deterministic; the runtime holds exactly its output.
    expect(runtime.current()).toStrictEqual(openWorkflow(BINDING).state);
  });

  it('reader() exposes current() only — open/apply are absent at runtime', () => {
    const runtime = new AutoflowRuntime();
    const reader: AutoflowStateReader = runtime.reader();
    expect('current' in reader).toBe(true);
    expect('open' in reader).toBe(false);
    expect('apply' in reader).toBe(false);
    expect(Object.isFrozen(reader)).toBe(true);
    const asRecord = reader as unknown as Record<string, unknown>;
    expect(asRecord['open']).toBeUndefined();
    expect(asRecord['apply']).toBeUndefined();
  });

  it('reader() reflects the live current state', () => {
    const runtime = new AutoflowRuntime();
    const reader = runtime.reader();
    expect(reader.current()).toBeNull();
    runtime.open(BINDING);
    expect(reader.current()).toBe(runtime.current());
    expect(reader.current()?.status).toBe('OPEN');
  });
});

const BINDING_2: WorkflowBinding = {
  workflowId: 'wf-live-0002',
  repositoryId: REPO,
  boundCommitSha: SHA_B,
};
const HUMAN_GATE_A: WorkflowEvent = { kind: 'HUMAN_GATE_OPENED', atCommitSha: SHA_A };
const CLOSE: WorkflowEvent = { kind: 'CLOSE_REQUESTED', closureReason: 'CALLER_CLOSED' };

describe('AutoflowRuntime single-active-workflow open guard', () => {
  it('rejects a second open while OPEN with WORKFLOW_ALREADY_ACTIVE, unchanged reference', () => {
    const runtime = new AutoflowRuntime();
    runtime.open(BINDING);
    const before = runtime.current();
    const result = runtime.open(BINDING_2);
    expect(result.outcome).toBe(AUTOFLOW_OPEN_ALREADY_ACTIVE);
    expect(result.state).toBeNull();
    // The active workflow is not clobbered: exact prior reference retained.
    expect(runtime.current()).toBe(before);
    expect(runtime.current()?.workflowId).toBe('wf-live-0001');
  });

  it('rejects a second open while AWAITING_HUMAN_DECISION with WORKFLOW_ALREADY_ACTIVE', () => {
    const runtime = new AutoflowRuntime();
    runtime.open(BINDING);
    runtime.apply(HUMAN_GATE_A);
    expect(runtime.current()?.status).toBe('AWAITING_HUMAN_DECISION');
    const before = runtime.current();
    const result = runtime.open(BINDING_2);
    expect(result.outcome).toBe(AUTOFLOW_OPEN_ALREADY_ACTIVE);
    expect(runtime.current()).toBe(before);
  });

  it('permits a new open after the current workflow is CLOSED', () => {
    const runtime = new AutoflowRuntime();
    runtime.open(BINDING);
    runtime.apply(CLOSE);
    expect(runtime.current()?.status).toBe('CLOSED');
    const result = runtime.open(BINDING_2);
    expect(result.outcome).toBe(TRANSITION_OUTCOME.APPLIED);
    // The new workflow replaces the closed prior; no history is retained.
    expect(runtime.current()?.workflowId).toBe('wf-live-0002');
    expect(runtime.current()?.status).toBe('OPEN');
  });

  it('permits an open from null (no prior workflow)', () => {
    const runtime = new AutoflowRuntime();
    const result = runtime.open(BINDING);
    expect(result.outcome).toBe(TRANSITION_OUTCOME.APPLIED);
    expect(runtime.current()?.workflowId).toBe('wf-live-0001');
  });
});

describe('reader() capability containment — writer is unrecoverable via prototype swap', () => {
  it('reader.current() does not dispatch through AutoflowRuntime.prototype.current', () => {
    const runtime = new AutoflowRuntime();
    runtime.open(BINDING);
    const reader = runtime.reader();
    const expected = runtime.current(); // live OPEN state, captured before the patch

    // Save/restore via descriptor (avoids taking an unbound-method reference).
    const originalDesc = Object.getOwnPropertyDescriptor(AutoflowRuntime.prototype, 'current');
    const receivers: unknown[] = [];
    try {
      // Adversarial: a downstream same-process actor replaces the (publicly
      // importable, mutable) prototype method to observe its receiver.
      (AutoflowRuntime.prototype as unknown as { current: () => unknown }).current =
        function (this: unknown): unknown {
          receivers.push(this);
          return null;
        };

      // The repaired reader reads the private state cell directly, so it routes
      // through NO prototype method: the patch is never invoked, no runtime
      // receiver is captured, and the live state is still returned unaffected.
      const value = reader.current();
      expect(receivers).toHaveLength(0);
      expect(value).toBe(expected);

      // Control: the patch itself IS effective — calling the prototype method on
      // a runtime receiver DOES capture it. The reader simply never routes there.
      (runtime as unknown as { current: () => unknown }).current();
      expect(receivers).toHaveLength(1);
      expect(receivers[0]).toBe(runtime);
    } finally {
      if (originalDesc !== undefined) {
        Object.defineProperty(AutoflowRuntime.prototype, 'current', originalDesc);
      }
    }

    // After restore, the reader remains live across a subsequent transition.
    runtime.apply(HEAD_OBSERVED_B);
    expect(reader.current()).toBe(runtime.current());
    expect(reader.current()?.boundCommitSha).toBe(SHA_B);
  });

  it('reader exposes current() only; open/apply remain absent/unrecoverable', () => {
    const reader = new AutoflowRuntime().reader();
    const asRecord = reader as unknown as Record<string, unknown>;
    expect('current' in reader).toBe(true);
    expect('open' in reader).toBe(false);
    expect('apply' in reader).toBe(false);
    expect(asRecord['open']).toBeUndefined();
    expect(asRecord['apply']).toBeUndefined();
    expect(Object.isFrozen(reader)).toBe(true);
  });
});

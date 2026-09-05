import { describe, expect, it } from 'vitest';

import {
  AUTOFLOW_APPLY_NO_WORKFLOW,
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

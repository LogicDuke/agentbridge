import { describe, expect, it } from 'vitest';

import { AutoflowOrchestrator } from '../../src/autoflow/orchestrator.js';
import {
  AUTOFLOW_APPLY_NO_WORKFLOW,
  AUTOFLOW_OPEN_ALREADY_ACTIVE,
  AutoflowRuntime,
} from '../../src/autoflow/runtime.js';
import {
  TRANSITION_OUTCOME,
  TRANSITION_REJECTION,
  WORKFLOW_STATUS,
  type WorkflowBinding,
} from '../../src/domain/index.js';

const REPO = 'repo-agentbridge';
const SHA_A = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
const SHA_B = 'ffeeddccbbaa99887766554433221100aabbccdd';

const BINDING: WorkflowBinding = { workflowId: 'wf-live-0001', repositoryId: REPO, boundCommitSha: SHA_A };
const BINDING_2: WorkflowBinding = { workflowId: 'wf-live-0002', repositoryId: REPO, boundCommitSha: SHA_B };
const BINDING_BAD: WorkflowBinding = { workflowId: '', repositoryId: REPO, boundCommitSha: SHA_A };

describe('AutoflowOrchestrator single-writer boundary', () => {
  it('open() delegates to the real domain openWorkflow (APPLIED opens one workflow)', () => {
    const runtime = new AutoflowRuntime();
    const orchestrator = new AutoflowOrchestrator(runtime);
    const result = orchestrator.open(BINDING);
    expect(result.outcome).toBe(TRANSITION_OUTCOME.APPLIED);
    expect(runtime.current()?.workflowId).toBe('wf-live-0001');
    expect(runtime.current()?.status).toBe('OPEN');
  });

  it('open() surfaces the runtime WORKFLOW_ALREADY_ACTIVE guard for a second open', () => {
    const orchestrator = new AutoflowOrchestrator(new AutoflowRuntime());
    orchestrator.open(BINDING);
    const result = orchestrator.open(BINDING_2);
    expect(result.outcome).toBe(AUTOFLOW_OPEN_ALREADY_ACTIVE);
  });

  it('open() surfaces a domain REJECTED result for a malformed binding', () => {
    const orchestrator = new AutoflowOrchestrator(new AutoflowRuntime());
    const result = orchestrator.open(BINDING_BAD);
    expect(result.outcome).toBe(TRANSITION_OUTCOME.REJECTED);
  });

  it('reader() exposes current() only — the writer verbs are absent at runtime', () => {
    const runtime = new AutoflowRuntime();
    const orchestrator = new AutoflowOrchestrator(runtime);
    const reader = orchestrator.reader();
    expect('current' in reader).toBe(true);
    expect('open' in reader).toBe(false);
    expect('apply' in reader).toBe(false);
    orchestrator.open(BINDING);
    expect(reader.current()).toBe(runtime.current());
  });

  it('does not expose the write-capable runtime on its public surface', () => {
    const runtime = new AutoflowRuntime();
    const orchestrator = new AutoflowOrchestrator(runtime);
    // No public key holds the runtime, and nothing enumerable equals it.
    const surface = orchestrator as unknown as Record<string, unknown>;
    for (const key of Object.keys(surface)) {
      expect(surface[key]).not.toBe(runtime);
    }
    // The private #runtime field is not reachable as a public property.
    expect(surface['runtime']).toBeUndefined();
    expect(surface['_runtime']).toBeUndefined();
    // The only outward capability is the reader, which cannot open/apply.
    const reader = orchestrator.reader() as unknown as Record<string, unknown>;
    expect(reader['open']).toBeUndefined();
    expect(reader['apply']).toBeUndefined();
  });

  it('the orchestrator public method surface carries exactly open, openHumanGate and reader', () => {
    const proto = Object.getPrototypeOf(new AutoflowOrchestrator(new AutoflowRuntime())) as object;
    const methods = Object.getOwnPropertyNames(proto).filter((n) => n !== 'constructor');
    // Structurally narrow: a startup human-gate verb, but NO generic apply(event).
    expect(methods.sort()).toEqual(['open', 'openHumanGate', 'reader']);
    expect(methods).not.toContain('apply');
  });
});

describe('AutoflowOrchestrator.openHumanGate (Decision 061 — startup-scripted human-gate)', () => {
  it('OPEN → APPLIED, AWAITING_HUMAN_DECISION at sequence 1, gate at revision 0', () => {
    const runtime = new AutoflowRuntime();
    const orchestrator = new AutoflowOrchestrator(runtime);
    orchestrator.open(BINDING);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);
    expect(runtime.current()?.sequence).toBe(0);

    const result = orchestrator.openHumanGate();
    expect(result.outcome).toBe(TRANSITION_OUTCOME.APPLIED);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.AWAITING_HUMAN_DECISION);
    expect(runtime.current()?.sequence).toBe(1);
    expect(runtime.current()?.humanGateOpenedAtRevision).toBe(0);
  });

  it('binds the event to the workflow\'s own authoritative boundCommitSha (no external SHA)', () => {
    const runtime = new AutoflowRuntime();
    const orchestrator = new AutoflowOrchestrator(runtime);
    orchestrator.open(BINDING); // boundCommitSha === SHA_A
    const result = orchestrator.openHumanGate();
    // APPLIED proves the internally-minted atCommitSha matched boundCommitSha;
    // a mismatched SHA would have produced BINDING_MISMATCH.
    expect(result.outcome).toBe(TRANSITION_OUTCOME.APPLIED);
    expect(runtime.current()?.boundCommitSha).toBe(SHA_A);
  });

  it('with no workflow open, does not manufacture one — returns NO_WORKFLOW, state stays null', () => {
    const runtime = new AutoflowRuntime();
    const orchestrator = new AutoflowOrchestrator(runtime);
    expect(runtime.current()).toBeNull();
    const result = orchestrator.openHumanGate();
    expect(result.outcome).toBe(AUTOFLOW_APPLY_NO_WORKFLOW);
    expect(result.state).toBeNull();
    expect(runtime.current()).toBeNull();
  });

  it('a second call rejects HUMAN_GATE_ALREADY_OPEN and preserves the exact state', () => {
    const runtime = new AutoflowRuntime();
    const orchestrator = new AutoflowOrchestrator(runtime);
    orchestrator.open(BINDING);
    orchestrator.openHumanGate();
    const gatedState = runtime.current();

    const second = orchestrator.openHumanGate();
    expect(second.outcome).toBe(TRANSITION_OUTCOME.REJECTED);
    if (second.outcome === TRANSITION_OUTCOME.REJECTED) {
      expect(second.rejection).toBe(TRANSITION_REJECTION.HUMAN_GATE_ALREADY_OPEN);
    }
    // Provable no-op: same frozen reference, unchanged sequence.
    expect(runtime.current()).toBe(gatedState);
    expect(runtime.current()?.sequence).toBe(1);
  });

  it('does not expose a generic apply(event) surface', () => {
    const orchestrator = new AutoflowOrchestrator(new AutoflowRuntime()) as unknown as Record<
      string,
      unknown
    >;
    expect(orchestrator['apply']).toBeUndefined();
    expect('apply' in orchestrator).toBe(false);
  });
});

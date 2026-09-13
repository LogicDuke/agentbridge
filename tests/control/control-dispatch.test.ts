import { describe, expect, it } from 'vitest';

import { AutoflowOrchestrator } from '../../src/autoflow/orchestrator.js';
import { AutoflowRuntime } from '../../src/autoflow/runtime.js';
import { WORKFLOW_STATUS, type WorkflowBinding } from '../../src/domain/index.js';
import { CONTROL_COMMAND, CONTROL_RESULT } from '../../src/control/control-command.js';
import { createControlDispatcher } from '../../src/control/control-dispatch.js';

const REPO = 'repo-agentbridge';
const SHA = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
const BINDING: WorkflowBinding = { workflowId: 'wf-d062-0001', repositoryId: REPO, boundCommitSha: SHA };

const COMMAND = { command: CONTROL_COMMAND.OPEN_HUMAN_GATE } as const;

describe('D062 dispatcher — the one narrow write-path capability', () => {
  it('with no workflow open, returns NO_WORKFLOW and manufactures nothing', () => {
    const runtime = new AutoflowRuntime();
    const dispatcher = createControlDispatcher(new AutoflowOrchestrator(runtime));
    expect(dispatcher.dispatch(COMMAND)).toBe(CONTROL_RESULT.NO_WORKFLOW);
    expect(runtime.current()).toBeNull();
  });

  it('with a workflow open, OPEN_HUMAN_GATE progresses through the orchestrator to APPLIED', () => {
    const runtime = new AutoflowRuntime();
    const orchestrator = new AutoflowOrchestrator(runtime);
    orchestrator.open(BINDING);
    const dispatcher = createControlDispatcher(orchestrator);
    expect(dispatcher.dispatch(COMMAND)).toBe(CONTROL_RESULT.APPLIED);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.AWAITING_HUMAN_DECISION);
    expect(runtime.current()?.sequence).toBe(1);
  });

  it('a duplicate open returns GATE_ALREADY_OPEN and leaves state unchanged', () => {
    const runtime = new AutoflowRuntime();
    const orchestrator = new AutoflowOrchestrator(runtime);
    orchestrator.open(BINDING);
    const dispatcher = createControlDispatcher(orchestrator);
    expect(dispatcher.dispatch(COMMAND)).toBe(CONTROL_RESULT.APPLIED);
    const gated = runtime.current();
    expect(dispatcher.dispatch(COMMAND)).toBe(CONTROL_RESULT.GATE_ALREADY_OPEN);
    // Provable no-op: same frozen reference.
    expect(runtime.current()).toBe(gated);
    expect(runtime.current()?.sequence).toBe(1);
  });

  it('exposes only dispatch, is frozen, and does not leak the orchestrator/runtime', () => {
    const runtime = new AutoflowRuntime();
    const orchestrator = new AutoflowOrchestrator(runtime);
    const dispatcher = createControlDispatcher(orchestrator);
    expect(Object.isFrozen(dispatcher)).toBe(true);
    const surface = dispatcher as unknown as Record<string, unknown>;
    expect(Object.keys(surface)).toEqual(['dispatch']);
    for (const key of Object.keys(surface)) {
      expect(surface[key]).not.toBe(orchestrator);
      expect(surface[key]).not.toBe(runtime);
    }
    expect('open' in surface).toBe(false);
    expect('apply' in surface).toBe(false);
    expect('reader' in surface).toBe(false);
    expect('openHumanGate' in surface).toBe(false);
  });
});

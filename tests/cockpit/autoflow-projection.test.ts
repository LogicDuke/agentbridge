import { describe, expect, it } from 'vitest';

import {
  projectCockpitAutoflow,
  type CockpitAutoflowProjection,
} from '../../src/cockpit/autoflow-projection.js';
import type { WorkflowState } from '../../src/domain/index.js';
import {
  admitEvidence,
  admitReview,
  applyOrThrow,
  buildInvocation,
  buildReport,
  closeWorkflow,
  openedWorkflow,
  openHumanGate,
  reportInvocation,
  requestInvocation,
  SHA_A,
} from '../domain/workflow-fixtures.js';

/* -------------------------------------------------------------------------
 * Every input is a real WorkflowState produced by the PR 007 state machine
 * (D4's Option-A trust boundary). Tests may drive `openWorkflow` /
 * `applyWorkflowEvent`; the production projection consumes only WorkflowState.
 * ------------------------------------------------------------------------- */

/** OPEN workflow with one REQUESTED and one REPORTED invocation, plus admissions. */
function mixedWorkflow(): WorkflowState {
  let state = openedWorkflow();
  state = applyOrThrow(state, requestInvocation(buildInvocation({ invocationId: 'inv-1' })));
  state = applyOrThrow(state, requestInvocation(buildInvocation({ invocationId: 'inv-2' })));
  state = applyOrThrow(state, reportInvocation(buildReport({ invocationId: 'inv-1' })));
  state = applyOrThrow(state, admitEvidence());
  state = applyOrThrow(state, admitReview());
  return state;
}

describe('projectCockpitAutoflow — status coverage', () => {
  it('1. projects an OPEN workflow verbatim', () => {
    const projection = projectCockpitAutoflow(openedWorkflow());
    expect(projection.status).toBe('OPEN');
    expect(projection.closureReason).toBeNull();
    expect(projection.humanGateOpenedAtRevision).toBeNull();
    expect(projection.invocations).toEqual([]);
    expect(projection.counts).toEqual({
      invocationsTotal: 0,
      requested: 0,
      reported: 0,
      evidenceAdmissions: 0,
      reviewAdmissions: 0,
    });
  });

  it('2. projects an AWAITING_HUMAN_DECISION workflow and preserves the gate revision', () => {
    const state = applyOrThrow(openedWorkflow(), openHumanGate(SHA_A));
    const projection = projectCockpitAutoflow(state);
    expect(projection.status).toBe('AWAITING_HUMAN_DECISION');
    // Gate opened at the bound commit's revision (0); preserved verbatim.
    expect(projection.humanGateOpenedAtRevision).toBe(state.revision);
    expect(projection.humanGateOpenedAtRevision).toBe(0);
  });

  it('3. projects a CLOSED workflow with its closure reason', () => {
    const state = applyOrThrow(openedWorkflow(), closeWorkflow('CALLER_CLOSED'));
    const projection = projectCockpitAutoflow(state);
    expect(projection.status).toBe('CLOSED');
    expect(projection.closureReason).toBe('CALLER_CLOSED');
  });
});

describe('projectCockpitAutoflow — direct facts', () => {
  it('4. preserves exact revision and sequence', () => {
    const state = mixedWorkflow();
    const projection = projectCockpitAutoflow(state);
    expect(projection.revision).toBe(state.revision);
    expect(projection.sequence).toBe(state.sequence);
  });

  it('5. echoes identity, binding, and pull request verbatim', () => {
    const state = mixedWorkflow();
    const projection = projectCockpitAutoflow(state);
    expect(projection.workflowId).toBe(state.workflowId);
    expect(projection.repositoryId).toBe(state.repositoryId);
    expect(projection.pullRequestId).toBe(state.pullRequestId);
    expect(projection.boundCommitSha).toBe(state.boundCommitSha);
  });
});

describe('projectCockpitAutoflow — invocations', () => {
  it('6. projects a REQUESTED invocation with null reported counters', () => {
    const state = applyOrThrow(
      openedWorkflow(),
      requestInvocation(buildInvocation({ invocationId: 'inv-1' })),
    );
    const projection = projectCockpitAutoflow(state);
    expect(projection.invocations).toHaveLength(1);
    const invocation = projection.invocations[0] as CockpitAutoflowProjection['invocations'][number];
    expect(invocation.invocationId).toBe('inv-1');
    expect(invocation.state).toBe('REQUESTED');
    expect(invocation.reportedStatus).toBeNull();
    expect(invocation.reportedAtRevision).toBeNull();
    expect(invocation.reportedAtSequence).toBeNull();
  });

  it('7. projects a REPORTED invocation carrying its reported status and counters', () => {
    let state = applyOrThrow(
      openedWorkflow(),
      requestInvocation(buildInvocation({ invocationId: 'inv-1' })),
    );
    state = applyOrThrow(state, reportInvocation(buildReport({ invocationId: 'inv-1' })));
    const projection = projectCockpitAutoflow(state);
    const invocation = projection.invocations[0] as CockpitAutoflowProjection['invocations'][number];
    expect(invocation.state).toBe('REPORTED');
    expect(invocation.reportedStatus).toBe('reported-complete');
    expect(invocation.reportedAtRevision).not.toBeNull();
    expect(invocation.reportedAtSequence).not.toBeNull();
  });

  it('8. counts mixed invocation states correctly', () => {
    const projection = projectCockpitAutoflow(mixedWorkflow());
    expect(projection.counts.invocationsTotal).toBe(2);
    expect(projection.counts.requested).toBe(1);
    expect(projection.counts.reported).toBe(1);
  });

  it('9. preserves invocation order (never sorted or deduplicated)', () => {
    const projection = projectCockpitAutoflow(mixedWorkflow());
    expect(projection.invocations.map((invocation) => invocation.invocationId)).toEqual([
      'inv-1',
      'inv-2',
    ]);
  });

  it('10. reports admission counts equal to the workflow admission-list lengths', () => {
    const state = mixedWorkflow();
    const projection = projectCockpitAutoflow(state);
    expect(projection.counts.evidenceAdmissions).toBe(state.evidence.length);
    expect(projection.counts.reviewAdmissions).toBe(state.reviews.length);
    expect(projection.counts.evidenceAdmissions).toBe(1);
    expect(projection.counts.reviewAdmissions).toBe(1);
  });
});

describe('projectCockpitAutoflow — determinism and immutability', () => {
  it('14. is deterministic: same input yields deep-equal output', () => {
    const state = mixedWorkflow();
    expect(projectCockpitAutoflow(state)).toEqual(projectCockpitAutoflow(state));
  });

  it('15. survives a JSON round trip unchanged', () => {
    const projection = projectCockpitAutoflow(mixedWorkflow());
    expect(JSON.parse(JSON.stringify(projection))).toEqual(projection);
  });

  it('12. does not mutate the source workflow state', () => {
    const state = mixedWorkflow();
    const before = JSON.stringify(state);
    projectCockpitAutoflow(state);
    expect(JSON.stringify(state)).toBe(before);
    expect(Object.isFrozen(state)).toBe(true);
  });
});

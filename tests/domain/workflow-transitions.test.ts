/**
 * Behavioural tests for the Autoflow state machine.
 *
 * Expected vocabulary values are bare string literals so the suite cannot
 * ratify a production mapping that has been changed incorrectly.
 */

import { describe, expect, it } from 'vitest';

import {
  applyWorkflowEvent,
  evaluateEvidenceFreshness,
  ingestInvocationReport,
  ingestReview,
  openWorkflow,
  type AgentInvocation,
  type EvidenceRecord,
  type ReviewContext,
  type WorkflowEvent,
  type WorkflowState,
} from '../../src/domain/index.js';
import {
  admitEvidence,
  admitReview,
  applyOrThrow,
  buildBinding,
  buildBindingWithoutPullRequest,
  buildHumanDecisionVerdict,
  buildInvocation,
  buildInvocationWithoutPullRequest,
  buildReport,
  buildReview,
  buildVerdict,
  closeWorkflow,
  EVIDENCE_A,
  EVIDENCE_B,
  INVOCATION_A,
  INVOCATION_B,
  label,
  MALFORMED_VALUES,
  NON_OBJECTS,
  observeHead,
  openedWorkflow,
  openHumanGate,
  oversized,
  PR_A,
  PR_B,
  REPO_A,
  REPO_B,
  reportInvocation,
  REQUESTED_AT,
  requestInvocation,
  REVIEW_A,
  REVIEW_B,
  SHA_A,
  SHA_B,
  SHA_C,
  UNSUPPORTED_EVENT_KINDS,
  WORKFLOW_A,
  withRawBindingField,
  withRawReportField,
  withRawReviewField,
  withRawVerdictField,
  withThrowingGetter,
} from './workflow-fixtures.js';

/** A workflow with one invocation already requested at the bound commit. */
function withRequestedInvocation(): WorkflowState {
  return applyOrThrow(openedWorkflow(), requestInvocation());
}

/** That workflow with a human gate open at the bound commit. */
function awaitingHuman(): WorkflowState {
  return applyOrThrow(withRequestedInvocation(), openHumanGate());
}

/** That workflow, closed. */
function closed(): WorkflowState {
  return applyOrThrow(withRequestedInvocation(), closeWorkflow());
}

describe('openWorkflow — group A, construction', () => {
  it('opens at revision 0 and sequence 0 with empty lists', () => {
    const result = openWorkflow(buildBinding());

    expect(result.outcome).toBe('APPLIED');
    expect(result.rejection).toBeNull();
    expect(result.invalidFields).toEqual([]);
    expect(result.state).toEqual({
      workflowId: WORKFLOW_A,
      repositoryId: REPO_A,
      pullRequestId: PR_A,
      boundCommitSha: SHA_A,
      revision: 0,
      sequence: 0,
      status: 'OPEN',
      closureReason: null,
      humanGateOpenedAtRevision: null,
      invocations: [],
      evidence: [],
      reviews: [],
    });
  });

  it('records an absent pull request as null', () => {
    const result = openWorkflow(buildBindingWithoutPullRequest());

    expect(result.outcome).toBe('APPLIED');
    expect(result.state?.pullRequestId).toBeNull();
  });

  it('deeply freezes the opened state', () => {
    const state = openedWorkflow();

    expect(Object.isFrozen(state)).toBe(true);
    expect(Object.isFrozen(state.invocations)).toBe(true);
    expect(Object.isFrozen(state.evidence)).toBe(true);
    expect(Object.isFrozen(state.reviews)).toBe(true);
  });

  it.each(['workflowId', 'repositoryId', 'boundCommitSha'])(
    'rejects a binding whose %s is missing',
    (field) => {
      const result = openWorkflow(withRawBindingField(field, undefined));

      expect(result.outcome).toBe('REJECTED');
      expect(result.state).toBeNull();
      expect(result.rejection).toBe('WORKFLOW_UNREADABLE');
      expect(result.invalidFields).toEqual([`binding.${field}`]);
    },
  );

  it.each(MALFORMED_VALUES)('rejects a workflowId that is %s', (_name, value) => {
    const result = openWorkflow(withRawBindingField('workflowId', value));

    expect(result.outcome).toBe('REJECTED');
    expect(result.invalidFields).toEqual(['binding.workflowId']);
  });

  it('rejects an oversized identifier rather than truncating it', () => {
    const long = oversized(257);
    const result = openWorkflow(withRawBindingField('boundCommitSha', long));

    expect(result.outcome).toBe('REJECTED');
    expect(result.state).toBeNull();
    expect(JSON.stringify(result)).not.toContain(long.slice(0, 32));
  });

  it('accepts an identifier of exactly the bound', () => {
    const result = openWorkflow(withRawBindingField('workflowId', oversized(256)));

    expect(result.outcome).toBe('APPLIED');
  });

  it('rejects a present but invalid pullRequestId — binding is all-or-nothing', () => {
    const result = openWorkflow(withRawBindingField('pullRequestId', 42));

    expect(result.outcome).toBe('REJECTED');
    expect(result.invalidFields).toEqual(['binding.pullRequestId']);
  });

  it.each(NON_OBJECTS)('rejects a binding that is %s', (_name, value) => {
    const result = openWorkflow(value as never);

    expect(result.outcome).toBe('REJECTED');
    expect(result.rejection).toBe('WORKFLOW_UNREADABLE');
    expect(result.invalidFields).toEqual([
      'binding.workflowId',
      'binding.repositoryId',
      'binding.boundCommitSha',
    ]);
  });

  it('reports every invalid field in declaration order', () => {
    const result = openWorkflow({
      workflowId: '',
      repositoryId: '',
      pullRequestId: 7,
      boundCommitSha: '',
    } as never);

    expect(result.invalidFields).toEqual([
      'binding.workflowId',
      'binding.repositoryId',
      'binding.pullRequestId',
      'binding.boundCommitSha',
    ]);
  });
});

describe('applyWorkflowEvent — group B, transition matrix', () => {
  const cases: readonly (readonly [string, () => WorkflowEvent, string, string | null])[] = [
    [
      'INVOCATION_REQUESTED',
      () => requestInvocation(buildInvocation({ invocationId: INVOCATION_B })),
      'OPEN',
      null,
    ],
    ['INVOCATION_REPORTED', () => reportInvocation(), 'OPEN', null],
    ['REVIEW_ADMITTED', () => admitReview(), 'OPEN', null],
    ['EVIDENCE_ADMITTED', () => admitEvidence(), 'OPEN', null],
    [
      'EVIDENCE_ADMITTED human-decision',
      () => admitEvidence(buildHumanDecisionVerdict()),
      'OPEN',
      null,
    ],
    ['HEAD_OBSERVED different', () => observeHead(SHA_B), 'OPEN', null],
    ['HUMAN_GATE_OPENED', () => openHumanGate(), 'AWAITING_HUMAN_DECISION', null],
    ['CLOSE_REQUESTED', () => closeWorkflow(), 'CLOSED', null],
  ];

  it.each(cases)('OPEN accepts %s', (_name, build, expectedStatus) => {
    const result = applyWorkflowEvent(withRequestedInvocation(), build());

    expect(result.outcome).toBe('APPLIED');
    expect(result.state.status).toBe(expectedStatus);
    expect(result.rejection).toBeNull();
  });

  it('OPEN refuses HEAD_OBSERVED at the same commit', () => {
    const result = applyWorkflowEvent(withRequestedInvocation(), observeHead(SHA_A));

    expect(result.outcome).toBe('REJECTED');
    expect(result.rejection).toBe('HEAD_UNCHANGED');
  });

  const awaitingCases: readonly (readonly [string, () => WorkflowEvent, string | null])[] = [
    [
      'INVOCATION_REQUESTED',
      () => requestInvocation(buildInvocation({ invocationId: INVOCATION_B })),
      'WORKFLOW_AWAITING_HUMAN',
    ],
    ['INVOCATION_REPORTED', () => reportInvocation(), null],
    ['REVIEW_ADMITTED', () => admitReview(), null],
    ['EVIDENCE_ADMITTED', () => admitEvidence(), null],
    [
      'EVIDENCE_ADMITTED human-decision',
      () => admitEvidence(buildHumanDecisionVerdict()),
      null,
    ],
    ['HEAD_OBSERVED different', () => observeHead(SHA_B), null],
    ['HEAD_OBSERVED same', () => observeHead(SHA_A), 'HEAD_UNCHANGED'],
    ['HUMAN_GATE_OPENED', () => openHumanGate(), 'HUMAN_GATE_ALREADY_OPEN'],
    ['CLOSE_REQUESTED', () => closeWorkflow(), null],
  ];

  it.each(awaitingCases)(
    'AWAITING_HUMAN_DECISION handles %s',
    (_name, build, expectedRejection) => {
      const state = awaitingHuman();
      const result = applyWorkflowEvent(state, build());

      if (expectedRejection === null) {
        expect(result.outcome).toBe('APPLIED');
      } else {
        expect(result.outcome).toBe('REJECTED');
        expect(result.rejection).toBe(expectedRejection);
        expect(result.state).toBe(state);
      }
    },
  );

  const everyEvent: readonly (readonly [string, () => WorkflowEvent])[] = [
    [
      'INVOCATION_REQUESTED',
      () => requestInvocation(buildInvocation({ invocationId: INVOCATION_B })),
    ],
    ['INVOCATION_REPORTED', () => reportInvocation()],
    ['REVIEW_ADMITTED', () => admitReview()],
    ['EVIDENCE_ADMITTED', () => admitEvidence()],
    ['EVIDENCE_ADMITTED human-decision', () => admitEvidence(buildHumanDecisionVerdict())],
    ['HEAD_OBSERVED different', () => observeHead(SHA_B)],
    ['HEAD_OBSERVED same', () => observeHead(SHA_A)],
    ['HUMAN_GATE_OPENED', () => openHumanGate()],
    ['CLOSE_REQUESTED', () => closeWorkflow()],
  ];

  it.each(everyEvent)('CLOSED refuses %s', (_name, build) => {
    const state = closed();
    const result = applyWorkflowEvent(state, build());

    expect(result.outcome).toBe('REJECTED');
    expect(result.rejection).toBe('WORKFLOW_CLOSED');
    expect(result.invalidFields).toEqual(['workflow.status']);
    expect(result.state).toBe(state);
  });

  it('CLOSED is terminal: there is no reopen', () => {
    const state = closed();

    expect(state.status).toBe('CLOSED');
    expect(state.closureReason).toBe('CALLER_CLOSED');
    expect(applyWorkflowEvent(state, openHumanGate()).state).toBe(state);
  });
});

describe('applyWorkflowEvent — group C, invocation lifecycle', () => {
  it('tracks a requested invocation with its own commit and inert labels', () => {
    const state = withRequestedInvocation();

    expect(state.sequence).toBe(1);
    expect(state.invocations).toHaveLength(1);
    expect(state.invocations[0]).toEqual({
      invocationId: INVOCATION_A,
      targetCommitSha: SHA_A,
      purpose: 'review',
      providerId: 'codex',
      agentId: 'agent-1',
      requestedAtRevision: 0,
      requestedAtSequence: 1,
      state: 'REQUESTED',
      reportedStatus: null,
      reportedAtRevision: null,
      reportedAtSequence: null,
    });
  });

  it('does not store the caller-supplied requestedAt timestamp', () => {
    expect(JSON.stringify(withRequestedInvocation())).not.toContain(REQUESTED_AT);
  });

  it('moves a requested invocation to REPORTED in place', () => {
    const state = applyOrThrow(
      applyOrThrow(withRequestedInvocation(), requestInvocation(
        buildInvocation({ invocationId: INVOCATION_B }),
      )),
      reportInvocation(),
    );

    expect(state.invocations[0]?.invocationId).toBe(INVOCATION_A);
    expect(state.invocations[0]?.state).toBe('REPORTED');
    expect(state.invocations[0]?.reportedStatus).toBe('reported-complete');
    expect(state.invocations[0]?.reportedAtSequence).toBe(3);
    expect(state.invocations[1]?.invocationId).toBe(INVOCATION_B);
    expect(state.invocations[1]?.state).toBe('REQUESTED');
  });

  it('refuses a duplicate invocation id', () => {
    const state = withRequestedInvocation();
    const result = applyWorkflowEvent(state, requestInvocation());

    expect(result.rejection).toBe('DUPLICATE_INVOCATION_ID');
    expect(result.state).toBe(state);
  });

  it('refuses a duplicate invocation id at a later revision too', () => {
    const moved = applyOrThrow(withRequestedInvocation(), observeHead(SHA_B));
    const result = applyWorkflowEvent(
      moved,
      requestInvocation(buildInvocation({ targetCommitSha: SHA_B })),
    );

    expect(result.rejection).toBe('DUPLICATE_INVOCATION_ID');
  });

  it('rejects a deserialized state with duplicate tracked invocation ids', () => {
    const state = withRequestedInvocation();
    // Frozen, as every collection this layer emits is: an unfrozen list is
    // refused at the frozen-list gate before the duplicate-id scan ever runs,
    // which would leave this assertion green for the wrong reason.
    const duplicateState = {
      ...state,
      invocations: Object.freeze([state.invocations[0], state.invocations[0]]),
    } as WorkflowState;
    const result = applyWorkflowEvent(duplicateState, reportInvocation());

    expect(result.outcome).toBe('REJECTED');
    expect(result.rejection).toBe('WORKFLOW_UNREADABLE');
    expect(result.state).toBe(duplicateState);

    // The same frozen shape without the duplicate is accepted, so the rejection
    // above is caused by the duplicate identity rather than the freeze gate.
    const uniqueState = {
      ...state,
      invocations: Object.freeze([state.invocations[0]]),
    } as WorkflowState;

    expect(applyWorkflowEvent(uniqueState, reportInvocation()).outcome).toBe('APPLIED');
  });

  it('refuses a report for an invocation it never requested', () => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      reportInvocation(buildReport({ invocationId: INVOCATION_B })),
    );

    expect(result.rejection).toBe('UNKNOWN_INVOCATION');
  });

  it('refuses a replayed report', () => {
    const reported = applyOrThrow(withRequestedInvocation(), reportInvocation());
    const result = applyWorkflowEvent(reported, reportInvocation());

    expect(result.rejection).toBe('INVOCATION_ALREADY_REPORTED');
    expect(result.state).toBe(reported);
  });

  it('refuses a report whose upstream ingestion failed', () => {
    const result = applyWorkflowEvent(
      withRequestedInvocation(),
      reportInvocation(buildReport({ outcome: 'INVOCATION_INVALID' })),
    );

    expect(result.rejection).toBe('INPUT_NOT_INGESTED');
    expect(result.invalidFields).toEqual(['report.outcome']);
  });

  it('refuses a report bound to a different repository', () => {
    const result = applyWorkflowEvent(
      withRequestedInvocation(),
      reportInvocation(buildReport({ repositoryId: REPO_B })),
    );

    expect(result.rejection).toBe('BINDING_MISMATCH');
    expect(result.invalidFields).toEqual(['report.repositoryId']);
  });

  it('refuses a report bound to a different commit than its invocation', () => {
    const result = applyWorkflowEvent(
      withRequestedInvocation(),
      reportInvocation(buildReport({ targetCommitSha: SHA_C })),
    );

    expect(result.rejection).toBe('BINDING_MISMATCH');
    expect(result.invalidFields).toEqual(['report.targetCommitSha']);
  });

  it('records a report that arrives after HEAD moved, bound to its own commit', () => {
    const moved = applyOrThrow(withRequestedInvocation(), observeHead(SHA_B));
    const result = applyWorkflowEvent(moved, reportInvocation());

    expect(result.outcome).toBe('APPLIED');
    expect(result.state.boundCommitSha).toBe(SHA_B);
    expect(result.state.invocations[0]?.targetCommitSha).toBe(SHA_A);
    expect(result.state.invocations[0]?.state).toBe('REPORTED');
    expect(result.state.invocations[0]?.reportedAtRevision).toBe(1);
    expect(result.state.evidence).toEqual([]);
  });

  it('accepts a report while a human gate is open', () => {
    const result = applyWorkflowEvent(awaitingHuman(), reportInvocation());

    expect(result.outcome).toBe('APPLIED');
    expect(result.state.status).toBe('AWAITING_HUMAN_DECISION');
  });

  it.each(['reported-complete', 'reported-failed', 'reported-cancelled', 'unknown'])(
    'carries reportedStatus %s verbatim',
    (status) => {
      const state = applyOrThrow(
        withRequestedInvocation(),
        reportInvocation(buildReport({ reportedStatus: status as never })),
      );

      expect(state.invocations[0]?.reportedStatus).toBe(status);
    },
  );

  it('fails an unrecognised reported status closed to unknown', () => {
    const state = applyOrThrow(
      withRequestedInvocation(),
      reportInvocation(withRawReportField('reportedStatus', 'COMPLETE')),
    );

    expect(state.invocations[0]?.reportedStatus).toBe('unknown');
  });
});

describe('applyWorkflowEvent — group D, HEAD, revision, and the A1 gate clear', () => {
  it('rebinds and advances the revision, leaving history in place', () => {
    const state = applyOrThrow(
      applyOrThrow(withRequestedInvocation(), admitEvidence()),
      observeHead(SHA_B),
    );

    expect(state.boundCommitSha).toBe(SHA_B);
    expect(state.revision).toBe(1);
    expect(state.sequence).toBe(3);
    expect(state.evidence).toHaveLength(1);
    expect(state.evidence[0]?.admittedAtRevision).toBe(0);
    expect(state.evidence[0]?.admittedAtCommitSha).toBe(SHA_A);
    expect(state.invocations[0]?.state).toBe('REQUESTED');
    expect(state.invocations[0]?.targetCommitSha).toBe(SHA_A);
  });

  it.each(MALFORMED_VALUES)('refuses an observed head that is %s', (_name, value) => {
    const result = applyWorkflowEvent(openedWorkflow(), {
      kind: 'HEAD_OBSERVED',
      observedCommitSha: value,
    } as never);

    expect(result.rejection).toBe('EVENT_PAYLOAD_INVALID');
    expect(result.invalidFields).toEqual(['event.observedCommitSha']);
  });

  it('refuses an oversized observed head', () => {
    const result = applyWorkflowEvent(openedWorkflow(), observeHead(oversized(257)));

    expect(result.rejection).toBe('EVENT_PAYLOAD_INVALID');
  });

  it('does not increment the sequence on a refused HEAD_OBSERVED', () => {
    const state = openedWorkflow();
    const result = applyWorkflowEvent(state, observeHead(SHA_A));

    expect(result.state.sequence).toBe(0);
    expect(result.state.revision).toBe(0);
  });

  it('advances the revision even when HEAD returns to a previous commit', () => {
    const first = applyOrThrow(openedWorkflow(), admitEvidence());
    const moved = applyOrThrow(first, observeHead(SHA_B));
    const back = applyOrThrow(moved, observeHead(SHA_A));

    expect(back.revision).toBe(2);
    expect(back.boundCommitSha).toBe(SHA_A);
    expect(back.evidence).toHaveLength(1);
    expect(back.evidence[0]?.admittedAtRevision).toBe(0);
  });

  it('re-admits the same evidence id at a later revision as a fresh admission', () => {
    const first = applyOrThrow(openedWorkflow(), admitEvidence());
    const moved = applyOrThrow(first, observeHead(SHA_B));
    const back = applyOrThrow(moved, observeHead(SHA_A));
    const readmitted = applyOrThrow(back, admitEvidence());

    expect(readmitted.evidence).toHaveLength(2);
    expect(readmitted.evidence[0]?.admittedAtRevision).toBe(0);
    expect(readmitted.evidence[1]?.admittedAtRevision).toBe(2);
    expect(readmitted.evidence[1]?.evidenceId).toBe(EVIDENCE_A);
  });

  it('A1: a HEAD advance clears an open human gate', () => {
    const state = applyOrThrow(awaitingHuman(), observeHead(SHA_B));

    expect(state.status).toBe('OPEN');
    expect(state.humanGateOpenedAtRevision).toBeNull();
    expect(state.revision).toBe(1);
  });

  it('A1: a HEAD advance from OPEN leaves the gate field null', () => {
    const state = applyOrThrow(openedWorkflow(), observeHead(SHA_B));

    expect(state.status).toBe('OPEN');
    expect(state.humanGateOpenedAtRevision).toBeNull();
  });

  it('A1: work may be requested immediately after the clearing HEAD advance', () => {
    const cleared = applyOrThrow(awaitingHuman(), observeHead(SHA_B));
    const result = applyWorkflowEvent(
      cleared,
      requestInvocation(buildInvocation({ invocationId: INVOCATION_B, targetCommitSha: SHA_B })),
    );

    expect(result.outcome).toBe('APPLIED');
  });

  it('A1: a decision bound to the superseded commit cannot retroactively unblock', () => {
    const cleared = applyOrThrow(awaitingHuman(), observeHead(SHA_B));
    const reopened = applyOrThrow(cleared, openHumanGate(SHA_B));
    const result = applyWorkflowEvent(reopened, admitEvidence(buildHumanDecisionVerdict()));

    expect(result.rejection).toBe('EVIDENCE_NOT_CURRENT');
    expect(result.state.status).toBe('AWAITING_HUMAN_DECISION');
  });

  it('A1: the gate can be re-opened at the new revision', () => {
    const cleared = applyOrThrow(awaitingHuman(), observeHead(SHA_B));
    const reopened = applyOrThrow(cleared, openHumanGate(SHA_B));

    expect(reopened.status).toBe('AWAITING_HUMAN_DECISION');
    expect(reopened.humanGateOpenedAtRevision).toBe(1);
  });
});

describe('applyWorkflowEvent — group E, evidence admission and A2', () => {
  it('admits a CURRENT verdict judged against this binding', () => {
    const state = applyOrThrow(openedWorkflow(), admitEvidence());

    expect(state.evidence).toEqual([
      {
        evidenceId: EVIDENCE_A,
        kind: 'ci-result',
        admittedAtCommitSha: SHA_A,
        admittedAtRevision: 0,
        admittedAtSequence: 1,
      },
    ]);
  });

  it.each(['STALE', 'INVALID'])('refuses a %s verdict', (verdictState) => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      admitEvidence(withRawVerdictField('state', verdictState)),
    );

    expect(result.rejection).toBe('EVIDENCE_NOT_CURRENT');
    expect(result.invalidFields).toEqual(['verdict.state']);
  });

  it('refuses a forged CURRENT verdict whose reason does not agree', () => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      admitEvidence(buildVerdict({ reason: 'COMMIT_SHA_MISMATCH' })),
    );

    expect(result.rejection).toBe('EVIDENCE_NOT_CURRENT');
    expect(result.invalidFields).toEqual(['verdict.reason']);
  });

  it('refuses a verdict judged against a different head', () => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      admitEvidence(buildVerdict({ targetHeadSha: SHA_B })),
    );

    expect(result.rejection).toBe('EVIDENCE_NOT_CURRENT');
    expect(result.invalidFields).toEqual(['verdict.targetHeadSha']);
  });

  it('refuses a verdict judged against a different repository', () => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      admitEvidence(buildVerdict({ targetRepositoryId: REPO_B })),
    );

    expect(result.rejection).toBe('EVIDENCE_NOT_CURRENT');
    expect(result.invalidFields).toEqual(['verdict.targetRepositoryId']);
  });

  it.each([
    ['repository', { repositoryId: REPO_B }, ['verdict.repositoryId']],
    ['commit', { commitSha: SHA_B }, ['verdict.commitSha']],
    [
      'repository and commit',
      { repositoryId: REPO_B, commitSha: SHA_B },
      ['verdict.repositoryId', 'verdict.commitSha'],
    ],
  ] as const)('refuses CURRENT evidence whose own %s binding is stale', (_name, overrides, fields) => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      admitEvidence(buildVerdict(overrides)),
    );

    expect(result.rejection).toBe('EVIDENCE_NOT_CURRENT');
    expect(result.invalidFields).toEqual(fields);
  });

  it('does not let a cross-repository human decision clear an open gate', () => {
    const state = awaitingHuman();
    const result = applyWorkflowEvent(
      state,
      admitEvidence(buildHumanDecisionVerdict({ repositoryId: REPO_B })),
    );

    expect(result.rejection).toBe('EVIDENCE_NOT_CURRENT');
    expect(result.state).toBe(state);
    expect(result.state.status).toBe('AWAITING_HUMAN_DECISION');
  });

  it.each(MALFORMED_VALUES)('refuses a verdict whose evidenceId is %s', (_name, value) => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      admitEvidence(withRawVerdictField('evidenceId', value)),
    );

    expect(result.rejection).toBe('EVENT_PAYLOAD_INVALID');
    expect(result.invalidFields).toContain('verdict.evidenceId');
  });

  it('refuses a verdict whose kind is outside the PR 004 vocabulary', () => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      admitEvidence(withRawVerdictField('kind', 'merge-approval')),
    );

    expect(result.rejection).toBe('EVENT_PAYLOAD_INVALID');
    expect(result.invalidFields).toEqual(['verdict.kind']);
  });

  it('refuses a duplicate admission at the same revision', () => {
    const state = applyOrThrow(openedWorkflow(), admitEvidence());
    const result = applyWorkflowEvent(state, admitEvidence());

    expect(result.rejection).toBe('DUPLICATE_ADMISSION');
    expect(result.state).toBe(state);
  });

  it('admits a different evidence id at the same revision', () => {
    const state = applyOrThrow(
      applyOrThrow(openedWorkflow(), admitEvidence()),
      admitEvidence(buildVerdict({ evidenceId: EVIDENCE_B })),
    );

    expect(state.evidence).toHaveLength(2);
  });

  it('clears an open gate on a human-decision admission', () => {
    const state = applyOrThrow(awaitingHuman(), admitEvidence(buildHumanDecisionVerdict()));

    expect(state.status).toBe('OPEN');
    expect(state.humanGateOpenedAtRevision).toBeNull();
    expect(state.evidence[0]?.kind).toBe('human-decision');
  });

  it('leaves an OPEN workflow open on a human-decision admission', () => {
    const state = applyOrThrow(openedWorkflow(), admitEvidence(buildHumanDecisionVerdict()));

    expect(state.status).toBe('OPEN');
  });

  it.each(['ci-result', 'code-review', 'security-review', 'test-result', 'repository-state'])(
    'does not let a %s admission clear a human gate',
    (kind) => {
      const state = applyOrThrow(
        awaitingHuman(),
        admitEvidence(buildVerdict({ kind: kind as never })),
      );

      expect(state.status).toBe('AWAITING_HUMAN_DECISION');
      expect(state.humanGateOpenedAtRevision).toBe(0);
    },
  );

  it('A2: an admission keeps its commit binding after HEAD moves', () => {
    const admitted = applyOrThrow(openedWorkflow(), admitEvidence());
    const moved = applyOrThrow(admitted, observeHead(SHA_B));
    const later = applyOrThrow(
      moved,
      admitEvidence(
        buildVerdict({ evidenceId: EVIDENCE_B, commitSha: SHA_B, targetHeadSha: SHA_B }),
      ),
    );

    expect(later.evidence[0]?.admittedAtCommitSha).toBe(SHA_A);
    expect(later.evidence[1]?.admittedAtCommitSha).toBe(SHA_B);
  });
});

describe('applyWorkflowEvent — group F, review admission and A3', () => {
  it('admits a review bound to the current commit', () => {
    const state = applyOrThrow(openedWorkflow(), admitReview());

    expect(state.reviews).toEqual([
      {
        reviewId: REVIEW_A,
        admittedAtCommitSha: SHA_A,
        admittedAtRevision: 0,
        admittedAtSequence: 1,
      },
    ]);
  });

  it('refuses a review whose ingestion failed', () => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      admitReview(buildReview({ outcome: 'CONTEXT_INVALID' })),
    );

    expect(result.rejection).toBe('INPUT_NOT_INGESTED');
  });

  it('refuses a review bound to a superseded commit', () => {
    const moved = applyOrThrow(openedWorkflow(), observeHead(SHA_B));
    const result = applyWorkflowEvent(moved, admitReview());

    expect(result.rejection).toBe('BINDING_MISMATCH');
    expect(result.invalidFields).toEqual(['review.reviewedCommitSha']);
  });

  it('refuses a cross-repository review', () => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      admitReview(buildReview({ repositoryId: REPO_B })),
    );

    expect(result.rejection).toBe('BINDING_MISMATCH');
  });

  it('refuses a review for a different pull request', () => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      admitReview(buildReview({ pullRequestId: PR_B })),
    );

    expect(result.rejection).toBe('BINDING_MISMATCH');
    expect(result.invalidFields).toEqual(['review.pullRequestId']);
  });

  it('ignores a pull request when the workflow has none', () => {
    const result = applyWorkflowEvent(
      openedWorkflow(buildBindingWithoutPullRequest()),
      admitReview(buildReview({ pullRequestId: PR_B })),
    );

    expect(result.outcome).toBe('APPLIED');
  });

  it('refuses a review whose pull request is present but unreadable', () => {
    for (const value of [oversized(257), '', 42, {}, []]) {
      const result = applyWorkflowEvent(
        openedWorkflow(),
        admitReview(withRawReviewField('pullRequestId', value)),
      );

      expect(result.rejection, label(value)).toBe('BINDING_MISMATCH');
      expect(result.invalidFields).toEqual(['review.pullRequestId']);
    }
  });

  it('refuses a review whose pull request getter throws', () => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      admitReview(withThrowingGetter(buildReview(), 'pullRequestId')),
    );

    expect(result.rejection).toBe('BINDING_MISMATCH');
    expect(result.invalidFields).toEqual(['review.pullRequestId']);
  });

  it('refuses a report whose pull request is present but unreadable', () => {
    const result = applyWorkflowEvent(
      withRequestedInvocation(),
      reportInvocation(withRawReportField('pullRequestId', oversized(257))),
    );

    expect(result.rejection).toBe('BINDING_MISMATCH');
    expect(result.invalidFields).toEqual(['report.pullRequestId']);
  });

  it('still ignores an unreadable pull request when the workflow has none', () => {
    const result = applyWorkflowEvent(
      openedWorkflow(buildBindingWithoutPullRequest()),
      admitReview(withRawReviewField('pullRequestId', oversized(257))),
    );

    expect(result.outcome).toBe('APPLIED');
  });

  it('refuses an unattributable review', () => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      admitReview(buildReview({ reviewId: null })),
    );

    expect(result.rejection).toBe('EVENT_PAYLOAD_INVALID');
    expect(result.invalidFields).toEqual(['review.reviewId']);
  });

  it('refuses a duplicate admission at the same revision and allows one later', () => {
    const once = applyOrThrow(openedWorkflow(), admitReview());
    expect(applyWorkflowEvent(once, admitReview()).rejection).toBe('DUPLICATE_ADMISSION');

    const moved = applyOrThrow(once, observeHead(SHA_B));
    const again = applyOrThrow(
      moved,
      admitReview(buildReview({ reviewedCommitSha: SHA_B })),
    );

    expect(again.reviews).toHaveLength(2);
    expect(again.reviews[1]?.admittedAtRevision).toBe(1);
  });

  it('stores no finding content, count, or severity', () => {
    const findings = Array.from({ length: 25 }, (_value, index) => ({
      findingId: `f${String(index)}`,
      ordinal: index,
      repositoryId: REPO_A,
      pullRequestId: PR_A,
      reviewedCommitSha: SHA_A,
      reviewId: REVIEW_A,
      provider: 'coderabbit',
      reviewerId: 'reviewer-1',
      severity: 'blocking',
      classification: 'security',
      status: 'open',
      title: 'SENTINEL-TITLE',
      message: 'SENTINEL-MESSAGE',
      filePath: null,
      startLine: null,
      endLine: null,
      sourceId: null,
      providerFindingId: null,
      truncated: false,
    }));
    const state = applyOrThrow(
      openedWorkflow(),
      admitReview(withRawReviewField('findings', findings)),
    );
    const serialized = JSON.stringify(state);

    expect(state.reviews).toHaveLength(1);
    expect(serialized).not.toContain('SENTINEL-TITLE');
    expect(serialized).not.toContain('SENTINEL-MESSAGE');
    expect(serialized).not.toContain('blocking');
    expect(serialized).not.toContain('findingCount');
    expect(serialized).not.toContain('25');
  });

  it('A3: admits a review that matches no tracked invocation', () => {
    const state = applyOrThrow(
      openedWorkflow(),
      admitReview(buildReview({ reviewId: 'unsolicited-reviewer-7' })),
    );

    expect(state.reviews).toHaveLength(1);
    expect(state.invocations).toEqual([]);
  });

  it('A3: admitting a review transitions no invocation', () => {
    const before = withRequestedInvocation();
    const after = applyOrThrow(
      before,
      admitReview(buildReview({ reviewId: INVOCATION_A })),
    );

    expect(after.invocations).toEqual(before.invocations);
    expect(after.invocations[0]?.state).toBe('REQUESTED');
  });

  it('A3: records nothing distinguishing a requested review from an unsolicited one', () => {
    const base = withRequestedInvocation();
    const solicited = applyOrThrow(base, admitReview(buildReview({ reviewId: INVOCATION_A })));
    const unsolicited = applyOrThrow(
      base,
      admitReview(buildReview({ reviewId: 'forge-auto-review' })),
    );
    const solicitedAdmission = solicited.reviews[0];
    const unsolicitedAdmission = unsolicited.reviews[0];

    expect(solicitedAdmission).toBeDefined();
    expect(unsolicitedAdmission).toBeDefined();
    expect({ ...solicitedAdmission, reviewId: 'x' }).toEqual({
      ...unsolicitedAdmission,
      reviewId: 'x',
    });
    expect(solicited.invocations).toEqual(unsolicited.invocations);
  });
});

describe('applyWorkflowEvent — group G, binding integrity', () => {
  it('refuses a cross-repository invocation', () => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      requestInvocation(buildInvocation({ repositoryId: REPO_B })),
    );

    expect(result.rejection).toBe('BINDING_MISMATCH');
    expect(result.invalidFields).toEqual(['invocation.repositoryId']);
  });

  it('refuses an invocation targeting a commit the workflow is not bound to', () => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      requestInvocation(buildInvocation({ targetCommitSha: SHA_C })),
    );

    expect(result.rejection).toBe('BINDING_MISMATCH');
    expect(result.invalidFields).toEqual(['invocation.targetCommitSha']);
  });

  it('refuses a cross-pull-request invocation', () => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      requestInvocation(buildInvocation({ pullRequestId: PR_B })),
    );

    expect(result.rejection).toBe('BINDING_MISMATCH');
    expect(result.invalidFields).toEqual(['invocation.pullRequestId']);
  });

  it('accepts an invocation with no pull request against a pull-request workflow', () => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      requestInvocation(buildInvocationWithoutPullRequest()),
    );

    expect(result.outcome).toBe('APPLIED');
  });

  it('treats a case-differing commit as a different commit', () => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      requestInvocation(buildInvocation({ targetCommitSha: SHA_A.toUpperCase() })),
    );

    expect(result.rejection).toBe('BINDING_MISMATCH');
  });

  it('treats a padded commit as a different commit', () => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      requestInvocation(buildInvocation({ targetCommitSha: ` ${SHA_A}` })),
    );

    expect(result.rejection).toBe('BINDING_MISMATCH');
  });

  it('reports every invalid invocation field in declaration order', () => {
    const result = applyWorkflowEvent(openedWorkflow(), {
      kind: 'INVOCATION_REQUESTED',
      invocation: {
        invocationId: '',
        repositoryId: '',
        pullRequestId: 7,
        targetCommitSha: '',
        providerId: '',
        agentId: '',
        purpose: 'merge',
        requestedAt: '',
      },
    } as never);

    expect(result.rejection).toBe('EVENT_PAYLOAD_INVALID');
    expect(result.invalidFields).toEqual([
      'invocation.invocationId',
      'invocation.repositoryId',
      'invocation.pullRequestId',
      'invocation.targetCommitSha',
      'invocation.providerId',
      'invocation.agentId',
      'invocation.purpose',
      'invocation.requestedAt',
    ]);
  });

  it.each(UNSUPPORTED_EVENT_KINDS)('refuses the event kind %s', (kind) => {
    const result = applyWorkflowEvent(openedWorkflow(), { kind } as never);

    expect(result.rejection).toBe('EVENT_KIND_UNKNOWN');
    expect(result.invalidFields).toEqual(['event.kind']);
  });

  it.each(NON_OBJECTS)('refuses an event that is %s', (_name, value) => {
    const state = openedWorkflow();
    const result = applyWorkflowEvent(state, value as never);

    expect(result.rejection).toBe('EVENT_UNREADABLE');
    expect(result.state).toBe(state);
  });

  it('refuses an event that is an array', () => {
    expect(applyWorkflowEvent(openedWorkflow(), [] as never).rejection).toBe(
      'EVENT_UNREADABLE',
    );
  });

  it('refuses a closure reason outside the vocabulary', () => {
    const result = applyWorkflowEvent(openedWorkflow(), closeWorkflow('MERGED'));

    expect(result.rejection).toBe('EVENT_PAYLOAD_INVALID');
    expect(result.invalidFields).toEqual(['event.closureReason']);
  });

  it('refuses a human gate opened at a commit the workflow is not bound to', () => {
    const result = applyWorkflowEvent(openedWorkflow(), openHumanGate(SHA_B));

    expect(result.rejection).toBe('BINDING_MISMATCH');
    expect(result.invalidFields).toEqual(['event.atCommitSha']);
  });

  it('rejects an already-open human gate before reading atCommitSha', () => {
    const event = { kind: 'HUMAN_GATE_OPENED' } as Record<string, unknown>;
    Object.defineProperty(event, 'atCommitSha', {
      enumerable: true,
      get() {
        throw new Error('must not be read');
      },
    });

    const result = applyWorkflowEvent(awaitingHuman(), event as never);

    expect(result.rejection).toBe('HUMAN_GATE_ALREADY_OPEN');
    expect(result.invalidFields).toEqual(['workflow.status']);
  });

  it('retains the gate revision when a workflow closes while awaiting a human', () => {
    const state = applyOrThrow(awaitingHuman(), closeWorkflow('HUMAN_DECISION_RECORDED'));

    expect(state.status).toBe('CLOSED');
    expect(state.closureReason).toBe('HUMAN_DECISION_RECORDED');
    expect(state.humanGateOpenedAtRevision).toBe(0);
  });
});

describe('applyWorkflowEvent — group N, end-to-end lifecycle replay', () => {
  const EVIDENCE_TARGET_A = { repositoryId: REPO_A, currentHeadSha: SHA_A };
  const EVIDENCE_TARGET_B = { repositoryId: REPO_A, currentHeadSha: SHA_B };

  function ciEvidence(evidenceId: string, commitSha: string): EvidenceRecord {
    return {
      evidenceId,
      repositoryId: REPO_A,
      commitSha,
      kind: 'ci-result',
      source: 'github',
      reference: 'check-run-1',
      observedAt: REQUESTED_AT,
    };
  }

  function humanEvidence(evidenceId: string, commitSha: string): EvidenceRecord {
    return {
      evidenceId,
      repositoryId: REPO_A,
      commitSha,
      kind: 'human-decision',
      source: 'human',
      reference: 'decision-1',
      observedAt: REQUESTED_AT,
    };
  }

  function reviewContext(reviewId: string, commitSha: string): ReviewContext {
    return {
      repositoryId: REPO_A,
      pullRequestId: PR_A,
      reviewedCommitSha: commitSha,
      provider: 'coderabbit',
      reviewerId: 'reviewer-1',
      reviewId,
    };
  }

  function invocation(
    invocationId: string,
    purpose: AgentInvocation['purpose'],
    targetCommitSha: string,
  ): AgentInvocation {
    return buildInvocation({ invocationId, purpose, targetCommitSha });
  }

  it('replays the real PR 005/006 lifecycle through the genuine upstream layers', () => {
    let state = openedWorkflow();

    // 1. implementation requested and reported.
    const implement = invocation('inv-implement', 'implement', SHA_A);
    state = applyOrThrow(state, requestInvocation(implement));
    state = applyOrThrow(
      state,
      reportInvocation(
        ingestInvocationReport(implement, {
          status: 'reported-complete',
          detail: 'opened a change request',
          artifacts: [{ artifactType: 'change-request', reference: 'pr-1234', commitSha: SHA_B }],
        }),
      ),
    );
    expect(state.invocations[0]?.state).toBe('REPORTED');
    expect(state.evidence).toEqual([]);

    // 2. an independent CI observation at the bound commit.
    state = applyOrThrow(
      state,
      admitEvidence(evaluateEvidenceFreshness(ciEvidence('ev-ci-a', SHA_A), EVIDENCE_TARGET_A)),
    );
    expect(state.evidence).toHaveLength(1);

    // 3. review requested, and its findings ingested by PR 005.
    const review = invocation('inv-review', 'review', SHA_A);
    state = applyOrThrow(state, requestInvocation(review));
    state = applyOrThrow(
      state,
      admitReview(
        ingestReview(reviewContext('inv-review', SHA_A), {
          findings: [{ title: 'unsafe read', message: 'validate before use', severity: 'blocking' }],
        }),
      ),
    );
    expect(state.reviews).toHaveLength(1);

    // 4. a human gate blocks new work but not fact recording.
    state = applyOrThrow(state, openHumanGate(SHA_A));
    expect(
      applyWorkflowEvent(state, requestInvocation(invocation('inv-x', 'repair', SHA_A))).rejection,
    ).toBe('WORKFLOW_AWAITING_HUMAN');
    state = applyOrThrow(
      state,
      reportInvocation(ingestInvocationReport(review, { status: 'reported-complete' })),
    );

    // 5. HEAD moves. A1 clears the gate; old-commit evidence stops applying.
    state = applyOrThrow(state, observeHead(SHA_B));
    expect(state.status).toBe('OPEN');
    expect(state.humanGateOpenedAtRevision).toBeNull();
    expect(state.revision).toBe(1);
    expect(
      applyWorkflowEvent(
        state,
        admitReview(ingestReview(reviewContext('inv-review', SHA_A), { findings: [] })),
      ).rejection,
    ).toBe('BINDING_MISMATCH');
    expect(
      applyWorkflowEvent(
        state,
        admitEvidence(evaluateEvidenceFreshness(ciEvidence('ev-ci-a', SHA_A), EVIDENCE_TARGET_B)),
      ).rejection,
    ).toBe('EVIDENCE_NOT_CURRENT');

    // 6. a fresh review at the new commit, plus an unsolicited one (A3).
    const fresh = invocation('inv-review-2', 'review', SHA_B);
    state = applyOrThrow(state, requestInvocation(fresh));
    state = applyOrThrow(
      state,
      admitReview(ingestReview(reviewContext('inv-review-2', SHA_B), { findings: [] })),
    );
    state = applyOrThrow(
      state,
      admitReview(ingestReview(reviewContext('forge-auto-review', SHA_B), { findings: [] })),
    );
    expect(state.reviews).toHaveLength(3);
    expect(state.invocations).toHaveLength(3);

    // 7. a human decides at the current commit, then an audit runs, then close.
    state = applyOrThrow(state, openHumanGate(SHA_B));
    state = applyOrThrow(
      state,
      admitEvidence(
        evaluateEvidenceFreshness(humanEvidence('ev-human-1', SHA_B), EVIDENCE_TARGET_B),
      ),
    );
    expect(state.status).toBe('OPEN');

    const audit = invocation('inv-audit', 'audit', SHA_B);
    state = applyOrThrow(state, requestInvocation(audit));
    state = applyOrThrow(
      state,
      reportInvocation(ingestInvocationReport(audit, { status: 'reported-complete' })),
    );
    state = applyOrThrow(
      state,
      admitEvidence(evaluateEvidenceFreshness(ciEvidence('ev-ci-b', SHA_B), EVIDENCE_TARGET_B)),
    );
    state = applyOrThrow(state, closeWorkflow('HUMAN_DECISION_RECORDED'));

    expect(state.status).toBe('CLOSED');
    expect(state.revision).toBe(1);
    expect(state.invocations).toHaveLength(4);
    expect(state.evidence).toHaveLength(3);
    expect(state.reviews).toHaveLength(3);
    expect(state.evidence[0]?.admittedAtCommitSha).toBe(SHA_A);
    expect(state.evidence[1]?.admittedAtCommitSha).toBe(SHA_B);
    expect(state.reviews[0]?.admittedAtCommitSha).toBe(SHA_A);
    expect(state.reviews[2]?.admittedAtCommitSha).toBe(SHA_B);
    expect(JSON.parse(JSON.stringify(state))).toEqual(state);

    // Serialization preserves the data, but `JSON.parse` does not restore the
    // frozen-collection runtime invariant — that is a caller obligation. The
    // raw parse is refused as unreadable; a re-frozen copy is readable again
    // and reaches the terminal-status rule this closed workflow expects.
    const restored = JSON.parse(JSON.stringify(state)) as WorkflowState;

    expect(Object.isFrozen(restored.invocations)).toBe(false);
    expect(applyWorkflowEvent(restored, closeWorkflow()).rejection).toBe('WORKFLOW_UNREADABLE');

    const refrozen = {
      ...restored,
      invocations: Object.freeze([...restored.invocations]),
      evidence: Object.freeze([...restored.evidence]),
      reviews: Object.freeze([...restored.reviews]),
    } as WorkflowState;

    expect(applyWorkflowEvent(refrozen, closeWorkflow()).rejection).toBe('WORKFLOW_CLOSED');
  });

  it('rejects a claim passed where an observation belongs', () => {
    const claimed = ingestInvocationReport(buildInvocation(), {
      status: 'reported-complete',
      artifacts: [{ artifactType: 'commit', reference: 'abc', commitSha: SHA_A }],
    });
    const claim = claimed.claims[0];

    expect(claim).toBeDefined();
    expect(
      applyWorkflowEvent(openedWorkflow(), { kind: 'EVIDENCE_ADMITTED', verdict: claim } as never)
        .rejection,
    ).toBe('EVIDENCE_NOT_CURRENT');
  });

  it('labels arbitrary values without throwing', () => {
    expect(label(Symbol('x'))).toContain('symbol');
    expect(label(REVIEW_B)).toContain(REVIEW_B);
  });
});

/**
 * Plant inherited accessor fields on `Object.prototype`, restoring them exactly.
 *
 * The installing descriptor is null-prototyped so that poisoning `set` while
 * `get` is already poisoned does not disrupt the very `defineProperty` that
 * installs it — the harness stays valid under the same condition it exercises.
 */
function withAccessorPoison(keys: readonly PropertyKey[], body: () => void): void {
  const proto = Object.prototype;
  const saved = keys.map((key) => Object.getOwnPropertyDescriptor(proto, key));
  const poison: PropertyDescriptor = {
    value(): unknown {
      return undefined;
    },
    writable: true,
    enumerable: false,
    configurable: true,
  };
  Object.setPrototypeOf(poison, null);
  try {
    for (const key of keys) {
      Object.defineProperty(proto, key, poison);
    }
    body();
  } finally {
    keys.forEach((key, index) => {
      const original = saved[index];
      if (original === undefined) {
        Reflect.deleteProperty(proto, key);
      } else {
        Object.defineProperty(proto, key, original);
      }
    });
  }
}

describe('PR9-WF-F1: noteRevisionSpan inline descriptors survive prototype poisoning', () => {
  // `noteRevisionSpan` stamps its lowest/highest slots with `Object.defineProperty`
  // over an inline descriptor. Those calls are on the public evaluation path:
  // `applyWorkflowEvent` -> `snapshotWorkflow` -> `noteRevisionSpan`. An inherited
  // `get`/`set` poison made `ToPropertyDescriptor` throw there, so a hostile realm
  // turned an intended apply/rejection into an unexpected `TypeError`.

  /** One invocation requested then reported at the same revision. */
  function reportedInvocation(): WorkflowState {
    return applyOrThrow(withRequestedInvocation(), reportInvocation());
  }

  /**
   * A state whose two same-revision invocation records are ordered so the
   * second-listed carries the lower sequence — driving `noteRevisionSpan`
   * through its lowest-slot inline descriptor. Built from real transitions,
   * then reordered; lists are refrozen to stay faithful to a produced state.
   */
  function reachesLowestSpanSite(): WorkflowState {
    let state = openedWorkflow();
    state = applyOrThrow(state, requestInvocation(buildInvocation({ invocationId: INVOCATION_A })));
    state = applyOrThrow(state, requestInvocation(buildInvocation({ invocationId: INVOCATION_B })));
    const invocations = Object.freeze([
      Object.freeze({ ...state.invocations[0], requestedAtSequence: 2 }),
      Object.freeze({ ...state.invocations[1], requestedAtSequence: 1 }),
    ]);
    return Object.freeze({ ...state, invocations }) as WorkflowState;
  }

  const deeplyFrozen = (state: WorkflowState): boolean =>
    Object.isFrozen(state) &&
    Object.isFrozen(state.invocations) &&
    Object.isFrozen(state.evidence) &&
    Object.isFrozen(state.reviews);

  it.each([['get'], ['set'], ['get', 'set']] as const)(
    'reaches the highest-slot inline descriptor under %s poison and applies unchanged',
    (...keys) => {
      const prior = reportedInvocation();
      const clean = applyWorkflowEvent(prior, admitEvidence());
      let poisoned: ReturnType<typeof applyWorkflowEvent> | undefined;

      withAccessorPoison([...keys], () => {
        poisoned = applyWorkflowEvent(prior, admitEvidence());
      });

      expect(poisoned).toEqual(clean);
      expect(poisoned?.outcome).toBe('APPLIED');
      // Chronology, revision, and sequence accounting are all unchanged.
      expect(poisoned?.state.revision).toBe(clean.state.revision);
      expect(poisoned?.state.sequence).toBe(clean.state.sequence);
      expect(poisoned ? deeplyFrozen(poisoned.state) : false).toBe(true);
    },
  );

  it.each([['get'], ['set'], ['get', 'set']] as const)(
    'reaches the lowest-slot inline descriptor under %s poison with identical outcome',
    (...keys) => {
      const prior = reachesLowestSpanSite();
      const clean = applyWorkflowEvent(prior, admitEvidence());
      let poisoned: ReturnType<typeof applyWorkflowEvent> | undefined;

      withAccessorPoison([...keys], () => {
        poisoned = applyWorkflowEvent(prior, admitEvidence());
      });

      // Whether the reordered state reads as applicable or as a deterministic
      // rejection, the poisoned run must reproduce the clean run exactly.
      expect(poisoned).toEqual(clean);
      expect(poisoned?.outcome).toBe(clean.outcome);
      expect(poisoned?.rejection).toBe(clean.rejection);
    },
  );

  it('preserves prior-state identity on a rejection reached through noteRevisionSpan', () => {
    const prior = reportedInvocation();
    let poisoned: ReturnType<typeof applyWorkflowEvent> | undefined;

    withAccessorPoison(['get', 'set'], () => {
      // A duplicate invocation id rejects, but the snapshot of `prior` reaches
      // `noteRevisionSpan` first.
      poisoned = applyWorkflowEvent(prior, requestInvocation());
    });

    expect(poisoned?.outcome).toBe('REJECTED');
    expect(poisoned?.rejection).toBe('DUPLICATE_INVOCATION_ID');
    expect(poisoned?.state).toBe(prior);
  });

  it('leaves the realm clean after exercising the inline descriptors', () => {
    expect(Object.getOwnPropertyDescriptor(Object.prototype, 'get')).toBeUndefined();
    expect(Object.getOwnPropertyDescriptor(Object.prototype, 'set')).toBeUndefined();
  });
});

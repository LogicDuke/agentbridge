import { describe, expect, it } from 'vitest';

import {
  APPROVAL_STATE,
  type ApprovalRecord,
  classifyAction,
  DECISION,
  evaluateActionRequest,
  GATE_OUTCOME,
  GATE_REASON,
  REQUIRED_REQUEST_FIELDS,
} from '../../src/domain/index.js';
import {
  EXPECTED_ALLOWED_ACTIONS,
  EXPECTED_NEVER_ALLOWED_ACTIONS,
} from './expected-policy.js';
import { buildRequest, MALFORMED_ACTIONS } from './request-fixtures.js';

describe('PR 002 ALLOW produces autonomous gate approval', () => {
  for (const action of EXPECTED_ALLOWED_ACTIONS) {
    it(`grants autonomy for ${action}`, () => {
      const decision = evaluateActionRequest(buildRequest({ action }));

      expect(decision.classification.decision).toBe(DECISION.ALLOW);
      expect(decision.outcome).toBe(GATE_OUTCOME.AUTONOMOUS);
      expect(decision.mayExecuteAutonomously).toBe(true);
      expect(decision.requiresHumanApproval).toBe(false);
      expect(decision.approvalState).toBe(APPROVAL_STATE.NOT_REQUIRED);
      expect(decision.reason).toBe(GATE_REASON.CLASSIFICATION_ALLOWED);
    });
  }
});

describe('PR 002 non-ALLOW never produces autonomous execution', () => {
  for (const action of EXPECTED_NEVER_ALLOWED_ACTIONS) {
    it(`withholds autonomy for ${action}`, () => {
      const decision = evaluateActionRequest(buildRequest({ action }));

      expect(decision.classification.decision).not.toBe(DECISION.ALLOW);
      expect(decision.outcome).toBe(GATE_OUTCOME.HUMAN_REVIEW_REQUIRED);
      expect(decision.mayExecuteAutonomously).toBe(false);
      expect(decision.requiresHumanApproval).toBe(true);
      expect(decision.approvalState).toBe(APPROVAL_STATE.PENDING);
      expect(decision.reason).toBe(GATE_REASON.CLASSIFICATION_REQUIRES_HUMAN);
    });
  }
});

describe('unknown and malformed action strings fail closed', () => {
  for (const action of MALFORMED_ACTIONS) {
    it(`withholds autonomy for ${JSON.stringify(action)}`, () => {
      const decision = evaluateActionRequest(buildRequest({ action }));

      expect(decision.mayExecuteAutonomously).toBe(false);
      expect(decision.requiresHumanApproval).toBe(true);
      expect(decision.outcome).not.toBe(GATE_OUTCOME.AUTONOMOUS);
    });
  }
});

describe('envelope traceability', () => {
  for (const field of REQUIRED_REQUEST_FIELDS) {
    it(`blocks a request with a blank ${field}`, () => {
      const decision = evaluateActionRequest(buildRequest({ [field]: '' }));

      expect(decision.outcome).toBe(GATE_OUTCOME.INVALID_REQUEST);
      expect(decision.reason).toBe(GATE_REASON.REQUEST_ENVELOPE_INVALID);
      expect(decision.mayExecuteAutonomously).toBe(false);
      expect(decision.invalidFields).toContain(field);
    });
  }

  it('treats whitespace-only values as blank', () => {
    const decision = evaluateActionRequest(buildRequest({ repositoryId: '   \t ' }));

    expect(decision.outcome).toBe(GATE_OUTCOME.INVALID_REQUEST);
    expect(decision.invalidFields).toContain('repositoryId');
  });

  it('blocks an otherwise allowed action when the envelope is untraceable', () => {
    const decision = evaluateActionRequest(
      buildRequest({ action: 'git.status', repositoryId: '' }),
    );

    expect(decision.classification.decision).toBe(DECISION.ALLOW);
    expect(decision.mayExecuteAutonomously).toBe(false);
    expect(decision.outcome).toBe(GATE_OUTCOME.INVALID_REQUEST);
  });

  it('reports every invalid field, not just the first', () => {
    const decision = evaluateActionRequest(
      buildRequest({ requestId: '', actorId: '', repositoryId: '' }),
    );

    expect([...decision.invalidFields].sort()).toEqual(
      ['actorId', 'repositoryId', 'requestId'].sort(),
    );
  });

  it('reports no invalid fields for a well-formed request', () => {
    expect(evaluateActionRequest(buildRequest()).invalidFields).toEqual([]);
  });
});

describe('gate result shape', () => {
  it('echoes envelope identity fields verbatim', () => {
    const request = buildRequest({
      requestId: 'req-42',
      actorId: 'agent-zeta',
      actorProvider: 'openai',
      repositoryId: 'repo-x',
      requestedAt: '2026-01-02T03:04:05.000Z',
      sessionId: 'session-9',
    });
    const decision = evaluateActionRequest(request);

    expect(decision.requestId).toBe('req-42');
    expect(decision.action).toBe(request.action);
    expect(decision.actorId).toBe('agent-zeta');
    expect(decision.actorProvider).toBe('openai');
    expect(decision.repositoryId).toBe('repo-x');
    expect(decision.requestedAt).toBe('2026-01-02T03:04:05.000Z');
    expect(decision.sessionId).toBe('session-9');
  });

  it('represents an absent sessionId as null rather than dropping it', () => {
    const decision = evaluateActionRequest(buildRequest());

    expect(decision.sessionId).toBeNull();
    expect(Object.keys(decision)).toContain('sessionId');
  });

  it('embeds the PR 002 classification unmodified', () => {
    for (const action of ['git.status', 'git.push', 'git.fetch', 'nope']) {
      const decision = evaluateActionRequest(buildRequest({ action }));

      expect(decision.classification).toEqual(classifyAction(action));
    }
  });

  it('does not echo rationale or metadata into the decision record', () => {
    const decision = evaluateActionRequest(
      buildRequest({ rationale: 'please', metadata: { note: 'hi' } }),
    );
    const keys = Object.keys(decision);

    expect(keys).not.toContain('rationale');
    expect(keys).not.toContain('metadata');
  });
});

describe('approval state is recorded, never authorizing', () => {
  const approvalFor = (requestId: string, state: ApprovalRecord['state']): ApprovalRecord => ({
    requestId,
    state,
    decidedBy: 'human-reviewer',
    decidedAt: '2026-08-10T01:00:00.000Z',
  });

  it('reports not-required when the action is autonomously allowed', () => {
    const decision = evaluateActionRequest(buildRequest({ action: 'git.status' }));

    expect(decision.approvalState).toBe(APPROVAL_STATE.NOT_REQUIRED);
  });

  it('reports pending when a human has not decided', () => {
    const decision = evaluateActionRequest(buildRequest({ action: 'git.push' }));

    expect(decision.approvalState).toBe(APPROVAL_STATE.PENDING);
  });

  it('records a matching human decision', () => {
    for (const state of [APPROVAL_STATE.APPROVED, APPROVAL_STATE.REJECTED] as const) {
      const request = buildRequest({ action: 'git.push', requestId: 'req-77' });
      const decision = evaluateActionRequest(request, approvalFor('req-77', state));

      expect(decision.approvalState).toBe(state);
    }
  });

  it('ignores an approval issued for a different request', () => {
    const request = buildRequest({ action: 'git.push', requestId: 'req-77' });
    const decision = evaluateActionRequest(
      request,
      approvalFor('req-OTHER', APPROVAL_STATE.APPROVED),
    );

    expect(decision.approvalState).toBe(APPROVAL_STATE.PENDING);
    expect(decision.mayExecuteAutonomously).toBe(false);
  });

  it('never grants autonomy on the strength of an approval', () => {
    const request = buildRequest({ action: 'production.change', requestId: 'req-88' });
    const decision = evaluateActionRequest(
      request,
      approvalFor('req-88', APPROVAL_STATE.APPROVED),
    );

    expect(decision.approvalState).toBe(APPROVAL_STATE.APPROVED);
    expect(decision.mayExecuteAutonomously).toBe(false);
    expect(decision.requiresHumanApproval).toBe(true);
    expect(decision.outcome).toBe(GATE_OUTCOME.HUMAN_REVIEW_REQUIRED);
  });
});

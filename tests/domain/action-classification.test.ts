import { describe, expect, it } from 'vitest';

import {
  ACTION_POLICY,
  ALL_ACTION_KINDS,
  classifyAction,
  DECISION,
  HUMAN_GATED_ACTION_KINDS,
  MODELED_ACTION_KINDS,
  READ_ONLY_ACTION_KINDS,
  REASON_CODE,
  REASON_CODES,
  resolveActionKind,
  UNKNOWN_ACTION_KIND,
} from '../../src/domain/index.js';
import {
  EXPECTED_ACTION_NAMES,
  EXPECTED_ALLOWED_ACTIONS,
  EXPECTED_NEVER_ALLOWED_ACTIONS,
  EXPECTED_POLICY,
} from './expected-policy.js';

/**
 * The independent table must be internally consistent before it can be trusted
 * to judge production.
 */
describe('independent expectation table', () => {
  it('lists thirteen allowed actions and fifteen never-allowed entries', () => {
    expect(EXPECTED_ALLOWED_ACTIONS.length).toBe(13);
    expect(EXPECTED_NEVER_ALLOWED_ACTIONS.length).toBe(15);
    expect(EXPECTED_ACTION_NAMES.length).toBe(28);
  });

  it('agrees with itself about which actions are allowed', () => {
    const allowedInTable = Object.entries(EXPECTED_POLICY)
      .filter(([, outcome]) => outcome.decision === 'ALLOW')
      .map(([action]) => action);
    const deniedInTable = Object.entries(EXPECTED_POLICY)
      .filter(([, outcome]) => outcome.decision !== 'ALLOW')
      .map(([action]) => action);

    expect([...allowedInTable].sort()).toEqual([...EXPECTED_ALLOWED_ACTIONS].sort());
    expect([...deniedInTable].sort()).toEqual([...EXPECTED_NEVER_ALLOWED_ACTIONS].sort());
  });

  it('never marks an allowed action as requiring approval, or vice versa', () => {
    for (const [action, outcome] of Object.entries(EXPECTED_POLICY)) {
      expect(outcome.requiresHumanApproval, action).toBe(outcome.decision !== 'ALLOW');
    }
  });
});

/**
 * Drift detection. The expectation table is hand-written, so production adding
 * or removing an action must break these, not silently pass.
 */
describe('production taxonomy matches the independent table', () => {
  it('recognises exactly the actions the table declares', () => {
    expect([...ALL_ACTION_KINDS].sort()).toEqual([...EXPECTED_ACTION_NAMES].sort());
  });

  it('assigns a policy entry to exactly those actions', () => {
    expect(Object.keys(ACTION_POLICY).sort()).toEqual([...EXPECTED_ACTION_NAMES].sort());
  });

  it('keeps its read-only and human-gated tiers disjoint and duplicate-free', () => {
    const readOnly = new Set<string>(READ_ONLY_ACTION_KINDS);

    for (const kind of HUMAN_GATED_ACTION_KINDS) {
      expect(readOnly.has(kind), `${kind} is in both tiers`).toBe(false);
    }
    expect(new Set(MODELED_ACTION_KINDS).size).toBe(MODELED_ACTION_KINDS.length);
    expect(MODELED_ACTION_KINDS).not.toContain(UNKNOWN_ACTION_KIND);
  });
});

describe('per-action outcomes', () => {
  for (const [action, expected] of Object.entries(EXPECTED_POLICY)) {
    it(`classifies ${action} as ${expected.decision}`, () => {
      const result = classifyAction(action);

      expect(result.decision).toBe(expected.decision);
      expect(result.requiresHumanApproval).toBe(expected.requiresHumanApproval);
      expect(result.known).toBe(expected.known);
      expect(result.action).toBe(action);
    });
  }
});

describe('the ALLOW set', () => {
  it('contains exactly the independently declared allowed actions', () => {
    const actuallyAllowed = EXPECTED_ACTION_NAMES.filter(
      (action) => classifyAction(action).decision === DECISION.ALLOW,
    );

    expect([...actuallyAllowed].sort()).toEqual([...EXPECTED_ALLOWED_ACTIONS].sort());
  });

  it('allows none of the independently declared never-allowed actions', () => {
    for (const action of EXPECTED_NEVER_ALLOWED_ACTIONS) {
      const result = classifyAction(action);

      expect(result.decision, action).not.toBe(DECISION.ALLOW);
      expect(result.requiresHumanApproval, action).toBe(true);
    }
  });

  it('does not autonomously allow git.fetch', () => {
    const result = classifyAction('git.fetch');

    expect(result.decision).not.toBe(DECISION.ALLOW);
    expect(result.decision).toBe(DECISION.ESCALATE);
    expect(result.requiresHumanApproval).toBe(true);
    expect(result.known).toBe(true);
    expect(result.riskTier).toBe('human-gated');
    expect(EXPECTED_ALLOWED_ACTIONS).not.toContain('git.fetch');
  });

  it('marks every allowed action read-only and every other modeled action gated', () => {
    for (const action of EXPECTED_ALLOWED_ACTIONS) {
      expect(classifyAction(action).riskTier, action).toBe('read-only');
      expect(classifyAction(action).reason, action).toBe(REASON_CODE.READ_ONLY_ACTION_ALLOWED);
    }
    for (const action of EXPECTED_NEVER_ALLOWED_ACTIONS) {
      if (action === UNKNOWN_ACTION_KIND) {
        continue;
      }
      expect(classifyAction(action).riskTier, action).toBe('human-gated');
      expect(classifyAction(action).reason, action).toBe(REASON_CODE.HUMAN_AUTHORITY_REQUIRED);
    }
  });
});

describe('the unknown contract', () => {
  it('escalates the unknown sentinel to human review', () => {
    const result = classifyAction(UNKNOWN_ACTION_KIND);

    expect(result.decision).not.toBe(DECISION.ALLOW);
    expect(result.decision).toBe(DECISION.ESCALATE);
    expect(result.requiresHumanApproval).toBe(true);
    expect(result.known).toBe(false);
    expect(result.riskTier).toBe('unknown');
    expect(result.reason).toBe(REASON_CODE.UNRECOGNIZED_ACTION_ESCALATED);
  });

  it('treats the literal string "unknown" as unmodeled, not as a modeled action', () => {
    expect(resolveActionKind(UNKNOWN_ACTION_KIND)).toBe(UNKNOWN_ACTION_KIND);
    expect(classifyAction(UNKNOWN_ACTION_KIND).known).toBe(false);
  });

  it('gives unrecognised input the same decision as gated input but a distinct reason', () => {
    const unknown = classifyAction('totally.unmodeled');
    const gated = classifyAction('git.push');

    expect(unknown.decision).toBe(gated.decision);
    expect(unknown.requiresHumanApproval).toBe(gated.requiresHumanApproval);
    expect(unknown.reason).not.toBe(gated.reason);
    expect(unknown.known).toBe(false);
    expect(gated.known).toBe(true);
  });

  it('emits no DENY anywhere in the V1 defaults, leaving one fail-closed contract', () => {
    for (const action of EXPECTED_ACTION_NAMES) {
      expect(classifyAction(action).decision, action).not.toBe(DECISION.DENY);
    }
    expect(classifyAction('some.unmodeled.action').decision).not.toBe(DECISION.DENY);
  });

  it('emits only reason codes declared in the domain', () => {
    for (const action of [...EXPECTED_ACTION_NAMES, 'not.an.action']) {
      expect(REASON_CODES).toContain(classifyAction(action).reason);
    }
  });
});

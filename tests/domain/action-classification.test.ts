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

describe('taxonomy shape', () => {
  it('models every V1 action kind exactly once', () => {
    expect(new Set(MODELED_ACTION_KINDS).size).toBe(MODELED_ACTION_KINDS.length);
    expect(MODELED_ACTION_KINDS.length).toBe(
      READ_ONLY_ACTION_KINDS.length + HUMAN_GATED_ACTION_KINDS.length,
    );
  });

  it('keeps read-only and human-gated tiers disjoint', () => {
    const readOnly = new Set<string>(READ_ONLY_ACTION_KINDS);
    for (const kind of HUMAN_GATED_ACTION_KINDS) {
      expect(readOnly.has(kind)).toBe(false);
    }
  });

  it('never lists the unknown sentinel as a modeled action', () => {
    expect(MODELED_ACTION_KINDS).not.toContain(UNKNOWN_ACTION_KIND);
    expect(ALL_ACTION_KINDS).toContain(UNKNOWN_ACTION_KIND);
  });
});

describe('safe V1 actions', () => {
  for (const kind of READ_ONLY_ACTION_KINDS) {
    it(`allows ${kind} without human approval`, () => {
      const result = classifyAction(kind);

      expect(result.decision).toBe(DECISION.ALLOW);
      expect(result.requiresHumanApproval).toBe(false);
      expect(result.known).toBe(true);
      expect(result.kind).toBe(kind);
      expect(result.riskTier).toBe('read-only');
      expect(result.reason).toBe(REASON_CODE.READ_ONLY_ACTION_ALLOWED);
    });
  }

  it('allows exactly the fourteen documented read-only actions', () => {
    expect(READ_ONLY_ACTION_KINDS.length).toBe(14);

    const allowed = ALL_ACTION_KINDS.filter(
      (kind) => classifyAction(kind).decision === DECISION.ALLOW,
    );
    expect([...allowed].sort()).toEqual([...READ_ONLY_ACTION_KINDS].sort());
  });
});

describe('dangerous V1 actions', () => {
  for (const kind of HUMAN_GATED_ACTION_KINDS) {
    it(`never allows ${kind} and requires human approval`, () => {
      const result = classifyAction(kind);

      expect(result.decision).not.toBe(DECISION.ALLOW);
      expect(result.decision).toBe(DECISION.ESCALATE);
      expect(result.requiresHumanApproval).toBe(true);
      expect(result.known).toBe(true);
      expect(result.kind).toBe(kind);
      expect(result.riskTier).toBe('human-gated');
      expect(result.reason).toBe(REASON_CODE.HUMAN_AUTHORITY_REQUIRED);
    });
  }

  it('covers all thirteen documented dangerous actions', () => {
    expect(HUMAN_GATED_ACTION_KINDS.length).toBe(13);
  });
});

describe('unknown actions', () => {
  it('never allows the unknown sentinel', () => {
    const result = classifyAction(UNKNOWN_ACTION_KIND);

    expect(result.decision).not.toBe(DECISION.ALLOW);
    expect(result.decision).toBe(DECISION.DENY);
    expect(result.requiresHumanApproval).toBe(true);
    expect(result.known).toBe(false);
    expect(result.riskTier).toBe('unknown');
    expect(result.reason).toBe(REASON_CODE.UNRECOGNIZED_ACTION_DENIED);
  });

  it('resolves the literal string "unknown" to the sentinel, not a modeled action', () => {
    expect(resolveActionKind(UNKNOWN_ACTION_KIND)).toBe(UNKNOWN_ACTION_KIND);
    expect(classifyAction(UNKNOWN_ACTION_KIND).known).toBe(false);
  });
});

describe('policy table integrity', () => {
  it('assigns a policy to every action kind and to nothing else', () => {
    expect(Object.keys(ACTION_POLICY).sort()).toEqual([...ALL_ACTION_KINDS].sort());
  });

  it('grants ALLOW to no policy entry outside the read-only tier', () => {
    for (const [kind, entry] of Object.entries(ACTION_POLICY)) {
      if (entry.decision === DECISION.ALLOW) {
        expect(READ_ONLY_ACTION_KINDS).toContain(kind);
        expect(entry.riskTier).toBe('read-only');
      }
    }
  });

  it('emits only reason codes declared in the domain', () => {
    for (const kind of ALL_ACTION_KINDS) {
      expect(REASON_CODES).toContain(classifyAction(kind).reason);
    }
  });
});

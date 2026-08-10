import { describe, expect, it } from 'vitest';

import {
  ACTION_POLICY,
  ALL_ACTION_KINDS,
  classifyAction,
  DECISION,
  type Decision,
  DECISIONS,
  isAutonomouslyAllowed,
  isModeledActionKind,
  MODELED_ACTION_KINDS,
  resolveActionKind,
} from '../../src/domain/index.js';
import {
  EXPECTED_ALLOWED_ACTIONS,
  EXPECTED_NEVER_ALLOWED_ACTIONS,
} from './expected-policy.js';

/**
 * Exact strings that must classify as ALLOW, taken from the independently
 * declared table rather than from the production taxonomy. If production moves
 * an action between tiers, this set does not move with it.
 */
const ALLOWED = new Set<string>(EXPECTED_ALLOWED_ACTIONS);

/**
 * Strings an agent could plausibly emit that are *not* exact taxonomy members.
 * None of them may reach ALLOW.
 */
const HOSTILE_INPUTS: readonly string[] = [
  // Case variation.
  'GIT.STATUS',
  'Git.Status',
  'git.STATUS',
  'REPOSITORY.INSPECT',
  // Surrounding or embedded whitespace.
  ' git.status',
  'git.status ',
  ' git.status ',
  '\tgit.status',
  'git.status\n',
  'git .status',
  'git. status',
  // Separator substitution.
  'git-status',
  'git_status',
  'git/status',
  'git:status',
  'gitstatus',
  'git..status',
  // Prefix and suffix smuggling.
  'git.status.extra',
  'x.git.status',
  'git.status;git.push',
  'git.status && git.push',
  'git.status#git.push',
  'git.status\u0000git.push', // NUL-byte truncation.
  // Dangerous actions disguised as safe ones.
  'git.push.status',
  'repository.inspect.write',
  'repository.write ',
  'GIT.PUSH',
  // Prototype-chain keys: a plain-object lookup would resolve these.
  '__proto__',
  'constructor',
  'prototype',
  'toString',
  'valueOf',
  'hasOwnProperty',
  'isPrototypeOf',
  'propertyIsEnumerable',
  '__defineGetter__',
  // Empty and whitespace-only.
  '',
  ' ',
  '\t',
  '\n',
  // Decision names smuggled in as action names.
  'ALLOW',
  'allow',
  'DENY',
  'ESCALATE',
  // Unicode lookalikes and normalization tricks.
  'git\u2024status', // U+2024 ONE DOT LEADER, not '.'.
  'g\u0131t.status', // U+0131 dotless i.
  '\uff47\uff49\uff54.\uff53\uff54\uff41\uff54\uff55\uff53', // Fullwidth "git.status".
  'git.status\u200b', // Trailing zero-width space.
  // Plainly unmodeled future work.
  'future.action',
  'quantum.entangle',
  'repository.rewrite_history',
  'kubernetes.apply',
];

describe('security invariant: nothing outside the allowlist is ALLOW', () => {
  it('rejects every hostile or malformed input', () => {
    for (const input of HOSTILE_INPUTS) {
      const result = classifyAction(input);

      expect(result.decision, `"${input}" must not be ALLOW`).not.toBe(DECISION.ALLOW);
      expect(result.decision, `"${input}" must route to human review`).toBe(DECISION.ESCALATE);
      expect(result.requiresHumanApproval, `"${input}" must require a human`).toBe(true);
      expect(result.known, `"${input}" must not be treated as known`).toBe(false);
      expect(result.kind, `"${input}" must resolve to the unknown sentinel`).toBe('unknown');
    }
  });

  it('allows a string only when the independent table says it is allowed', () => {
    const corpus = [...ALL_ACTION_KINDS, ...EXPECTED_NEVER_ALLOWED_ACTIONS, ...HOSTILE_INPUTS];

    for (const input of corpus) {
      expect(classifyAction(input).decision === DECISION.ALLOW, `"${input}"`).toBe(
        ALLOWED.has(input),
      );
    }
  });

  it('has no default-to-allow path: mutating any modeled action string denies it', () => {
    for (const kind of MODELED_ACTION_KINDS) {
      for (const mutation of [`${kind} `, ` ${kind}`, kind.toUpperCase(), `${kind}.x`]) {
        if (ALLOWED.has(mutation)) {
          continue;
        }
        expect(classifyAction(mutation).decision, `"${mutation}"`).not.toBe(DECISION.ALLOW);
      }
    }
  });

  it('never allows an unmodeled action added later without a policy entry', () => {
    const futureAction = 'infrastructure.terraform_apply';

    expect(isModeledActionKind(futureAction)).toBe(false);
    expect(resolveActionKind(futureAction)).toBe('unknown');
    expect(classifyAction(futureAction).decision).not.toBe(DECISION.ALLOW);
    expect(classifyAction(futureAction).decision).toBe(DECISION.ESCALATE);
    expect(classifyAction(futureAction).requiresHumanApproval).toBe(true);
  });
});

describe('security invariant: human approval tracks autonomy', () => {
  it('requires approval for exactly the non-ALLOW decisions', () => {
    for (const input of [...ALL_ACTION_KINDS, ...HOSTILE_INPUTS]) {
      const result = classifyAction(input);
      expect(result.requiresHumanApproval).toBe(result.decision !== DECISION.ALLOW);
    }
  });

  it('treats ALLOW as the only autonomous decision', () => {
    for (const decision of DECISIONS) {
      expect(isAutonomouslyAllowed(decision)).toBe(decision === DECISION.ALLOW);
    }
  });

  it('requires approval for every independently declared never-allowed action', () => {
    for (const action of EXPECTED_NEVER_ALLOWED_ACTIONS) {
      expect(classifyAction(action).requiresHumanApproval, action).toBe(true);
    }
  });
});

describe('determinism', () => {
  it('returns equal results for repeated calls', () => {
    for (const input of [...ALL_ACTION_KINDS, ...HOSTILE_INPUTS]) {
      const first = classifyAction(input);
      const second = classifyAction(input);
      const third = classifyAction(input);

      expect(second).toEqual(first);
      expect(third).toEqual(first);
    }
  });

  it('does not depend on call order', () => {
    const forward = ALL_ACTION_KINDS.map((kind) => classifyAction(kind));
    const backward = [...ALL_ACTION_KINDS].reverse().map((kind) => classifyAction(kind));

    expect([...backward].reverse()).toEqual(forward);
  });

  it('preserves the requested string verbatim for audit', () => {
    for (const input of HOSTILE_INPUTS) {
      expect(classifyAction(input).action).toBe(input);
    }
  });
});

describe('serialization', () => {
  it('round-trips every classification through JSON without loss', () => {
    for (const input of [...ALL_ACTION_KINDS, ...HOSTILE_INPUTS]) {
      const result = classifyAction(input);
      const revived: unknown = JSON.parse(JSON.stringify(result));

      expect(revived).toEqual(result);
    }
  });

  it('serializes the full documented field set', () => {
    const revived: unknown = JSON.parse(JSON.stringify(classifyAction('git.push')));

    expect(revived).toEqual({
      action: 'git.push',
      kind: 'git.push',
      known: true,
      riskTier: 'human-gated',
      decision: 'ESCALATE',
      reason: 'HUMAN_AUTHORITY_REQUIRED',
      requiresHumanApproval: true,
    });
  });

  it('serializes an unknown action as an escalation, never an allow', () => {
    const revived: unknown = JSON.parse(JSON.stringify(classifyAction('nope')));

    expect(revived).toEqual({
      action: 'nope',
      kind: 'unknown',
      known: false,
      riskTier: 'unknown',
      decision: 'ESCALATE',
      reason: 'UNRECOGNIZED_ACTION_ESCALATED',
      requiresHumanApproval: true,
    });
  });

  it('serializes git.fetch as gated, not allowed', () => {
    const revived: unknown = JSON.parse(JSON.stringify(classifyAction('git.fetch')));

    expect(revived).toEqual({
      action: 'git.fetch',
      kind: 'git.fetch',
      known: true,
      riskTier: 'human-gated',
      decision: 'ESCALATE',
      reason: 'HUMAN_AUTHORITY_REQUIRED',
      requiresHumanApproval: true,
    });
  });

  it('emits only declared decision values', () => {
    for (const input of [...ALL_ACTION_KINDS, ...HOSTILE_INPUTS]) {
      expect(DECISIONS).toContain(classifyAction(input).decision);
    }
  });
});

describe('immutability', () => {
  it('freezes classification results so a denial cannot be upgraded to ALLOW', () => {
    const result = classifyAction('git.push');
    const mutable = result as { decision: Decision; requiresHumanApproval: boolean };

    expect(Object.isFrozen(result)).toBe(true);
    expect(() => {
      mutable.decision = DECISION.ALLOW;
    }).toThrow(TypeError);
    expect(() => {
      mutable.requiresHumanApproval = false;
    }).toThrow(TypeError);
    expect(result.decision).toBe(DECISION.ESCALATE);
    expect(result.requiresHumanApproval).toBe(true);
  });

  it('freezes the policy table so it cannot be widened at runtime', () => {
    const mutable = ACTION_POLICY as Record<string, unknown>;

    expect(Object.isFrozen(ACTION_POLICY)).toBe(true);
    expect(() => {
      mutable['git.push'] = { riskTier: 'read-only', decision: DECISION.ALLOW };
    }).toThrow(TypeError);
    expect(classifyAction('git.push').decision).toBe(DECISION.ESCALATE);
  });
});

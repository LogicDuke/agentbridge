/**
 * Independently declared expectations for the V1 action policy.
 *
 * This table is the test suite's own source of truth. It is written out by
 * hand and imports **nothing** from `src/`, so it cannot follow a production
 * mistake. If someone swaps `git.push` into the allowed set, moves
 * `git.status` out of it, or adds an action without classifying it, the
 * production result stops matching this table and the tests fail.
 *
 * Deriving these expectations from `READ_ONLY_ACTION_KINDS` or `ACTION_POLICY`
 * would make the suite agree with whatever production says, which is exactly
 * the failure mode this file exists to prevent. Do not import from `src/` here.
 */

export interface ExpectedOutcome {
  readonly decision: 'ALLOW' | 'DENY' | 'ESCALATE';
  readonly requiresHumanApproval: boolean;
  readonly known: boolean;
}

/**
 * Every action the V1 kernel is expected to recognise, plus the `unknown`
 * sentinel, with the outcome each must produce.
 */
export const EXPECTED_POLICY: Readonly<Record<string, ExpectedOutcome>> = Object.freeze({
  // Read-only / inspection: safe to run without human authority.
  'repository.inspect': { decision: 'ALLOW', requiresHumanApproval: false, known: true },
  'git.status': { decision: 'ALLOW', requiresHumanApproval: false, known: true },
  'git.diff': { decision: 'ALLOW', requiresHumanApproval: false, known: true },
  'git.log': { decision: 'ALLOW', requiresHumanApproval: false, known: true },
  'source.search': { decision: 'ALLOW', requiresHumanApproval: false, known: true },
  'test.run': { decision: 'ALLOW', requiresHumanApproval: false, known: true },
  'lint.run': { decision: 'ALLOW', requiresHumanApproval: false, known: true },
  'typecheck.run': { decision: 'ALLOW', requiresHumanApproval: false, known: true },
  'build.run': { decision: 'ALLOW', requiresHumanApproval: false, known: true },
  'audit.run': { decision: 'ALLOW', requiresHumanApproval: false, known: true },
  'scratch.inspect': { decision: 'ALLOW', requiresHumanApproval: false, known: true },
  'github.read': { decision: 'ALLOW', requiresHumanApproval: false, known: true },
  'agent.communicate': { decision: 'ALLOW', requiresHumanApproval: false, known: true },

  // Human-gated: modeled, but authority belongs to a human.
  'repository.write': { decision: 'ESCALATE', requiresHumanApproval: true, known: true },
  'git.commit': { decision: 'ESCALATE', requiresHumanApproval: true, known: true },
  'git.push': { decision: 'ESCALATE', requiresHumanApproval: true, known: true },
  'git.reset': { decision: 'ESCALATE', requiresHumanApproval: true, known: true },
  'git.force_push': { decision: 'ESCALATE', requiresHumanApproval: true, known: true },
  'git.branch_delete': { decision: 'ESCALATE', requiresHumanApproval: true, known: true },
  // Network egress + local .git writes. Gated in V1, not autonomously allowed.
  'git.fetch': { decision: 'ESCALATE', requiresHumanApproval: true, known: true },
  'deployment.run': { decision: 'ESCALATE', requiresHumanApproval: true, known: true },
  'staging.change': { decision: 'ESCALATE', requiresHumanApproval: true, known: true },
  'production.change': { decision: 'ESCALATE', requiresHumanApproval: true, known: true },
  'database.write': { decision: 'ESCALATE', requiresHumanApproval: true, known: true },
  'database.migrate': { decision: 'ESCALATE', requiresHumanApproval: true, known: true },
  'secret.access': { decision: 'ESCALATE', requiresHumanApproval: true, known: true },
  'policy.modify': { decision: 'ESCALATE', requiresHumanApproval: true, known: true },

  // Unmodeled: fails closed to human review, never allowed.
  unknown: { decision: 'ESCALATE', requiresHumanApproval: true, known: false },
});

/**
 * The only action strings that may ever classify as ALLOW, listed literally.
 *
 * Kept separate from {@link EXPECTED_POLICY} on purpose: this list is what the
 * "allow iff" assertions compare against, and a reviewer can audit it without
 * reading the wider table.
 */
export const EXPECTED_ALLOWED_ACTIONS: readonly string[] = Object.freeze([
  'repository.inspect',
  'git.status',
  'git.diff',
  'git.log',
  'source.search',
  'test.run',
  'lint.run',
  'typecheck.run',
  'build.run',
  'audit.run',
  'scratch.inspect',
  'github.read',
  'agent.communicate',
]);

/**
 * Action strings that must never classify as ALLOW, listed literally.
 * `git.fetch` is included: V1 does not grant autonomous network egress.
 */
export const EXPECTED_NEVER_ALLOWED_ACTIONS: readonly string[] = Object.freeze([
  'repository.write',
  'git.commit',
  'git.push',
  'git.reset',
  'git.force_push',
  'git.branch_delete',
  'git.fetch',
  'deployment.run',
  'staging.change',
  'production.change',
  'database.write',
  'database.migrate',
  'secret.access',
  'policy.modify',
  'unknown',
]);

/** Every action string this suite expects the kernel to recognise. */
export const EXPECTED_ACTION_NAMES: readonly string[] = Object.freeze(
  Object.keys(EXPECTED_POLICY),
);

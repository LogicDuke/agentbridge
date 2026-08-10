/**
 * Deterministic classification of requested actions into policy outcomes.
 *
 * PR 002 scope: classification only. Nothing here executes, spawns, reads the
 * filesystem, touches the network, or loads configuration. `classifyAction` is
 * a pure function of its single string argument.
 */

import {
  type ActionKind,
  type ActionRiskTier,
  resolveActionKind,
  UNKNOWN_ACTION_KIND,
} from './actions.js';
import {
  DECISION,
  type Decision,
  isAutonomouslyAllowed,
  REASON_CODE,
  type ReasonCode,
} from './decisions.js';

/** The policy assigned to a single action kind. */
export interface ActionPolicyEntry {
  readonly riskTier: ActionRiskTier;
  readonly decision: Decision;
  readonly reason: ReasonCode;
}

const READ_ONLY_POLICY: ActionPolicyEntry = Object.freeze({
  riskTier: 'read-only',
  decision: DECISION.ALLOW,
  reason: REASON_CODE.READ_ONLY_ACTION_ALLOWED,
});

const HUMAN_GATED_POLICY: ActionPolicyEntry = Object.freeze({
  riskTier: 'human-gated',
  decision: DECISION.ESCALATE,
  reason: REASON_CODE.HUMAN_AUTHORITY_REQUIRED,
});

/**
 * Unrecognized actions escalate rather than deny.
 *
 * There is exactly one fail-closed contract in V1: anything not on the
 * read-only allowlist routes to human review. Denying the unmodeled while
 * escalating the merely dangerous would create two different non-allowed
 * outcomes with no operational difference, and would strand an unrecognized
 * request with no route to a human who could resolve it.
 *
 * `riskTier` and `known` still distinguish this case from a modeled dangerous
 * action, so a reviewer can tell "authority required" from "never analyzed".
 */
const UNKNOWN_POLICY: ActionPolicyEntry = Object.freeze({
  riskTier: 'unknown',
  decision: DECISION.ESCALATE,
  reason: REASON_CODE.UNRECOGNIZED_ACTION_ESCALATED,
});

/**
 * V1 default policy table.
 *
 * Typed as a total `Record<ActionKind, ...>` and written out entry by entry on
 * purpose. Adding a kind to the taxonomy breaks this table at compile time,
 * which is the mechanism that stops a new action from silently inheriting
 * `ALLOW`. Do not replace this with a generated map — that would trade the
 * compile-time exhaustiveness check for convenience.
 *
 * These are V1 defaults. A later PR makes them repository-configurable, at
 * which point the `UNKNOWN` entry stays non-overridable.
 */
export const ACTION_POLICY: Readonly<Record<ActionKind, ActionPolicyEntry>> = Object.freeze({
  // Read-only / inspection.
  'repository.inspect': READ_ONLY_POLICY,
  'git.status': READ_ONLY_POLICY,
  'git.diff': READ_ONLY_POLICY,
  'git.log': READ_ONLY_POLICY,
  'source.search': READ_ONLY_POLICY,
  'test.run': READ_ONLY_POLICY,
  'lint.run': READ_ONLY_POLICY,
  'typecheck.run': READ_ONLY_POLICY,
  'build.run': READ_ONLY_POLICY,
  'audit.run': READ_ONLY_POLICY,
  'scratch.inspect': READ_ONLY_POLICY,
  'github.read': READ_ONLY_POLICY,
  'agent.communicate': READ_ONLY_POLICY,

  // Dangerous / human-gated.
  'repository.write': HUMAN_GATED_POLICY,
  'git.commit': HUMAN_GATED_POLICY,
  'git.push': HUMAN_GATED_POLICY,
  'git.reset': HUMAN_GATED_POLICY,
  'git.force_push': HUMAN_GATED_POLICY,
  'git.branch_delete': HUMAN_GATED_POLICY,
  'git.fetch': HUMAN_GATED_POLICY,
  'deployment.run': HUMAN_GATED_POLICY,
  'staging.change': HUMAN_GATED_POLICY,
  'production.change': HUMAN_GATED_POLICY,
  'database.write': HUMAN_GATED_POLICY,
  'database.migrate': HUMAN_GATED_POLICY,
  'secret.access': HUMAN_GATED_POLICY,
  'policy.modify': HUMAN_GATED_POLICY,

  // Unmodeled.
  [UNKNOWN_ACTION_KIND]: UNKNOWN_POLICY,
});

/**
 * The kernel's answer about a single requested action.
 *
 * Every field is a primitive, so the result is JSON-serializable without a
 * custom encoder and survives a round trip unchanged.
 */
export interface ActionClassification {
  /** The action string exactly as requested, preserved for audit. */
  readonly action: string;
  /** The taxonomy member the request resolved to. */
  readonly kind: ActionKind;
  /** True only when the request named a concretely modeled action. */
  readonly known: boolean;
  /** Risk tier of the resolved kind. */
  readonly riskTier: ActionRiskTier;
  /** Policy outcome. */
  readonly decision: Decision;
  /** Stable, machine-readable rationale. */
  readonly reason: ReasonCode;
  /**
   * True whenever the orchestrator may not proceed on its own authority.
   *
   * Always the exact inverse of `decision === 'ALLOW'`, so it can never
   * contradict the decision it accompanies.
   */
  readonly requiresHumanApproval: boolean;
}

/**
 * Classify a requested action against the V1 default policy.
 *
 * Pure, total, and deterministic: the same input always yields an equal
 * result, and no input throws.
 *
 * The only path to `ALLOW` is an exact match against an entry whose policy is
 * `ALLOW`. Unrecognized input resolves to the unknown sentinel, whose policy is
 * `ESCALATE`. There is no `else { allow }` branch, and no fallback branch at all:
 * `resolveActionKind` only ever returns a member of `ActionKind`, and
 * {@link ACTION_POLICY} is total over that union, so the lookup cannot miss.
 * Totality is enforced by the compiler and pinned by a test, rather than by a
 * runtime default that would itself be an untested branch.
 *
 * The key reaching {@link ACTION_POLICY} is always one of the taxonomy's
 * literal members, never raw caller input, so attacker-supplied keys such as
 * `'constructor'` cannot reach the object at all — `resolveActionKind` screens
 * them through a prototype-free `Map` first.
 *
 * @param requestedAction Untrusted action identifier supplied by an agent.
 */
export function classifyAction(requestedAction: string): ActionClassification {
  const kind = resolveActionKind(requestedAction);
  const policy = ACTION_POLICY[kind];

  return Object.freeze({
    action: requestedAction,
    kind,
    known: kind !== UNKNOWN_ACTION_KIND,
    riskTier: policy.riskTier,
    decision: policy.decision,
    reason: policy.reason,
    requiresHumanApproval: !isAutonomouslyAllowed(policy.decision),
  });
}

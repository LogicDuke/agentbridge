/**
 * Action taxonomy for the AgentBridge domain kernel.
 *
 * This module models *what an agent may ask for*. It executes nothing, and it
 * imports nothing outside this domain.
 *
 * Action identifiers are matched exactly. No trimming, case folding, aliasing,
 * or fuzzy matching is performed, because lenient matching on a security
 * boundary is a privilege-escalation vector: `"GIT.STATUS "` must not become
 * the allowed `git.status`.
 *
 * The taxonomy is deliberately extensible but never open-ended. Adding an
 * action kind here forces a matching policy entry in `classification.ts`,
 * so new actions cannot silently inherit an existing outcome.
 */

/**
 * Actions that do not mutate a managed repository or any external system.
 *
 * `test.run`, `lint.run`, `typecheck.run`, `build.run`, and `audit.run` are
 * classified read-only with respect to the *managed repository*: they are
 * verification commands whose outputs are evidence. PR 002 does not execute
 * them; a later PR will, under its own sandboxing rules.
 */
export const READ_ONLY_ACTION_KINDS = [
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
] as const;

export type ReadOnlyActionKind = (typeof READ_ONLY_ACTION_KINDS)[number];

/**
 * Actions that carry authority: they mutate repository, infrastructure, or
 * data state, expose secrets, or change the policy that governs the kernel.
 *
 * `git.fetch` sits here despite reading nothing from the working tree. It
 * opens an outbound network connection to a remote and writes to the local
 * `.git` directory — downloading objects and moving remote-tracking refs — so
 * it is neither side-effect free nor purely local. V1 gates it rather than
 * granting the orchestrator autonomous network egress.
 */
export const HUMAN_GATED_ACTION_KINDS = [
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
] as const;

export type HumanGatedActionKind = (typeof HUMAN_GATED_ACTION_KINDS)[number];

/** Sentinel for any action the taxonomy does not model. */
export const UNKNOWN_ACTION_KIND = 'unknown';

export type UnknownActionKind = typeof UNKNOWN_ACTION_KIND;

/** An action the taxonomy models concretely. */
export type ModeledActionKind = ReadOnlyActionKind | HumanGatedActionKind;

/** Every action kind the kernel can resolve to, including the unknown sentinel. */
export type ActionKind = ModeledActionKind | UnknownActionKind;

/** Risk tier a resolved action belongs to. */
export type ActionRiskTier = 'read-only' | 'human-gated' | 'unknown';

/** Every concretely modeled action kind. Excludes the unknown sentinel. */
export const MODELED_ACTION_KINDS: readonly ModeledActionKind[] = [
  ...READ_ONLY_ACTION_KINDS,
  ...HUMAN_GATED_ACTION_KINDS,
];

/** Every member of the {@link ActionKind} union, including the unknown sentinel. */
export const ALL_ACTION_KINDS: readonly ActionKind[] = [
  ...MODELED_ACTION_KINDS,
  UNKNOWN_ACTION_KIND,
];

/**
 * Membership is backed by a `Map`, not a plain object.
 *
 * A plain-object lookup inherits `Object.prototype`, so `'toString'`,
 * `'constructor'`, and `'__proto__'` would read as modeled actions and could
 * resolve to a truthy policy entry. A `Map` has no prototype chain for keys.
 */
const MODELED_ACTION_LOOKUP: ReadonlyMap<string, ModeledActionKind> = new Map(
  MODELED_ACTION_KINDS.map((kind) => [kind, kind] as const),
);

/** Type guard: does this untrusted string name a concretely modeled action? */
export function isModeledActionKind(value: string): value is ModeledActionKind {
  return MODELED_ACTION_LOOKUP.has(value);
}

/**
 * Resolve an untrusted, agent-supplied action string to a taxonomy member.
 *
 * Anything unrecognized resolves to {@link UNKNOWN_ACTION_KIND}, including the
 * literal string `'unknown'` — the sentinel names the absence of a model, so
 * requesting it by name is still an unmodeled request. Never throws.
 */
export function resolveActionKind(requestedAction: string): ActionKind {
  return MODELED_ACTION_LOOKUP.get(requestedAction) ?? UNKNOWN_ACTION_KIND;
}

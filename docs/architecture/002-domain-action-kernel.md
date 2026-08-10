# Domain & Action Kernel (PR 002)

Status: V1 defaults. Superseded only by an explicit architecture decision.

## Scope

PR 002 adds the first security-domain kernel: pure TypeScript models for
*requested operations* and a deterministic classifier that maps them to policy
outcomes.

**Classification only. No operation is executed.** The kernel contains no
subprocess or shell execution, no Git invocation, no persistence or database
layer, no GitHub API, no model adapters, no network calls, no configuration
loading, and no repository writes. `classifyAction` is a pure function of one
string argument.

## Authority model

Agents produce requests and recommendations. They do not produce authority.
The kernel decides the policy classification of a request; a human — or, later,
an explicitly configured repository policy — grants the authority to act on it.

This mirrors the V1 boundary in `001-v1-architecture.md`: automate coordination
before automating authority.

## Modules

| Module | Responsibility |
| --- | --- |
| `src/domain/actions.ts` | Action taxonomy, risk tiers, resolution of untrusted strings |
| `src/domain/decisions.ts` | `Decision` and `ReasonCode` vocabularies |
| `src/domain/classification.ts` | V1 policy table and the `classifyAction` function |

## Decisions

| Decision | Meaning |
| --- | --- |
| `ALLOW` | The orchestrator may proceed autonomously. |
| `ESCALATE` | Legitimate operation, but authority belongs to a human. |
| `DENY` | Refused. No in-band autonomous or approval path exists. |

`ALLOW` is the only autonomous outcome, so any decision variant added later is
non-autonomous by construction.

## V1 defaults

Read-only / inspection actions classify as `ALLOW`:

`repository.inspect`, `git.status`, `git.diff`, `git.log`, `git.fetch`,
`source.search`, `test.run`, `lint.run`, `typecheck.run`, `build.run`,
`audit.run`, `scratch.inspect`, `github.read`, `agent.communicate`

The verification actions (`test.run`, `lint.run`, `typecheck.run`, `build.run`,
`audit.run`) are read-only *with respect to the managed repository*: their
outputs are evidence. PR 002 does not run them; a later PR will, under its own
sandboxing rules.

Dangerous actions classify as `ESCALATE`:

`repository.write`, `git.commit`, `git.push`, `git.reset`, `git.force_push`,
`git.branch_delete`, `deployment.run`, `staging.change`, `production.change`,
`database.write`, `database.migrate`, `secret.access`, `policy.modify`

### Why dangerous actions are ESCALATE and unknown actions are DENY

Dangerous actions get `ESCALATE` rather than `DENY` because they are legitimate,
well-understood operations that merely require authority the orchestrator does
not hold. The kernel knows what `git.push` means, so it can describe the request
to a human accurately enough for informed approval. `DENY` would collapse
"needs a human" into "impossible" and remove the approval path the product
depends on.

Unknown actions get `DENY`, not `ESCALATE`, for the opposite reason: the kernel
cannot describe an unmodeled string to a human approver, so escalating it would
invite rubber-stamp approval of something nobody has analyzed. The remedy for an
unknown action is to model it deliberately in the taxonomy — a reviewed code
change — not an ad-hoc runtime approval.

Both outcomes set `requiresHumanApproval: true`, which answers the single
question "may the orchestrator proceed on its own?"

## The security invariant

**UNKNOWN never resolves to ALLOW.**

Three independent mechanisms enforce it:

1. **Exact matching.** Action identifiers are compared verbatim. No trimming,
   case folding, aliasing, or fuzzy matching, because lenient matching on a
   security boundary is a privilege-escalation vector — `"GIT.STATUS "` must
   never become the allowed `git.status`.
2. **Explicit allowlist, no fallback branch.** Unrecognized input resolves to
   the unknown sentinel, whose policy is `DENY`. The policy table is a total
   `Record<ActionKind, ActionPolicyEntry>`, so the lookup cannot miss and needs
   no runtime default — totality is enforced by the compiler and pinned by a
   test rather than by a defensive branch that no test could exercise. There is
   no `else { allow }` anywhere.
3. **Compile-time exhaustiveness.** Because the table is total over the
   `ActionKind` union and written entry by entry, adding an action kind breaks
   the build until that kind is deliberately classified. A new action cannot
   silently inherit `ALLOW`.

Lookups also go through a `Map` rather than a plain object, so attacker-supplied
keys such as `__proto__`, `constructor`, or `toString` cannot resolve to an
inherited prototype value.

Classification results and the policy table are frozen, so a denial cannot be
upgraded to `ALLOW` by mutating a returned object.

## Result shape

`ActionClassification` carries the requested action verbatim, the resolved
taxonomy kind, whether the action is known, its risk tier, the decision, a
stable machine-readable reason code, and whether human approval is required.
Every field is a primitive, so the result is JSON-serializable and survives a
round trip unchanged.

## Not a policy engine

This is a kernel, not the Policy Engine. It has no rules DSL, no per-repository
overrides, no evidence binding, no approval workflow, and no audit sink.

These defaults are **V1 defaults**. A later PR makes them repository-configurable
so that project-specific restrictions live in repository policy rather than
hard-coded engine behavior. When that happens, the unknown-action entry remains
non-overridable: configuration may narrow authority, never widen it to allow the
unmodeled.

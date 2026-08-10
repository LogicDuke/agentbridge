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
| `ESCALATE` | Not permitted autonomously; routed to human review. |
| `DENY` | Refused outright, with no human review path. |

`ALLOW` is the only autonomous outcome, so any decision variant added later is
non-autonomous by construction.

**V1 defaults never emit `DENY`.** `DENY` stays in the vocabulary because the
decision model must be able to express an outright refusal once policy becomes
repository-configurable, but nothing in V1 selects it. See "One fail-closed
contract" below.

## V1 defaults

Read-only / inspection actions classify as `ALLOW`:

`repository.inspect`, `git.status`, `git.diff`, `git.log`, `source.search`,
`test.run`, `lint.run`, `typecheck.run`, `build.run`, `audit.run`,
`scratch.inspect`, `github.read`, `agent.communicate`

The verification actions (`test.run`, `lint.run`, `typecheck.run`, `build.run`,
`audit.run`) are read-only *with respect to the managed repository*: their
outputs are evidence. PR 002 does not run them; a later PR will, under its own
sandboxing rules.

Everything else classifies as `ESCALATE`:

`repository.write`, `git.commit`, `git.push`, `git.reset`, `git.force_push`,
`git.branch_delete`, `git.fetch`, `deployment.run`, `staging.change`,
`production.change`, `database.write`, `database.migrate`, `secret.access`,
`policy.modify`

### Why `git.fetch` is gated

`git.fetch` reads nothing from the working tree, which makes it look like an
inspection action, but it opens an outbound network connection to a remote and
writes to the local `.git` directory — downloading objects and moving
remote-tracking refs. It is neither side-effect free nor purely local. V1 gates
it rather than granting the orchestrator autonomous network egress. If a later
PR wants read-only evidence gathering over the network, that is a deliberate
policy decision, not a default.

### One fail-closed contract

Every non-allowed outcome — dangerous *and* unrecognized — is `ESCALATE` with
`requiresHumanApproval: true`. There is exactly one way to fail, and it always
routes to a human.

Dangerous actions escalate because they are legitimate operations that merely
require authority the orchestrator does not hold. Unrecognized actions escalate
because the alternative strands them: denying an unmodeled string outright
leaves the request with no route to a human who could resolve it, and creates a
second non-allowed outcome with no operational difference from the first.

The two cases stay distinguishable without a second decision value. `known` is
`false` and `riskTier` is `unknown` for unrecognized input, and the reason code
differs (`UNRECOGNIZED_ACTION_ESCALATED` versus `HUMAN_AUTHORITY_REQUIRED`), so
a reviewer can tell "authority required" from "never analyzed". The durable fix
for a recurring unknown action is still to model it deliberately in the
taxonomy, which is a reviewed code change.

## The security invariant

**UNKNOWN never resolves to ALLOW.**

Four independent mechanisms enforce it:

1. **Exact matching.** Action identifiers are compared verbatim. No trimming,
   case folding, aliasing, or fuzzy matching, because lenient matching on a
   security boundary is a privilege-escalation vector — `"GIT.STATUS "` must
   never become the allowed `git.status`.
2. **Explicit allowlist, no fallback branch.** Unrecognized input resolves to
   the unknown sentinel, whose policy is `ESCALATE`. The policy table is a total
   `Record<ActionKind, ActionPolicyEntry>`, so the lookup cannot miss and needs
   no runtime default — totality is enforced by the compiler and pinned by a
   test rather than by a defensive branch that no test could exercise. There is
   no `else { allow }` anywhere.
3. **Compile-time exhaustiveness.** Because the table is total over the
   `ActionKind` union and written entry by entry, adding an action kind breaks
   the build until that kind is deliberately classified. A new action cannot
   silently inherit `ALLOW`.
4. **Independent test expectations.** `tests/domain/expected-policy.ts` declares
   the expected outcome for every action by hand and imports nothing from
   `src/`. Tests compare production against that table rather than deriving
   expectations from `READ_ONLY_ACTION_KINDS` or `ACTION_POLICY`, so a
   production mistake — swapping `git.push` into the allowed set, moving
   `git.status` out of it, or adding an action without classifying it — fails
   the suite instead of being ratified by it.

Lookups also go through a `Map` rather than a plain object, so attacker-supplied
keys such as `__proto__`, `constructor`, or `toString` cannot resolve to an
inherited prototype value.

Classification results and the policy table are frozen, so an escalation cannot
be upgraded to `ALLOW` by mutating a returned object.

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

# Repair Job Authority Envelope and Merge Barrier (Cockpit C1)

Status: V1. Superseded only by an explicit architecture decision.

Numbered outside the `001`–`006` series on purpose: C1 is the first Cockpit
bootstrap record, not the next step of the V1 pipeline, and it must not collide
with the numbering the Autoflow and transport PRs are using.

## Purpose

C1 establishes what a bounded autonomous repair job **may be authorized to do**,
before AgentBridge has repository-write or agent-execution capability.

    trusted job configuration + exact operation operands -> authorization decision

It answers exactly one question:

> May *this* bounded repair job perform *this exact operation*, with *these
> exact operands*, once?

**C1 performs no operation.** No filesystem, git, worktree, commit, push, GitHub
API, pull-request creation, reviewer trigger, merge, subprocess, `child_process`,
shell, PowerShell, Bash, process transport, network, database, SQLite, Evidence
Store, REST API, HTTP server, dashboard, frontend, queue, poll, retry, timer,
scheduler, Promise, or async of any kind. No clock is read and no identifier is
generated. `authorizeJobOperation` is a pure function of its two arguments.

The security boundary is deliberately established **first**, so that a later
execution layer has to be written through it rather than around it.

## Relationship to the frozen V1 architecture

The V1 statement stands unchanged: *managed repositories remain read-only.* C1
does not rewrite V1 as write-capable, and nothing in this PR grants any write.

What C1 adds is an **explicit future authority model**. A later Cockpit
execution layer **may** receive narrowly scoped repair authority, and if it ever
does, it may only receive it through this boundary. Outside a valid repair-job
authorization envelope, the existing read-only boundary is exactly as it was.

C1 imports nothing from PR 002–PR 006 except for a documented bound-parity test,
and changes none of them:

| Layer | Owns | C1 |
| --- | --- | --- |
| PR 002 | action taxonomy, deterministic classification, unknown fails closed | unchanged, un-imported |
| PR 003 | `ActionRequest`, `PolicyGate`, agent requests are not authority, human `ApprovalRecord` is separate | unchanged, un-imported |
| PR 004 | commit-bound evidence, `CURRENT`/`STALE`/`INVALID` freshness | unchanged, un-imported |
| PR 005 | provider-neutral review ingestion, findings are evidence not authority | unchanged, un-imported |
| PR 006 | provider-neutral `AgentInvocation`, provider identity inert, claims untrusted | unchanged, un-imported |

C1 answers a different question from each of them. It does not reclassify
actions, does not judge freshness, does not ingest findings, and does not record
invocations.

**C1 contains no workflow state machine.** No Autoflow implementation, no
states, no transitions, no `READY_FOR_MERGE`. The proposed Autoflow state
machine lives in its own PR and this branch neither reads from nor depends on
it.

## The core invariant

> A repair job is a bounded capability envelope. Authority is derived from
> trusted job configuration and exact operation operands, and from nothing else.

Agent identity, provider name, rationale, prose, metadata, claimed success, and
privileged-sounding labels cannot increase authority. The strongest form of that
guarantee is structural rather than defensive: **there is no field typed to
accept them.** `RepairJobAuthorization` has no metadata bag. `JobOperationRequest`
has no `agentId`, `providerId`, `rationale`, `metadata`, `role`, `approval`,
`priority`, `confidence`, or `override`. The normalizer reads no such key, so a
value planted at runtime has nowhere to land and nothing to influence.

Everything fails closed.

## Trust boundary

| Input | Trust | Contributes |
| --- | --- | --- |
| `RepairJobAuthorization` | **Trusted configuration** | the entire authority envelope |
| `JobOperationRequest` | **Untrusted** | which operation, and which exact operands |

The request's binding fields (`jobId`, `repositoryId`, `parentPullRequestId`,
`parentHeadSha`) are *claims*, never authority. Their only purpose is to make a
request that names the wrong repository, pull request, job, or commit
**refusable** instead of silently re-targeted at whatever the job happens to
say. Each is compared by exact string equality against the trusted snapshot, and
an absent claim fails exactly like a wrong one.

The job envelope itself is trusted but still read defensively, following PR 004's
treatment of `EvidenceTarget`: trusted does not mean dereferenceable without
care.

## The authorization envelope

`RepairJobAuthorization` binds one repair job to:

| Field | Binds |
| --- | --- |
| `jobId` | the job's own identity |
| `policyVersion` | which policy authorized the envelope; part of permit identity |
| `repositoryId` | the one repository this job may ever touch |
| `parentPullRequestId` | the protected parent feature pull request |
| `protectedParentRef` | the parent integration ref, which no operation may write; canonical `refs/heads/<name>` |
| `parentHeadSha` | the exact commit the job is bound to |
| `findingSource` | where the finding came from; a provider-neutral label, inert |
| `findingId` | the finding being repaired |
| `findingHeadSha` | the commit the finding was verified against |
| `repairBranch` | the isolated repair branch; canonical `refs/heads/<name>` |
| `repairWorktreeId` | the isolated repair worktree |
| `authorizedPaths` | exact repository-relative paths, not a prefix or glob |
| `authorizedCommandClasses` | verification classes, never command strings |
| `repairAgentId` | who repairs; audit only, never authority |
| `independentValidatorId` | who must independently validate |

Every field is required. Trusted configuration is **all-or-nothing**: there is
no partially configured job, and no field that degrades silently. A job with any
invalid field authorizes nothing, and `findInvalidRepairJobFields` reports the
offending names in declaration order.

Two structural invariants are enforced as configuration validity rather than as
a runtime check that could be forgotten:

- `repairBranch` and `protectedParentRef` are **different branch refs** under
  C1's canonical comparison rule. A job whose repair branch *is* the protected
  parent is not a quarantined repair; it is a direct write to protected history
  wearing a repair job's name. This compares canonical ref *names*; establishing
  that two accepted names resolve to distinct targets in a repository is the
  later trusted execution boundary's obligation, described below.
- `independentValidatorId !== repairAgentId`. A repair agent that is its own
  validator defeats the quarantine the whole pipeline exists to enforce.

### Branch refs have exactly one accepted spelling

"Different branch refs", not "different strings". Git resolves `main`,
`heads/main`, and `refs/heads/main` to one and the same ref, so a boundary that
compares ref strings has three names for one authority target. Configuring
`protectedParentRef: 'refs/heads/main'` beside `repairBranch: 'main'` would
otherwise read as a quarantined repair, and a `repair.push` naming `main` would
pass every check and produce an `ExecutionPermit` whose ref denotes the protected
branch.

C1 cannot ask git which ref a shorthand resolves to — it runs no git, spawns no
subprocess, opens no file, and observes no repository, and the answer depends on
what exists in a repository at the moment the name is used. So C1 does not
resolve; it **narrows**. `readCanonicalBranchRef` accepts exactly one spelling
and refuses every other spelling of the same branch as malformed:

- the literal, case-sensitive prefix `refs/heads/`, followed by a non-empty name
- name segments separated by single `/`, each non-empty
- segment characters drawn only from `A-Z`, `a-z`, `0-9`, `-`, `_`, and `.`
- no segment beginning or ending with `.`, no `..` anywhere, and no segment
  ending in `.lock` in any ASCII case

The property that buys is a property of ref *names*, not of repository state:
**two accepted refs are the same canonical ref name if and only if they are equal
strings.** That is what closes caller-controlled textual aliasing and what makes
the distinctness invariant mean something at this layer. It is not a claim that
two unequal canonical names denote two distinct targets in a repository; see
*What canonical ref names do and do not prove* below. The conservative ASCII
character set is part of the guarantee, not a convenience — it removes Unicode
normalisation, under which an NFC and an NFD spelling of one name are unequal
strings a filesystem-backed loose ref can resolve to a single ref, and it removes
`~`, `^`, `:`, `?`, `*`, `[`, `\`, `@{`, and whitespace in one rule. Nothing is
normalised, prefixed, or case-folded on the way in: a value is accepted exactly
as supplied or refused.

The same reader is applied to **every** security-relevant ref position — the two
job fields, and the `ref`, `sourceRef`, and `targetRef` request operands — so
validation can never compare a canonical configured value against an
uncanonical request operand. A supplied operand that is not canonical is refused
`REF_MALFORMED` before any comparison, rather than compared as though it were a
different branch.

One relationship is enforced at authorization time, because it is about
freshness rather than shape: `findingHeadSha` must equal `parentHeadSha`, or
every operation is denied `FINDING_SHA_STALE`. A repair derived from a finding
about some other commit is a repair of something that may no longer be there.
PR 004 remains the owner of `CURRENT` versus `STALE` for evidence; this is the
narrower structural check that the job's own two SHAs agree, which C1 can decide
without importing that kernel or producing a second answer to PR 004's question.

### What canonical ref names do and do not prove

Stated precisely, because overclaiming here would be worse than not checking.

**Proved.** An accepted value is a string in the one canonical `refs/heads/<name>`
shape, and two accepted values that remain unequal under C1's documented
comparison rule are two different canonical ref names. Caller-supplied textual
aliasing is closed within that structural authority: the originally proven bypass
— configuring or requesting `main`, `heads/main`, and `refs/heads/main` against
one another so the protected parent could be presented as a different branch — is
refused as `REF_MALFORMED` before any comparison, and a configured pair that
collides under the comparison rule invalidates the job rather than authorizing it.

**Not proved, and not claimed.** That two different canonical ref names are two
distinct branch targets in a repository. C1 does not establish repository-resolved
ref identity, does not detect whether an accepted ref is symbolic, does not
resolve a symbolic ref's target, does not determine whether two distinct canonical
names ultimately dereference to the same repository target, and observes no live
repository state. Two independent reasons stand:

- **Symbolic refs.** A repository may hold a canonical-looking ref — say
  `refs/heads/repair` — that is itself a symbolic ref to `refs/heads/main`.
  Whether such a ref exists, and what it points at, is repository state at the
  moment the name is used. C1 runs no git, spawns no subprocess, opens no file,
  and observes no repository, so no string comparison it performs can decide it.
- **Filesystem identity.** Git stores loose refs as files, so on a
  case-insensitive filesystem `refs/heads/Main` and `refs/heads/main` can be one
  ref while comparing unequal. C1 observes no filesystem, so it refuses the
  ambiguous case instead of pretending it away: the job's two configured refs are
  additionally compared with ASCII case folded, and a pair that differs only by
  case is rejected as malformed configuration.

The case fold is a conservative refusal, not a resolution. It narrows one
filesystem-dependent collision that is characterisable from the strings alone; it
establishes nothing about symbolic refs, which are not decidable from a string at
all.

**A future trusted repository/Git execution boundary must close the rest.** C1
establishes structural canonical ref-name authority; it cannot establish live
repository identity, cannot bind the target a mutation will actually reach, and
cannot enforce anything across a concurrent change. Before acting on any authority
an `ExecutionPermit` records — not only operations that write a ref — that
boundary must satisfy the requirements below, and must **fail closed** — refuse
the operation — wherever a required identity cannot be safely established,
wherever resolution cycles or is otherwise indeterminate, or wherever an effective
identity is or dereferences to a ref the operand's role is not authorized to
denote.

*The protected-parent rule is role-bound.* Protected-parent identity is forbidden
only where it is unauthorized for the operand's role — which is every role but
one. The effective mutation target of a `repair.commit` or a `repair.push`, and a
`repair.change_request` `sourceRef`, must each be the authorized repair ref, so
for all three an effective identity that is or dereferences to the protected
parent is a refusal. A `repair.change_request` `targetRef` is the single operand
whose *required* effective identity **is** the protected parent ref — the same
operand C1's string layer already singles out as the only one that may name it —
so for that role, and only that role, reaching the protected parent is the
authorized outcome and reaching anything else is the refusal. Stated role-blind
instead, the rule would forbid the one direction the quarantine depends on. No
role widens past this: an operand authorized to denote the protected parent as a
change-request *target* acquires no authority to denote it anywhere else, and the
exemption never reaches an operand that would mutate the parent.

*Which identity is compared.* The isolation question is about the **effective
ref-name referent** — the terminal ref reached by resolving a symbolic-ref chain —
not about commit-object identity. A freshly created repair branch may legitimately
point at the **same commit object** as the protected parent until its first repair
commit, so distinct commit OIDs are neither necessary nor sufficient: two
different branch refs may share one commit OID, and commit-object equality does not
make two refs the same authority target. The boundary must therefore compare
effective ref-name referents, and must not rest the check on whether two refs
currently resolve to the same commit. What that comparison must *yield* is fixed
by the operand's role: for an operand whose required identity is the authorized
repair ref, a symbolic or effective ref-name identity that aliases the protected
parent must be detected and rejected; for the one operand whose required identity
is the protected parent ref — the `repair.change_request` `targetRef` — the alias
to detect and reject is the converse one, an effective identity that is not the
protected parent ref.

*Binding the effective mutation target.* A resolved ref *name* is not the target a
mutation will advance, and the boundary must bind the two before it acts:

- **`repair.commit`.** A commit advances the branch reached through the authorized
  worktree's effective `HEAD` referent, not whatever ref name the request carried.
  The boundary must bind that effective `HEAD` referent to the authorized repair
  ref and refuse to commit if the worktree is detached, attached to the protected
  parent, attached to any other ref, or its safe binding cannot be established.
- **`repair.push`.** A push carries both a source and a destination ref, and the
  authorized repair ref governs **both**. The boundary must bind the push's
  **effective source ref** and its **effective destination ref** — each by its
  effective ref-name referent, not by commit-object identity — to the authorized
  repair ref, and must not let a caller-selected source or destination refspec
  redirect either half. The source must be **present**: an absent source, the
  deletion refspec `:refs/heads/…`, is not a `repair.push` at all but a
  `branch.delete`, which is denied, so a destination that still names the repair
  ref does not make it authorized. No alternate branch, tag, or commit-ish may
  stand in for the authorized repair ref on either half. The receiving/mutation
  side must fail closed if either effective half is the protected parent, is not
  provably the authorized repair ref, or ceases to be between the check and the
  push — the authorized source-to-destination relationship must hold through to
  that consuming boundary, not only at an earlier pre-check. An ordinary
  `refs/heads/repair:refs/heads/repair` push, whose effective source and
  destination are both the authorized repair ref, remains authorized.

*Operands that set direction without mutating a ref.* The obligation is not
limited to ref-mutating operations. `repair.change_request` mutates no ref, but
its `sourceRef` and `targetRef` fix the effective direction of the stacked
validation request, which the quarantine requires to run **from** the repair
branch **to** the protected parent. The boundary must establish that the effective
source identity is the authorized repair ref and the effective target identity is
the protected parent ref, reject a symbolic or effective alias that changes that
direction, and fail closed if either effective identity cannot be safely
established. Because this operation performs no ref update to guard, the boundary
that consumes these identities is the change-request/provider creation — or
update — request itself, and the established source and target identities must be
**bound through to that provider request**: the provider must create the request
from exactly the authorized effective source and target. Provider-side resolution
of the supplied ref names is not itself forbidden — a create/update API may have
to resolve the source and target names against its own authoritative repository
state — but it must yield exactly those authorized effective identities: it must
not let re-resolution, ambient repository state, or any substitution cause the
request to be created from, or to consume, a **materially different** effective
source or target than the one authorized. Resolution that preserves the exact
authorized source-to-target relationship conforms; resolution that would consume
a materially different effective identity does not. If that authorized
source-to-target relationship cannot be maintained through to the provider
request — because an effective identity has changed, cannot be safely
re-established, or cannot be shown equivalent to the authorized one at that
boundary — the boundary must fail closed and create no change request.

*Concurrency is not closed by a pre-check.* A resolve-then-check-then-act
sequence is **not** an atomic security guarantee: an effective ref or referent can
change between the comparison and the moment the identity is consumed, so a name
observed as an ordinary repair ref can become symbolic to the protected parent —
or a target can cease to denote it — after the check and before the act. The
invariant must be enforced **at the actual trusted execution boundary that
consumes each identity, not only where a ref is mutated**, by a mechanism whose
semantics prevent an unchecked identity change between the comparison and that
consumption — not by an earlier client-side observation the boundary later trusts.
That consuming boundary differs by operation and the obligation is identical at
each: for `repair.commit` it is the commit mutation boundary, for `repair.push`
the push receiving/mutation boundary, and for `repair.change_request` — which
mutates no ref — the change-request/provider creation boundary at which the source
and target identities are actually consumed. An operation whose authorized
effective-identity relationship cannot be held through to its consuming boundary
must fail closed.

This document states the required invariant, not an implementation: it names no
git command, lock, or transaction mechanism, and it claims no more atomicity than
the eventual executor's own primitives can actually provide.

Writing that obligation down adds no runtime git authority to C1 and grants no new
authority anywhere: C1 gains no git invocation, no filesystem access, no
subprocess, and no network, and remains pure TypeScript.

## Operations are structured, not named

A generic action name is not sufficient for Cockpit write authority. There is no
`repository.write`, no `git.run`, and no `shell.exec`: an operation whose
authority cannot be checked against an exact operand has no place in the model.

| Operation | Required operands | Authorized when |
| --- | --- | --- |
| `source.read` | worktree, path | worktree is the repair worktree and path is in scope |
| `source.edit` | worktree, path | worktree is the repair worktree and path is in scope |
| `verification.run` | worktree, command class | class is modeled *and* configured for this job |
| `repair.commit` | worktree, ref | ref is exactly the repair branch |
| `repair.push` | ref, non-force | ref is exactly the repair branch and the push is not forced |
| `repair.change_request` | source ref, target ref | repair branch → protected parent ref |

Every ref operand — the `repair.commit` and `repair.push` ref, and the
`repair.change_request` source and target refs alike — is read through the same
canonical branch-ref reader the job envelope uses, so "exactly the repair branch"
is a claim about a canonical ref name and not about a caller's chosen spelling. It
is not a claim about the effective ref-name referent that name reaches in a
repository, about which ref a commit or push would actually advance, or about the
effective direction of a change request — all of which only the later trusted
execution boundary can establish.

`repair.change_request` is the **only** operation that may name the protected
parent ref, and only as a change-request *target*. Opening a change request
against a ref does not mutate it: the parent stays untouched until an operator
merges. Every write-shaped operation additionally denies
`PROTECTED_REF_MUTATION` specifically when the parent ref is named, rather than
falling through to the generic "not the repair branch" refusal, so the audit
record distinguishes a mistake from an escape attempt.

## Decision model

| Decision | Meaning |
| --- | --- |
| `ALLOW_ONCE` | this exact normalized operation, under this exact job binding, may be executed **once**, under the accompanying `ExecutionPermit` |
| `DENY` | refused; nothing at this layer converts it into an allow |
| `OPERATOR_REQUIRED` | outside every autonomous envelope; only a human operator, through a separate type, could ever authorize it |

`ALLOW_ONCE` is not a standing permission and does not generalise to a similar
operation, a later HEAD, or another job. `OPERATOR_REQUIRED` is **not** "escalate
and retry": the evaluator never returns a permit alongside it, and there is no
argument through which an approval could arrive to change it.

The vocabulary deliberately does not reuse PR 003's `ALLOW`/`ESCALATE`/`DENY` or
its `AUTONOMOUS` outcome. Those answer "what is this action?" for a read-only V1;
this answers "may this bounded job perform this exact operation once?", which is
a different question over different operands. Reusing the words would invite a
later reader to treat the two as interchangeable.

`ApprovalRecord` is **not** reused to represent automatic Cockpit permission. It
is human decision data about a PR 003 `ActionRequest`; making it double as a
machine authorization would turn every existing approval into a candidate
capability. The automatic machine authorization is `ExecutionPermit`, a separate
type with separate identity.

Every refusal carries a stable, machine-readable reason:
`MERGE_IS_OPERATOR_ONLY`, `OPERATION_FORBIDDEN`, `OPERATION_UNKNOWN`,
`OPERATION_UNREADABLE`, `JOB_ENVELOPE_INVALID`, `JOB_MISMATCH`,
`REPOSITORY_MISMATCH`, `PARENT_PULL_REQUEST_MISMATCH`, `PARENT_HEAD_MISMATCH`,
`FINDING_SHA_STALE`, `OPERAND_MISSING`, `PATH_MALFORMED`, `PATH_NOT_AUTHORIZED`,
`WORKTREE_NOT_AUTHORIZED`, `COMMAND_CLASS_NOT_AUTHORIZED`, `REF_MALFORMED`,
`PROTECTED_REF_MUTATION`, `REF_NOT_REPAIR_BRANCH`,
`CHANGE_REQUEST_TARGET_INVALID`, `FORCE_PUSH_FORBIDDEN`.

## The merge barrier

**Merge is operator-only. This is a permanent AgentBridge Cockpit invariant
unless an explicit later architecture decision changes it.**

There must be no path where an agent request, plus a repair job, plus provider
identity, plus metadata, plus a human `ApprovalRecord`, produces an autonomous
merge permission. C1 makes that structural rather than conventional, on five
independent levers, any one of which would be sufficient:

1. **Type level.** `merge` is not a member of `RepairAuthorizableOperation`.
   `ExecutionPermit.operation` is typed to that union, so **a merge permit does
   not type-check.** A test asserts the compile error with `@ts-expect-error`.
2. **Single allow site.** `ALLOW_ONCE` is produced at exactly one `return` in
   the codebase, reachable only after two type guards have narrowed the
   operation to `RepairAuthorizableOperation`.
3. **First check.** The merge check is the first decision made, above the job
   envelope validation and every binding and operand check, so no envelope,
   binding, or operand state can precede or condition it.
4. **No approval parameter.** `authorizeJobOperation` takes exactly two
   arguments. There is no parameter through which an `ApprovalRecord` —
   approved or otherwise — can reach the evaluator. A test pins the arity.
5. **No readable identity.** Nothing reads an agent id, provider id, rationale,
   or metadata, because no such field exists on either argument.

The maximum autonomous state a future workflow may reach is therefore "ready for
an operator to merge". **C1 implements no such state and no state machine**; it
establishes only that ordinary job authority has no permission that could become
merge.

`auto_merge.enable` is `DENY`, not `OPERATOR_REQUIRED`, and the distinction is
deliberate: enabling auto-merge delegates the merge decision away from the moment
HEAD is final. An operator asking for auto-merge is asking to not be the
operator.

### Mandatory hard denials

Modeled explicitly, so refusing them is a deterministic decision with a stable
reason rather than an accident of falling through to `unknown`:

`merge` (operator-only), `auto_merge.enable`, `parent_ref.write`, `push.force`,
`history.rewrite`, `branch.delete`, `policy.modify`, `secret.access`,
`deployment.run`, `staging.change`, `production.change`, `database.write`,
`database.migrate`.

Cross-repository, cross-pull-request, and wrong-HEAD operations are refused by
binding rather than by name, because they are not distinct operations — they are
in-scope operations pointed somewhere else. Unrelated file writes are refused by
file scope. Unknown operations are refused as `OPERATION_UNKNOWN`.

Force push is denied twice over: by name as `push.force`, and as an operand
check on `repair.push` that runs *before* the ref is examined, so a forced push
to the authorized repair branch is refused for being forced rather than
accidentally allowed. The force flag fails closed: only an absent or literally
`false` value is not a force, so `0`, `''`, `null`, `'false'`, and an object are
all forces.

A privileged provider or agent label — `root`, `system`, `admin`,
`agentbridge-internal` — changes none of these outcomes. A test sweeps every
label across every job shape and every operand shape.

### Operator merge authority, defined but not built

`OperatorMergeAuthorization` records the shape of the only thing that may ever
authorize a merge. **No function in AgentBridge produces one.** There is no
factory, no builder, and no evaluator output that contains one. The boundary that
turns a human decision into a record of this shape does not exist yet, and
building it is an explicit later decision rather than an implementation detail of
whichever layer needs it first.

`operatorMergeAuthorizes` checks **binding, and only binding**. The distinction
between what C1 proves and what a later layer must enforce is stated exactly,
because overclaiming here would be worse than not checking.

**Proved by a `true` result.** The candidate record carries the required
structural fields as readable identifiers; its `singleUse` is literally `true`;
and its `repositoryId`, `pullRequestId`, and `headSha` are exactly equal to the
corresponding fields of the **supplied** `MergeTarget` — including
`MergeTarget.currentHeadSha`. Every comparison is exact string equality, so a
candidate can never cover a target naming another pull request, another
repository, or a different SHA, and there is no path that widens, refreshes, or
re-binds it.

`MergeTarget` is caller-supplied input. `operatorMergeAuthorizes` performs no
repository read, no GitHub API call, no adapter call, and no network access, so
**the binding guarantee is only ever as fresh and as authoritative as the target
handed to it.** C1 compares against a value; it does not observe a repository.

**Not proved, and not claimed.**

| Property | C1 |
| --- | --- |
| target SHA is authoritative | **not proved** — `MergeTarget.currentHeadSha` is an input; C1 cannot distinguish a live HEAD from a stale or invented one |
| target SHA is fresh | **not proved** — C1 cannot know whether the repository moved after the target was built |
| operator origin | **not proved** — the argument is untrusted data; a plain object literal written by any caller passes |
| human identity / authentication | **not proved** — `operatorId` is a readable string; C1 reads no credential and authenticates nothing |
| trusted minting, signature, possession | **not proved** — C1 has no issuing boundary and no secret material, so it cannot distinguish a minted record from an assembled one |
| a changed SHA means a new operator decision | **not proved** — see below |
| uniqueness / one-time consumption | **not proved** — C1 has no consumed-capability store |
| replay prevention | **not proved** — the identical record returns `true` on every call while the same target is supplied |

`singleUse: true` is a **structural intent marker**: it records that the shape is
that of a single-use capability. It is *not* enforced single consumption, and
this document does not claim the record is replay-proof or that it cannot be
reused. Likewise, a non-empty `operatorId` is descriptive data; it does not make
the record operator-originated, authenticated, or human-authorized.

On a changed SHA, C1 requires only a **newly matching candidate record**: if the
supplied target SHA changes, the previous candidate stops matching, and some
candidate whose `headSha` equals the newly supplied target SHA would be required.
This document does **not** claim that a new SHA requires a new operator decision.
C1 cannot tell whether such a candidate is a fresh human decision or the same
untrusted caller assembling another literal; the future trusted boundary must
establish that.

**A `true` result is therefore not sufficient proof that a merge may execute.**
It is a necessary binding check.

### What the future trusted Merge Broker must do

An explicitly reviewed later Cockpit layer, not implemented here, must:

1. authenticate the operator;
2. establish trusted capability minting and origin, so the record cannot have
   been assembled by a caller;
3. obtain the authoritative pull-request/repository HEAD immediately before the
   merge attempt;
4. require that exact HEAD to match the operator capability;
5. enforce single-use consumption atomically;
6. reject if HEAD changed;
7. perform or request the merge only after all gates still pass.

C1 performs **none** of those steps and claims none of them: no authentication,
no signatures, no token issuance, no secret material, no repository or live-HEAD
lookup, no replay or consumed-capability store, no operator session, and no
endpoint.

**No merge executor and no GitHub merge API call exists in this PR.**

None of this weakens the merge barrier above. `OperatorMergeAuthorization` is not
wired into `authorizeJobOperation`, and ordinary repair-job authority still
receives `OPERATOR_REQUIRED` with no permit for `merge`, regardless of what any
record of this shape says.

## Execution permits

An `ExecutionPermit` is the record of one authorization: exactly one job, exactly
one normalized operation, exactly one operand set, bound to the job's repository,
parent pull request, parent HEAD, and policy version at the moment of decision.

**A permit is not a bearer token.** `permitAuthorizes` re-derives the entire
decision from the trusted job and the untrusted request and then compares, so a
permit only ever authorizes what the evaluator would authorize at the moment of
use. The anti-forgery property follows, and is worth stating in the form it
actually holds:

> A forged permit that passes re-verification is a permit the evaluator would
> have issued anyway.

Forgery therefore buys nothing, and a permit widens no authority — it records
authority already derived from trusted configuration.

A permit is also **not a repository-safety finding**. That a ref operand — a
`repair.commit` or `repair.push` ref, or a `repair.change_request` `sourceRef` or
`targetRef` — passed C1's canonical syntax validation says nothing about the
effective ref-name referent it reaches in the repository the operation would
touch, about which ref a commit or push would actually advance, or about the
effective direction of a change request, so a permit must never be read as proof
that repository-level ref identity, the effective mutation target, or the
change-request direction is safe. The trusted execution boundary that acts on a
permit binds the effective identity, resolves it, and enforces it at the boundary
that actually consumes that identity — the mutation/receiving boundary for a
`repair.commit` or `repair.push`, and the change-request/provider creation boundary
for a `repair.change_request` — and fails closed; see *What canonical ref names do
and do not prove* above.

### Single use

Single use is stated structurally. `singleUse` is typed as the literal `true` and
`scope` as the literal `'exactly-one-execution'`, so neither can be widened by
assignment; the object is frozen; and there is no `expiresAt`, `ttl`, `uses`,
`remaining`, `renew`, `refresh`, or `reusable` field for a consumer to read as a
standing right. A test asserts the exact key set.

**C1 stores nothing and consumes nothing.** What C1 guarantees is that the
*identity* of a permit is a total function of the exact execution it authorizes,
so a consumer that records consumed `permitId`s can detect a replay rather than
being unable to distinguish one. `permitAuthorizes` reports whether a permit is
*valid*; it never reports whether it is *unused*, and it does not pretend to.

### Permit identity

`permitId` is derived deterministically — no clock, no randomness, no counter —
matching the purity of every other AgentBridge domain layer. It is **not a
nonce**: two authorizations of byte-identical executions produce the same id,
which is exactly the property that makes replay detectable.

Two legitimate executions of the same operation are distinguished by `requestId`,
which the caller mints per attempt and which participates in permit identity.
`requestId` confers no authority: an agent that mints a fresh one obtains exactly
the authority it already had, for one more execution of an operation the job
already authorizes.

The encoding is length-prefixed (`<len>:<part>`), so no operand value can inject
a delimiter and make one execution's id collide with another's. Identity covers
the policy version, job, repository, parent pull request, parent HEAD, request
id, operation, and every operand the operation defines.

A permit carries **only** the operands its operation defines; every other operand
is `null`. A `source.read` request that also names the protected parent ref
produces a permit whose `ref` is `null`, so an unused operand cannot ride along
into execution.

## Authorized file scope

`repository.write` is not modeled at all, so there is no permission that means
"edit the entire repository". A future edit authorization is evaluated against
the **actual requested path**.

`authorizedPaths` is a list of exact repository-relative paths — not a prefix,
glob, or directory. Directory authority would require normalisation and
containment guarantees this pure model cannot prove, and a `src/a` versus
`src/ab` prefix boundary is a classic escape. An empty list is legitimate: it
describes a verification-only job.

`readRepositoryRelativePath` rejects, without exception: non-strings, empty
strings, values over 1 024 characters, any `.` or `..` segment, a leading `/`,
an empty segment, a trailing `/`, a leading `~`, `\` anywhere, `:` anywhere,
control characters including NUL, a `.git` segment at any depth in any ASCII
case, and any segment with a leading space or a trailing space or dot. Both the
configured paths and the requested path go through the same reader, and the same
reader is applied all-or-nothing to job configuration: one bad path invalidates
the whole scope rather than leaving a job that looks configured but is not the
one an operator wrote.

### What path containment does and does not prove

Stated precisely, because overclaiming here would be worse than not checking:

**Proved.** The value is a string matching a conservative repository-relative
shape, and it is exactly equal to a path an operator configured. No traversal,
absolute path, drive-absolute path, alternate data stream, NUL truncation, or
`.git` access can be expressed at all.

**Not proved, and not claimed.** That two equal strings name the same file. A
pure model cannot know about case-insensitive or case-preserving filesystems,
Unicode normalisation applied by the filesystem, symbolic links, hard links, bind
mounts, or junctions. **A future execution layer must re-verify containment
against the real filesystem it is about to touch.** This reader narrows the
input; it does not sandbox it.

No normalisation of any kind is performed. `SRC/A.TS` is not `src/a.ts` here, and
whether it is on disk is the executor's problem to solve with the filesystem, not
this layer's to guess.

## Command authority

C1 never authorizes a shell command string. It authorizes a **class** — `test`,
`lint`, `typecheck`, `build`, `audit` — and a later execution layer resolves a
class to a concrete command through repository policy. There is no field on this
boundary that can carry a command line, argument vector, environment, or shell,
and a request naming `npm test`, `test; rm -rf /`, `sh`, or `powershell` is
refused as an unauthorized class.

The five classes mirror the verification actions PR 002 already classifies
read-only. C1 does not import that taxonomy — a class here is an authorization
label, not an action kind — but the vocabularies are kept aligned so the two
layers cannot disagree about what verification means.

Authorization requires two independent conditions: the class must be one C1
models at all, *and* the job must have been configured to permit it. An
unmodeled class in job configuration invalidates the job rather than being
quietly accepted.

**No command execution, shell parsing, subprocess spawning, PowerShell, Bash, or
process transport exists in this PR.**

## Protected parent and stacked validation quarantine

The mandatory AgentBridge pattern is preserved:

    finding
    -> verify against CURRENT HEAD
    -> bounded repair specification
    -> isolated repair branch and worktree
    -> repair agent
    -> stacked validation PR targeting the protected parent feature PR
    -> independent review
    -> CI / typecheck / lint / build / tests
    -> policy and evidence gate
    -> ready for an operator
    -> operator decision

C1 implements none of that workflow. It encodes only the minimal authority
invariants that stop a later layer from bypassing the quarantine by accident:

- The protected parent ref is never a write target of any operation, under any
  *spelling*: refs are canonical everywhere, so a caller cannot present a textual
  alias of the parent as a different branch. Repository-dependent aliasing — a
  canonical repair ref that is symbolic to the parent, a worktree `HEAD` or push
  destination whose effective target is the parent, a change-request source or
  target whose effective direction is reversed, or an effective ref that changes
  after a pre-check — is not visible to a pure string boundary, and is the later
  trusted execution boundary's to bind, resolve, or reject before it acts on any
  authority a permit records.
- Filesystem-shaped operations are bound to the repair worktree, so an edit
  cannot land in the parent's checkout.
- The stacked change request must run from the repair branch to the protected
  parent ref, in that direction. A change request *from* the parent is refused,
  and one targeting an integration branch directly is refused.
- A repair agent cannot become its own sole validator: the job is invalid if
  `independentValidatorId` equals `repairAgentId`, and
  `satisfiesIndependentValidator` consults **only** `validatorId` against the
  trusted configuration. A claimed role, a claimed provider, and a
  privileged-sounding label satisfy nothing.

## Hostile runtime

All runtime input crossing this boundary is treated as hostile, following the
patterns PR 004, PR 005, and PR 006 established:

- **Captured intrinsics.** `Object.freeze`, `Object.defineProperty`,
  `Object.hasOwn`, `Array.isArray`, `Number.isInteger`, `String`,
  `String.prototype.trim`, `String.prototype.charCodeAt`, and `Reflect.apply`
  are captured at module load, before any untrusted access is possible. String
  methods are captured unbound and invoked through `Reflect.apply`, so neither a
  poisoned prototype method nor a poisoned `Function.prototype.call` is on the
  path.
- **Own-property reads.** Every untrusted property is read own-only. An
  inherited value, including one planted on `Object.prototype` through a
  `__proto__` payload, is treated as absent.
- **Guarded reads.** Every read is wrapped, because a getter or Proxy trap may
  throw. `Array.isArray` itself is guarded, because it throws on a revoked
  Proxy.
- **Trusted snapshots, read exactly once.** Both arguments are read into frozen
  snapshots before any decision is made, and everything downstream reads only
  the snapshot. A getter that returns a different value on each access cannot
  validate one operand and have another reach the decision or the permit. Tests
  pin this for the path, the ref, and the authorized-path list.
- **No validation TOCTOU.** The single `readRepairJobAuthorization` pass is both
  the validator and the snapshot builder, so `findInvalidRepairJobFields` and
  the evaluator cannot drift apart — there is no second implementation to
  diverge.
- **Bounds before iteration.** 256-character identifiers, 1 024-character paths,
  512 authorized paths, 64 path segments, 16 command classes. A hostile
  `length` — including a Proxy reporting `Number.MAX_SAFE_INTEGER` — is refused
  rather than iterated.
- **Identifiers reject, never truncate.** A truncated identifier is worse than
  no identifier: git resolves commit prefixes, so a cut SHA can falsely match a
  real object and a cut branch name can name a different ref. **C1 truncates
  nothing at all, because C1 has no prose field.** An oversized list is likewise
  rejected, not shortened.
- **Refs are narrowed, never repaired.** A non-canonical branch ref is refused,
  not rewritten into the canonical spelling. Repairing a spelling would be
  choosing an authority target on the caller's behalf, which is exactly the
  decision the boundary exists to refuse. The reader is a pure function of a
  primitive string captured by a single own-property read, so it introduces no
  second observation of untrusted state and no validation TOCTOU.
- **List entries are own elements.** Every entry of an authorization list is
  read as an **own** indexed property, so only an element the supplied object
  reports as its own can become an authorized path or command class. For any
  array whose own-property introspection is truthful — every ordinary array,
  however its prototype chain is arranged — that is exactly the elements the job
  configuration supplied: an index with no own element is a sparse hole, and a
  hole rejects the whole list rather than collapsing, shortening, or taking a
  default, so an inherited numeric property planted on a custom array prototype
  or on `Array.prototype` is refused however well-formed its value looks.
  Provenance decides, not shape. A hole is not authorization, and prototype
  state is not authorization.

  The guarantee stops where the runtime's own-property report does, and the
  boundary is documented rather than papered over. A Proxy *defines* the
  observable result of `Object.hasOwn` and of the subsequent read, so one whose
  `getOwnPropertyDescriptor` trap claims a hole is own while the read forwards
  through the target's prototype will pass an inherited value through. The
  reader performs one own check and one guarded read and re-validates nothing
  afterwards, but those are two observations rather than one atomic one, and a
  Proxy may answer them inconsistently. C1 establishes provenance no further
  than the supplied object's own report, and claims no more. This widens no
  authority: a caller able to supply such a Proxy can supply the same value as a
  dense own element instead, which is configuration, not an attack.
- **Array building avoids the prototype.** Appends define an own indexed
  property rather than using `push` or indexed assignment, so an inherited index
  setter is not on the path.
- **Fail closed without throwing.** Every entry point is total. A non-object, a
  revoked Proxy, a record of throwing getters, and a payload of wrong types all
  yield a refusal, never an exception.
- **Prose and metadata create no authority.** Not because they are ignored, but
  because there is no field to put them in.

Existing hardened readers were **not** refactored to share helpers with C1. The
boundary independence recorded in PR 006 is intentional and takes precedence over
deduplication. C1's four modules do share readers with each other, because they
are one boundary rather than four.

One cross-boundary convention is pinned by test rather than by import:
`JOB_BOUNDS.MAX_IDENTIFIER_LENGTH` equals `INVOCATION_BOUNDS.MAX_IDENTIFIER_LENGTH`,
because a `jobId` may be correlated with an `invocationId`, and two ids sharing a
256-character prefix must never be able to collapse into one.

## Determinism

Given identical arguments, authorization produces byte-equivalent output: no
clock, no randomness, no filesystem, no network, no environment, no mutable
global state, no identifier generation. `permitId` derives from the exact
execution, so no hashing dependency is required. Invalid-field names preserve
declaration order, and nothing is sorted, grouped, or deduplicated. Decisions,
permits, operand records, and all lists are frozen, so an authorization cannot be
rebound to another job, operand, or commit after the fact.

## What C1 deliberately does not contain

No Autoflow workflow or state implementation. No `READY_FOR_MERGE`
implementation. No Claude, Codex, or CodeRabbit adapter. No process transport,
`child_process`, filesystem I/O, git execution, worktree creation, commit, push,
GitHub API, pull-request creation, reviewer triggering, or network access. No
merge executor and no auto-merge. No SQLite, Evidence Store persistence, REST
API, HTTP server, dashboard, or frontend. No polling, queues, async
orchestration, retry loops, timers, or schedulers. No executor of any kind: C1
models and evaluates authorization and nothing else.

This is one layer of a boundary that does not exist yet, established before the
capability it bounds.

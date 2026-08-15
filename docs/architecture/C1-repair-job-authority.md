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
| `protectedParentRef` | the parent integration ref, which no operation may write |
| `parentHeadSha` | the exact commit the job is bound to |
| `findingSource` | where the finding came from; a provider-neutral label, inert |
| `findingId` | the finding being repaired |
| `findingHeadSha` | the commit the finding was verified against |
| `repairBranch` | the isolated repair branch |
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

- `repairBranch !== protectedParentRef`. A job whose repair branch *is* the
  protected parent is not a quarantined repair; it is a direct write to
  protected history wearing a repair job's name.
- `independentValidatorId !== repairAgentId`. A repair agent that is its own
  validator defeats the quarantine the whole pipeline exists to enforce.

One relationship is enforced at authorization time, because it is about
freshness rather than shape: `findingHeadSha` must equal `parentHeadSha`, or
every operation is denied `FINDING_SHA_STALE`. A repair derived from a finding
about some other commit is a repair of something that may no longer be there.
PR 004 remains the owner of `CURRENT` versus `STALE` for evidence; this is the
narrower structural check that the job's own two SHAs agree, which C1 can decide
without importing that kernel or producing a second answer to PR 004's question.

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
`WORKTREE_NOT_AUTHORIZED`, `COMMAND_CLASS_NOT_AUTHORIZED`,
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
target repository, target pull request, and the repository's *current* HEAD. Every
comparison is exact string equality, so the record is invalid the moment HEAD
changes and can never cover another pull request, another repository, or a future
SHA. There is no path that widens, refreshes, or re-binds it.

**Not proved, and not claimed.**

| Property | C1 |
| --- | --- |
| operator origin | **not proved** — the argument is untrusted data; a plain object literal written by any caller passes |
| human identity / authentication | **not proved** — `operatorId` is a readable string; C1 reads no credential and authenticates nothing |
| trusted minting, signature, possession | **not proved** — C1 has no issuing boundary and no secret material, so it cannot distinguish a minted record from an assembled one |
| uniqueness / one-time consumption | **not proved** — C1 has no consumed-capability store |
| replay prevention | **not proved** — the identical record returns `true` on every call while HEAD is unchanged |

`singleUse: true` is a **structural intent marker**: it records that the shape is
that of a single-use capability. It is *not* enforced single consumption, and
this document does not claim the record is replay-proof or that it cannot be
reused. Likewise, a non-empty `operatorId` is descriptive data; it does not make
the record operator-originated, authenticated, or human-authorized.

**A `true` result is therefore not sufficient proof that a merge is
operator-authorized.** It is a necessary binding check. A future trusted operator
boundary — the merge broker, an explicitly reviewed later Cockpit layer — is
responsible for authenticating the operator, establishing that the record was
minted by that boundary rather than supplied by a caller, and consuming the
record so it cannot authorize a second merge. C1 deliberately implements none of
that: no authentication, no signatures, no token issuance, no secret material, no
replay or consumed-capability store, no operator session, and no endpoint.

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

- The protected parent ref is never a write target of any operation.
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
- **Sparse arrays reject.** A hole reads as `undefined`, which no reader accepts,
  so sparseness rejects rather than collapsing.
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

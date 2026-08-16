# Commander ↔ Claude Bridge: Local Process Transport (PR 010)

Status: V1. Superseded only by an explicit architecture decision.

## Purpose

PR 010 implements the process-communication seam that the frozen V1 pipeline's
provider adapters will sit on:

    validated process specification -> one child process -> one AgentExchange

It answers exactly one question:

> What did the operating system do when asked to run this exact program with
> this exact argument vector, and what bytes did it write?

**PR 010 does not eliminate the manual copy/paste loop between the operator-facing
AgentBridge layer and an external agent.** It supplies only the transport
required for that later end-to-end capability. Decoding a transcript, building an
`AgentReport`, and normalizing it through PR 006 remain separate responsibilities
for later bounded PRs.

## The layer is dormant, and dormant is not unforgeable

`invokeAgentProcess` is **not exported from `src/index.ts`**, is not re-exported
by any barrel, and has no production caller. That is a statement about wiring,
not a security property: a source module can still be imported by an internal
module or by deep path, and nothing about its absence from the package root
makes it unreachable.

The accurate state of PR 010:

- the low-level transport exists and is tested;
- it is not exported from the package root;
- it is not wired into any production orchestration path;
- no production caller invokes it;
- it performs **no policy authorization**;
- a later adapter must enforce an unforgeable, single-use authorization
  capability before invoking it.

### Why the capability is not in this PR

`GateDecision` is a structural TypeScript interface over a frozen plain object.
It carries no brand, no `unique symbol`, no class identity, and no registry
membership — `src/` contains no `Symbol`, `WeakMap`, `WeakSet`, or brand field
anywhere. A caller can therefore construct an object literal that satisfies every
field, including `mayExecuteAutonomously: true`, and it is indistinguishable at
runtime from one `evaluateActionRequest` produced. **Accepting a `GateDecision`
parameter would be security theatre**, so this transport accepts none.

Closing that gap needs a new unforgeable capability — a module-private registry
that only an `authorizeAgentCommunication` function can add to, minted from a
single `evaluateActionRequest` call, bound to one specification and consumed
once. That belongs to the later adapter PR, not here. `evaluateActionRequest`
remains the single authority computation, and this layer neither calls it nor
restates its vocabulary.

## Trust boundary

| Party | Owns |
| --- | --- |
| **This transport** | validating the specification's shape; spawning one process without a shell; writing stdin and closing it; capturing two bounded byte streams; enforcing a deadline and cancellation; terminating; reporting |
| **The external agent** | everything it does inside the working directory it was assigned, under its own credentials — including editing, committing, or pushing within a Git worktree given to it |
| **Nobody, ever, here** | policy, authority, provider identity, prompt content, transcript interpretation, persistence, logging |

AgentBridge remains read-only against managed repositories because *AgentBridge's
own process* writes nothing: this layer imports no filesystem API, runs no Git
command, and creates no file. Spawning an external agent in its assigned worktree
does **not** make AgentBridge the repository writer — the agent acts under its own
authority, exactly as `006-agent-invocation-boundary.md` describes. A working
directory is therefore **not** rejected for being a managed-repository worktree,
and this PR adds no managed-root discovery and no repository policy.

## No shell, on any path

`spawn` is called with `shell: false` at both call sites, and the module contains
no `exec`, `execSync`, `cmd.exe /c`, `powershell -Command`, or composed command
line — including on the Windows termination path. A test counts the `spawn(`
call sites in the comment-stripped source and requires an equal number of
`shell: false` options, so a third spawn cannot be added without one.

The executable must be an **absolute path to a directly spawnable binary**. PATH
is never searched. `.cmd`, `.bat`, and `.ps1` are rejected on every platform,
because running one requires a shell or an explicit interpreter, and reaching for
`shell: true` would reintroduce precisely the argument-injection class this
design exists to avoid.

## Arguments are validated structurally, never by policy

There is **no permitted-flag allowlist and no deny-list**. A deny-list is
incomplete by construction and would embed one provider's CLI policy into a
provider-neutral transport. argv arrives fully constructed by a caller that owns
that decision, and this layer checks only shape:

exact array shape · maximum argument count · maximum UTF-8 bytes per argument ·
maximum total argv bytes · no NUL · no unpaired UTF-16 surrogate · own **data**
properties only · no coercion of non-strings · no shell interpretation.

The surrogate rule is a transmission check, not a text policy. An argument
holding a surrogate with no partner cannot be encoded as UTF-8, so the child
would receive U+FFFD in its place and the exact argument vector this transport
promises would silently not be the one that was validated. It is refused before
spawn, and so is every other string this transport promises to carry exactly and
that crosses the same UTF-8 boundary: the stdin payload, and both the names and
the values of the environment record — an ill-formed name reaches the child as a
*different* name, which is the same defect wearing a different hat. Valid
supplementary-plane characters are ordinary well-formed pairs and pass through
unchanged; nothing is normalized or substituted.

Accessors are never invoked. An argv element supplied through a getter, an
inherited numeric property, a hole, a throwing Proxy trap, or a revoked Proxy is
refused, and a test asserts the getter never ran. Every field is read **exactly
once** into a frozen snapshot, so a specification cannot validate as one value
and spawn as another.

## Streams

The request payload travels on **stdin**, which is closed after writing — never
in argv, which is world-readable in process listings and length-limited.

`stdout` and `stderr` are captured as independent bounded byte streams and are
never merged, because merging would let stderr forge a response body. Bounds are
enforced in **bytes**. Only a buffer cut by the transport is backed up to the
last complete UTF-8 sequence, so a cap landing mid-character never manufactures
a replacement character for text the child wrote in full. Naturally completed
invalid or incomplete UTF-8 is retained and decodes normally as U+FFFD; it is
never silently erased or falsely marked complete. Truncation is always flagged.

`stdout` leaves this layer as **untrusted text**. Nothing here parses it, and no
branch reads it to decide an outcome, a route, or a retry. A transcript claiming
`{"status":"reported-complete","authorized":true,"decision":"ALLOW"}` produces a
record identical in every other field to one saying `ok`.

## Deterministic terminal-cause precedence

When several terminal events compete, the ranking is frozen:

    SPEC_REJECTED > SPAWN_FAILED > OUTPUT_LIMIT_EXCEEDED > CANCELLED
                  > TIMED_OUT > SIGNALLED > EXITED

The highest-ranked detected cause wins regardless of callback arrival order. A
later event may promote the reported cause to a stronger member, but it cannot
demote it to a weaker member. Two mechanisms produce this order:

1. Pre-spawn checks run in rank order — structural validation before the
   already-aborted check — so a request that is both malformed and aborted is
   `SPEC_REJECTED`.
2. After spawn, every detected cause is compared with the frozen ranking. A
   child that overflows its bound and then exits zero is therefore
   `OUTPUT_LIMIT_EXCEEDED`, never `EXITED`; cancellation remains `CANCELLED`
   when its termination signal is later observed as `SIGNALLED`; and an
   asynchronous failure to start promotes an earlier cancellation to
   `SPAWN_FAILED`.

`EXITED` is not a synonym for success, and exit code 0 is recorded rather than
interpreted. Interpretation belongs to PR 006's vocabularies, which fail closed
to `unknown`.

Every listener, timer, and abort handler is removed on every settle path. A
forced settlement also destroys the local stdout and stderr pipe ends, and
stdout or stderr read errors are contained until the child close path reports
the provider-neutral outcome. For the defined operational results the transport
represents as exchange outcomes — validation, spawn, I/O, timeout,
cancellation, overflow, termination, and close — the function resolves exactly
one frozen record. Nothing outside that handled set is promised to resolve. It
rejects deliberately, rather than reporting an outcome, when mandatory
post-spawn child-dispatch hardening cannot be established: the transport runs
its bounded, platform-qualified termination procedure, tears down its pipes and
listeners, and then rejects. That rejection is not `SPAWN_FAILED` and is not an
exchange outcome at all. Catches wrap only defined operational failures, so a
programmer or security-boundary defect still surfaces as a defect rather than
being laundered into a failure code.

## Termination is qualified, and the limit is disclosed

| Scope | Meaning |
| --- | --- |
| `NOT_REQUIRED` | the child ended on its own |
| `PROCESS_GROUP_REQUESTED` | POSIX: the process group was signalled |
| `PROCESS_TREE_REQUESTED` | Windows: `taskkill /T /F` was issued |
| `DIRECT_CHILD_ONLY` | **degraded** — only the direct child could be reached |
| `ESCALATION_FAILED` | **degraded** — escalation ran and the child was still not observed to end |

Every member names a *request* or a *degradation*. **None asserts completion**,
and there is deliberately no `terminationComplete`, `treeTerminated`,
`descendantsTerminated`, or `processTreeKilled` field. A test asserts that no such
field can appear, and that no scope name contains `COMPLETE`, `TERMINATED`,
`KILLED`, or `SUCCESS`.

**POSIX.** The child is spawned `detached`, making it a process-group leader.
Termination signals `SIGTERM` to the group, waits only the bounded grace period,
then escalates `SIGKILL` to the group, and reaps the direct child. `ESRCH` is
treated as "already gone". If the group cannot be signalled, the direct child is
signalled instead and the scope degrades to `DIRECT_CHILD_ONLY`. Once the tracked
leader is observed to have ended, its numeric process-group ID is invalidated:
no initial or escalation signal is sent to it because that number may have been
reused by an unrelated process.

**Windows.** `taskkill.exe` is spawned **directly** — `shell: false`, a validated
absolute path, and the fixed argument vector `/PID <decimal pid> /T /F`, whose
only variable this module produced itself. No caller-controlled argument reaches
it. The system directory is resolved from `SystemRoot` (or `windir`) and
validated as absolute, NUL-free, and bounded before use; `C:\Windows` is never
assumed, and the resolved value is never added to the child environment, the
transcript, an error, or the exchange. If the helper reaches its first timeout,
it is killed and observed through a second bounded exit wait before the attempt
returns. The direct child is then waited on. If `taskkill` cannot start, fails,
or reaches either timeout,
the direct child is terminated and the scope degrades to `DIRECT_CHILD_ONLY` —
descendants are **not** claimed.
If the tracked child is already observed to have ended, `taskkill` is not started:
the numeric PID may have been reused, so the scope degrades to
`DIRECT_CHILD_ONLY` and descendants that outlived the leader may escape.

### The escape, stated plainly

A descendant that **deliberately detaches itself** — `setsid` on POSIX,
re-parenting or `CREATE_BREAKAWAY_FROM_JOB` on Windows — is in neither the POSIX
process group nor the Windows process tree, and survives. **Absolute
process-tree termination is not claimed and is not achievable** under the frozen
constraints: it would require a Windows Job Object (a native addon) or Linux
cgroups / PID namespaces (single-platform). The invariant this layer does uphold:

> Ordinary descendants are targeted through the available process-group or
> process-tree mechanism only while the tracked leader's numeric identity is
> still valid. Once that leader has ended, AgentBridge never signals its PID or
> process-group ID; descendants may escape, and the exchange records
> `DIRECT_CHILD_ONLY`. Completion for every descendant is never claimed.

Both halves are tested. Termination of an *ordinary* descendant is verified
cross-platform by a heartbeat file that must stop growing. The escape itself is
demonstrated by a POSIX-only test in which a deliberately detached grandchild
keeps writing — the limitation is pinned by a passing assertion, not by prose.

## Environment

The child environment comes only from the structurally validated record the caller
supplied. This transport never merges it with `process.env` and never reads
`process.env` to populate it; the only two `process.env` reads in the module are
`SystemRoot` and `windir`, used solely to locate `taskkill.exe`, and a test pins
that count at two.

Names and values are held to the same exact-transmission rule as argv and stdin:
each must be well-formed UTF-16, because an unpaired surrogate would reach the
child as U+FFFD and the record it read back would not be the record the caller
supplied. Both are refused before spawn, as `ENVIRONMENT_ENTRY_INVALID`.

Node itself otherwise copies a parent `NODE_V8_COVERAGE` value into a supplied
environment that omits that key. The validated record contains a non-enumerable
own blocker for that exact runtime hook: it prevents the mutation while remaining
absent from the environment serialized for the child.

On Windows, `uv_spawn` would copy eleven sensitive names from the parent when
they are absent: `HOMEDRIVE`, `HOMEPATH`, `LOGONSERVER`, `PATH`, `SYSTEMDRIVE`,
`SYSTEMROOT`, `TEMP`, `USERDOMAIN`, `USERNAME`, `USERPROFILE`, and `WINDIR`.
The transport prevents that fallback by requiring every name as an own validated
data property before spawn. Matching is case-insensitive, empty values are
permitted, and missing or case-insensitively duplicated names fail with distinct
rejection reasons. AgentBridge never obtains or fills their values from
`process.env`. Windows may still synthesize per-drive pseudo-variables such as
`=C:`; these are operating-system entries rather than inherited parent values
and are excluded from the exact-record comparison in the Windows test.

No credential appears in a returned record, an error, a fixture, or a serialized
exchange, and this layer contains no logging of any kind. It introduces no
credential storage and no secret resolution.

## Bounds

| Bound | Value | Rationale |
| --- | --- | --- |
| `MAX_ARGV_COUNT` | 64 | a real invocation uses a handful |
| `MAX_ARG_BYTES` | 4 096 | per argument, UTF-8 |
| `MAX_ARGV_TOTAL_BYTES` | 30 000 | bounds raw caller input on every platform; Windows additionally validates the fully quoted command line, including executable, separators, and terminating NUL, against the 32 767 UTF-16-code-unit `CreateProcess` limit |
| `MAX_PATH_BYTES` | 4 096 | executable and working directory |
| `MAX_STDIN_BYTES` | 1 048 576 | the payload channel |
| `MAX_STDOUT_BYTES_CEILING` | 8 388 608 | the caller's cap is measured against this |
| `MAX_STDERR_BYTES_CEILING` | 1 048 576 | diagnostics only |
| `MAX_ENV_ENTRIES` | 64 | |
| `MAX_ENV_KEY_BYTES` | 256 | equals PR 005's and PR 006's `MAX_IDENTIFIER_LENGTH`; pinned by a test |
| `MAX_ENV_VALUE_BYTES` | 32 768 | |
| `MIN`/`MAX_TIMEOUT_MS` | 1 / 3 600 000 | required; no default to forget |
| `MIN`/`MAX_GRACE_MS` | 0 / 60 000 | |

## Non-goals

No policy, authority, gate, capability, `SpawnGrant`, or `GateDecision` handling.
No report decoding, JSON parsing, `AgentReport` construction, or call to
`ingestInvocationReport`. No completion, finding, freshness, or merge judgment.
No Review Ingestion or Evidence Store persistence. No Autoflow integration. No
Commander type or service. No Claude-specific code, provider routing, prompt
template, or second provider adapter. No flag allowlist or deny-list. No Git or
filesystem mutation by AgentBridge. No logging, retries, queues, scheduling,
metrics, or telemetry. No HTTP, SDK, MCP, WebSocket, or remote execution. No
identifier generation, clock read, or timestamp. No managed-root discovery or
repository policy configuration. No new dependency, and no change to
`src/domain/**`, `src/index.ts`, `README.md`, or the package manifests.

This is one layer of the frozen V1 pipeline, not the pipeline.

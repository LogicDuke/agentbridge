/**
 * The one place in AgentBridge that starts an operating-system process.
 *
 *     validated specification -> one child process -> one frozen AgentExchange
 *
 * This module is **dormant in PR 010**. It is not exported from `src/index.ts`,
 * it is not re-exported by any barrel, and no production code invokes it. That
 * is a statement about wiring, not about safety: a source module can still be
 * imported by an internal module or by deep path, so nothing here should be read
 * as "unreachable by construction". Before any production caller invokes it, a
 * later adapter must enforce an unforgeable, single-use authorization capability
 * derived from PR 003's `evaluateActionRequest`. **This module performs no
 * policy authorization of its own and must never gain any.**
 *
 * Scope: process communication only. Nothing here parses stdout, builds an
 * `AgentReport`, calls `ingestInvocationReport`, judges completion, evaluates
 * freshness, computes policy, persists, logs, retries, queues, or generates an
 * identifier. `stdout` and `stderr` leave as untrusted text.
 *
 * What the *child* does inside its assigned working directory — including
 * editing, committing, or pushing within a Git worktree it was given — is that
 * agent's own authority under its own credentials, exactly as
 * `docs/architecture/006-agent-invocation-boundary.md` describes. AgentBridge
 * itself writes no file and runs no Git command: this module imports no
 * filesystem API at all.
 *
 * ## No shell, on any path
 *
 * `spawn` is always called with `shell: false`. There is no `exec`, no
 * `execSync`, no `cmd.exe /c`, no `powershell -Command`, and no composed command
 * line anywhere in this file — including the Windows termination path, where
 * `taskkill.exe` is spawned directly from a validated absolute path with a fixed
 * argument vector whose only variable is a decimal PID this module produced
 * itself.
 *
 * ## Termination is qualified, and says so
 *
 * Descendant termination is attempted through a POSIX process group or through
 * `taskkill /T /F`, and the resulting {@link TerminationScope} records what was
 * *requested*, never that it completed. A descendant that deliberately detaches
 * itself — `setsid` on POSIX, re-parenting on Windows — is outside the guarantee
 * this transport can offer. Absolute process-tree termination is **not claimed**
 * and would require a Windows Job Object or Linux cgroups, both of which need
 * either a native addon or a single-platform mechanism.
 */

import { ChildProcess, spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { Readable, Writable } from 'node:stream';

import {
  type AgentExchange,
  type AgentProcessSpec,
  containsNul,
  isAbsolutePath,
  readInvocation,
  TERMINAL_CAUSE_PRECEDENCE,
  TERMINATION_SCOPE,
  type TerminationScope,
  TRANSPORT_BOUNDS,
  TRANSPORT_OUTCOME,
  type TransportLimits,
  type TransportOutcome,
  type TransportPlatform,
  type TransportRejection,
  trimPartialUtf8,
  utf8ByteLength,
} from './agent-transport.js';

/**
 * Intrinsics captured at module load, before any child output can be observed.
 * Same pattern as the domain boundaries.
 */
const objectFreeze = Object.freeze;
const objectDefineProperty = Object.defineProperty;
const reflectApply = Reflect.apply;
const NativePromise = Promise;
const scheduleTimeout = setTimeout;
const cancelTimeout = clearTimeout;
const runtimeProcess = process;
// `Buffer.isBuffer` and `Buffer.concat` are statics that ignore `this`, captured
// so a later reassignment of the global cannot change how child output is read.
/* eslint-disable @typescript-eslint/unbound-method */
const bufferIsBuffer = Buffer.isBuffer;
const bufferConcat = Buffer.concat;
// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
const bufferSubarray: (this: Buffer, start: number, end?: number) => Buffer =
  // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
  Buffer.prototype.subarray;
// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
const bufferToString: (this: Buffer, encoding: BufferEncoding) => string =
  // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
  Buffer.prototype.toString;
const stringCharCodeAt = String.prototype.charCodeAt;
const numberToString = Number.prototype.toString;
const eventTargetAddEventListener = EventTarget.prototype.addEventListener;
const eventTargetRemoveEventListener = EventTarget.prototype.removeEventListener;
const eventEmitterEmit = EventEmitter.prototype.emit;
const eventEmitterOn = EventEmitter.prototype.on;
const eventEmitterRemoveListener = EventEmitter.prototype.removeListener;
const eventEmitterRemoveAllListeners = EventEmitter.prototype.removeAllListeners;
const readableOn = Readable.prototype.on;
const readableDestroy = Readable.prototype.destroy;
const writableEnd = Writable.prototype.end;
const childProcessKill = ChildProcess.prototype.kill;
const processKill = process.kill;
const abortSignalAborted: ((this: AbortSignal) => boolean) | undefined =
  Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')?.get;
/* eslint-enable @typescript-eslint/unbound-method */

/**
 * Bound on how long the Windows tree-kill helper may run before it is itself
 * abandoned and the direct-child fallback is used. Independent of the caller's
 * grace period, so a caller cannot make termination unbounded by supplying a
 * large one, and cannot make it unreliable by supplying zero.
 */
const TASKKILL_TIMEOUT_MS = 5_000;

/**
 * Keep Node's own lifecycle dispatch on the intrinsic captured at module load.
 *
 * ChildProcess and its stdio streams inherit EventEmitter.prototype.emit; Node
 * does not provide a more-specific override for any of them. Giving each
 * transport-owned object an immutable own data property therefore preserves
 * Node's normal dispatch while preventing a later prototype replacement from
 * fabricating, suppressing, or reordering its lifecycle events.
 */
function protectEventDispatch(emitter: EventEmitter | null): void {
  if (emitter === null) {
    return;
  }
  objectDefineProperty(emitter, 'emit', {
    configurable: false,
    enumerable: false,
    value: eventEmitterEmit,
    writable: false,
  });
}

/** Protect a spawned process and every transport-owned pipe it exposes. */
function protectChildDispatch(child: ChildProcess): void {
  protectEventDispatch(child);
  protectEventDispatch(child.stdin);
  protectEventDispatch(child.stdout);
  protectEventDispatch(child.stderr);
}

function resolved<T>(value: T): Promise<T> {
  return new NativePromise<T>((resolve) => {
    resolve(value);
  });
}

function onEvent(
  emitter: EventEmitter,
  event: string,
  listener: (...args: never[]) => void,
): void {
  reflectApply(eventEmitterOn, emitter, [event, listener]);
}

function removeEventListener(
  emitter: EventEmitter,
  event: string,
  listener: (...args: never[]) => void,
): void {
  reflectApply(eventEmitterRemoveListener, emitter, [event, listener]);
}

function removeAllEvents(emitter: EventEmitter): void {
  reflectApply(eventEmitterRemoveAllListeners, emitter, []);
}

function onReadableData(readable: Readable, listener: (chunk: unknown) => void): void {
  // Readable overrides EventEmitter.on to enter flowing mode for `data`.
  reflectApply(readableOn, readable, ['data', listener]);
}

/**
 * Absorb an asynchronous spawn failure so it can never go unhandled.
 *
 * `spawn` can return a ChildProcess whose failure is reported later through an
 * `error` event — ENOENT is the common case — and an `error` with no listener
 * makes EventEmitter rethrow, which terminates the host process rather than
 * this exchange. From the moment `spawn` returns there must therefore always be
 * at least one `error` listener, including while dispatch hardening runs and on
 * every path that fails it. Presence is the whole guarantee: the outcome is
 * still decided by the transport's own handlers, so this one does nothing.
 */
function absorbSpawnFailure(): void {
  // Intentionally empty; see the doc comment.
}

/** Keep a spawned process covered after its listeners have been cleared. */
function rearmSpawnFailureAbsorber(child: ChildProcess): void {
  onEvent(child, 'error', absorbSpawnFailure);
}

/** Release a child output pipe through the intrinsic captured at module load. */
function destroyReadable(readable: Readable | null): void {
  if (readable !== null) {
    reflectApply(readableDestroy, readable, []);
  }
}

/** Position in the declared precedence; lower indices bind more strongly. */
function precedenceRank(outcome: TransportOutcome): number {
  for (let index = 0; index < TERMINAL_CAUSE_PRECEDENCE.length; index += 1) {
    if (TERMINAL_CAUSE_PRECEDENCE[index] === outcome) {
      return index;
    }
  }
  return TERMINAL_CAUSE_PRECEDENCE.length;
}

/** Append by defining an own element, bypassing inherited index setters. */
function append<T>(list: T[], value: T): void {
  objectDefineProperty(list, list.length, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

/** A bounded byte accumulator for one stream. */
interface Sink {
  readonly chunks: Buffer[];
  readonly limit: number;
  bytes: number;
  truncated: boolean;
}

function createSink(limit: number): Sink {
  return { chunks: [], limit, bytes: 0, truncated: false };
}

/**
 * Add a chunk, keeping at most `limit` bytes.
 *
 * Returns true once the bound has been reached, which is what promotes the
 * exchange to `OUTPUT_LIMIT_EXCEEDED`. A stream that lands exactly on the bound
 * is **not** truncated; the next byte is what makes it so.
 */
function pushChunk(sink: Sink, chunk: Buffer): boolean {
  if (sink.bytes >= sink.limit) {
    sink.truncated = true;
    return true;
  }
  const room = sink.limit - sink.bytes;
  if (chunk.length > room) {
    append(sink.chunks, reflectApply(bufferSubarray, chunk, [0, room]));
    sink.bytes = sink.limit;
    sink.truncated = true;
    return true;
  }
  append(sink.chunks, chunk);
  sink.bytes += chunk.length;
  return false;
}

/** Join, trim only transport-cut UTF-8, and decode natural invalid bytes. */
function decodeSink(sink: Sink): { readonly text: string; readonly bytes: number } {
  const joined = bufferConcat(sink.chunks);
  const retained = sink.truncated ? trimPartialUtf8(joined) : joined;
  return {
    text: reflectApply(bufferToString, retained, ['utf8']),
    bytes: retained.length,
  };
}

/** Read a validated signal through the captured platform brand-checking getter. */
function readAbortState(signal: AbortSignal): boolean | null {
  if (abortSignalAborted === undefined) {
    return null;
  }
  try {
    const state: unknown = reflectApply(abortSignalAborted, signal, []);
    return typeof state === 'boolean' ? state : null;
  } catch {
    return null;
  }
}

/** Register without consulting caller-controlled signal properties. */
function addAbortListener(signal: AbortSignal, listener: EventListener): boolean {
  try {
    reflectApply(eventTargetAddEventListener, signal, ['abort', listener, { once: true }]);
    return true;
  } catch {
    return false;
  }
}

/** Best-effort cleanup through the captured platform intrinsic. */
function removeAbortListener(signal: AbortSignal, listener: EventListener): void {
  try {
    reflectApply(eventTargetRemoveEventListener, signal, ['abort', listener]);
  } catch {
    // A platform failure cannot be allowed to reject an otherwise total exchange.
  }
}

/** An exchange that never reached the operating system. */
function unspawnedExchange(
  outcome: TransportOutcome,
  rejection: TransportRejection | null,
): AgentExchange {
  return objectFreeze({
    outcome,
    rejection,
    exitCode: null,
    terminatingSignal: null,
    stdout: '',
    stderr: '',
    stdoutTruncated: false,
    stderrTruncated: false,
    stdoutBytes: 0,
    stderrBytes: 0,
    terminationScope: TERMINATION_SCOPE.NOT_REQUIRED,
  });
}

/** True when a caught value is a POSIX "no such process" error. */
function isNoSuchProcess(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) {
    return false;
  }
  const code: unknown = (error as { readonly code?: unknown }).code;
  return code === 'ESRCH';
}

/** Signal the child's own process group. True when the group was reached. */
function signalProcessGroup(pid: number, signal: NodeJS.Signals): boolean {
  try {
    reflectApply(processKill, runtimeProcess, [-pid, signal]);
    return true;
  } catch (error: unknown) {
    // ESRCH means the group is already gone, which is the state we wanted.
    return isNoSuchProcess(error);
  }
}

/** Signal only the direct child, ignoring an already-dead process. */
function killDirectChild(child: ChildProcess, signal?: NodeJS.Signals): void {
  try {
    reflectApply(childProcessKill, child, signal === undefined ? [] : [signal]);
  } catch {
    // The child already exited; there is nothing left to signal.
  }
}

/** True when the child has already been observed to end. */
function hasEnded(child: ChildProcess): boolean {
  return child.exitCode !== null || child.signalCode !== null;
}

/** Resolve true when the child ends within `ms`, false when it outlives it. */
function waitForExit(child: ChildProcess, ms: number): Promise<boolean> {
  if (hasEnded(child)) {
    return resolved(true);
  }
  return new NativePromise<boolean>((resolve) => {
    let done = false;
    const finish = (value: boolean): void => {
      if (done) {
        return;
      }
      done = true;
      cancelTimeout(timer);
      removeEventListener(child, 'exit', onExit);
      resolve(value);
    };
    const onExit = (): void => {
      finish(true);
    };
    const timer = scheduleTimeout(() => {
      finish(false);
    }, ms);
    onEvent(child, 'exit', onExit);
  });
}

/**
 * Run one best-effort cleanup step after a mandatory hardening failure.
 *
 * Cleanup on that path is best effort by definition. The handle it operates on
 * has already been observed to be hostile, so reading `stdout`, destroying a
 * pipe, or clearing listeners can each throw. None of those secondary failures
 * may displace the hardening error the caller is owed, and none of them may
 * abandon the steps that follow, so every step is isolated here.
 */
function attemptCleanup(step: () => void): void {
  try {
    step();
  } catch {
    // Deliberately absorbed; see the doc comment. The mandatory hardening
    // failure is still what the scheduling path reports to the caller.
  }
}

/**
 * Clear a failed exchange's listeners without leaving the handle uncovered.
 *
 * {@link removeAllEvents} also removes the spawn-failure absorber, so restoring
 * it belongs to the same synchronous step: nothing can be dispatched between
 * the two calls, and the handle is therefore never observably uncovered. A
 * hostile handle can make the restore itself throw, which would leave a queued
 * spawn failure with no listener and take the host process down with it, so the
 * absorber is installed once *before* the clear as well. That first call is the
 * evidence that the captured `on` intrinsic still works on this handle; when it
 * does not, the listeners are left exactly as they are, because a handle that
 * kept its absorber is strictly safer than one left uncovered.
 */
function clearEventsKeepingAbsorber(child: ChildProcess): void {
  try {
    rearmSpawnFailureAbsorber(child);
  } catch {
    return;
  }
  attemptCleanup(() => {
    removeAllEvents(child);
    rearmSpawnFailureAbsorber(child);
  });
}

/** Kill and reap a helper whose post-spawn dispatch hardening failed. */
async function reapUnprotectedHelper(child: ChildProcess): Promise<void> {
  killDirectChild(child);
  await waitForExit(child, TASKKILL_TIMEOUT_MS);
  removeAllEvents(child);
  // Clearing the listeners also cleared the absorber, and this helper's own
  // spawn failure may still be queued, so cover the handle again.
  rearmSpawnFailureAbsorber(child);
}

/**
 * Locate `taskkill.exe` from the Windows system directory.
 *
 * `C:\Windows` is **not** assumed. The directory comes from the transport's own
 * `SystemRoot` (or `windir`) and is validated as an absolute, NUL-free, bounded
 * path before use; anything else yields `null`, which degrades termination
 * honestly rather than guessing at a path.
 *
 * This value is read for this internal operation only. It is never added to the
 * child's environment, never written into an exchange, and never echoed
 * anywhere — the child environment remains exactly what the caller supplied.
 */
function resolveTaskkill(): { readonly executable: string; readonly systemRoot: string } | null {
  const raw: unknown = runtimeProcess.env['SystemRoot'] ?? runtimeProcess.env['windir'];
  if (typeof raw !== 'string' || raw.length === 0) {
    return null;
  }
  if (containsNul(raw)) {
    return null;
  }
  if (utf8ByteLength(raw) > TRANSPORT_BOUNDS.MAX_PATH_BYTES) {
    return null;
  }
  if (!isAbsolutePath(raw, 'win32')) {
    return null;
  }
  const last = reflectApply(stringCharCodeAt, raw, [raw.length - 1]);
  const separator = last === 0x5c || last === 0x2f ? '' : '\\';
  return { executable: `${raw}${separator}System32\\taskkill.exe`, systemRoot: raw };
}

/**
 * Ask Windows to end the child's process tree.
 *
 * Spawned directly — no shell, no PATH search, no composed command line, and no
 * caller-controlled argument. The only variable is a decimal PID this module
 * produced. Resolves true only when `taskkill` actually ran to a conclusive
 * exit; exit code 128 counts, because it means the target was already gone.
 */
function runTaskkill(
  taskkill: { readonly executable: string; readonly systemRoot: string },
  pid: number,
): Promise<boolean> {
  return new NativePromise<boolean>((resolve) => {
    let killer: ChildProcess;
    try {
      const decimalPid = reflectApply(numberToString, pid, []);
      killer = spawn(taskkill.executable, ['/PID', decimalPid, '/T', '/F'], {
        stdio: 'ignore',
        shell: false,
        windowsHide: true,
        windowsVerbatimArguments: false,
        env: { SystemRoot: taskkill.systemRoot },
      });
    } catch {
      resolve(false);
      return;
    }
    // Before anything else can throw: taskkill's own failure to start arrives
    // asynchronously, and hardening runs before this helper's error handler.
    rearmSpawnFailureAbsorber(killer);
    try {
      protectChildDispatch(killer);
    } catch {
      // The reap operates on a handle whose hardening already failed, so its
      // own steps can throw. Resolving from both settlement paths keeps this
      // helper's promise — and therefore every termination that awaits it —
      // total, and leaves no discarded rejection unhandled.
      void reapUnprotectedHelper(killer).then(
        () => {
          resolve(false);
        },
        () => {
          resolve(false);
        },
      );
      return;
    }

    let done = false;
    let reapTimer: NodeJS.Timeout | null = null;
    const finish = (value: boolean): void => {
      if (done) {
        return;
      }
      done = true;
      cancelTimeout(timer);
      if (reapTimer !== null) {
        cancelTimeout(reapTimer);
      }
      removeAllEvents(killer);
      resolve(value);
    };
    const timer = scheduleTimeout(() => {
      if (hasEnded(killer)) {
        finish(false);
        return;
      }
      killDirectChild(killer);
      // Observe the helper's exit after killing it. The second bound preserves
      // totality even if the operating system never reports a terminal event.
      reapTimer = scheduleTimeout(() => {
        finish(false);
      }, TASKKILL_TIMEOUT_MS);
    }, TASKKILL_TIMEOUT_MS);
    onEvent(killer, 'error', () => {
      finish(false);
    });
    onEvent(killer, 'exit', (code: number | null) => {
      finish(code === 0 || code === 128);
    });
  });
}

/**
 * POSIX termination: signal the process group, then escalate.
 *
 * The child was spawned `detached`, so it leads its own process group and
 * `kill(-pid, ...)` reaches its ordinary descendants. A descendant that called
 * `setsid` itself has left that group and is not reached — which is why the
 * returned scope says *requested*, never *completed*.
 */
async function terminatePosix(
  child: ChildProcess,
  pid: number,
  graceMs: number,
): Promise<TerminationScope> {
  if (hasEnded(child)) {
    return TERMINATION_SCOPE.DIRECT_CHILD_ONLY;
  }

  let groupReached = signalProcessGroup(pid, 'SIGTERM');
  if (!groupReached) {
    killDirectChild(child, 'SIGTERM');
  }
  if (await waitForExit(child, graceMs)) {
    return groupReached
      ? TERMINATION_SCOPE.PROCESS_GROUP_REQUESTED
      : TERMINATION_SCOPE.DIRECT_CHILD_ONLY;
  }

  // The grace timer and child exit can become ready in the same event-loop
  // turn. Once the child is observed ended, its numeric process-group ID may
  // be reused, so it must not receive the escalation signal.
  if (hasEnded(child)) {
    return groupReached
      ? TERMINATION_SCOPE.PROCESS_GROUP_REQUESTED
      : TERMINATION_SCOPE.DIRECT_CHILD_ONLY;
  }

  if (!signalProcessGroup(pid, 'SIGKILL')) {
    killDirectChild(child, 'SIGKILL');
    groupReached = false;
  }
  await waitForExit(child, graceMs);
  return groupReached
    ? TERMINATION_SCOPE.PROCESS_GROUP_REQUESTED
    : TERMINATION_SCOPE.DIRECT_CHILD_ONLY;
}

/**
 * Windows termination: ask `taskkill /T /F`, and fall back honestly.
 *
 * Returns only after the `taskkill` attempt has finished or reached its own
 * bounded failure path, and after the direct child has been waited on. When
 * `taskkill` cannot start, fails, or times out, the direct child is terminated
 * and the scope degrades to `DIRECT_CHILD_ONLY` — descendants are not claimed.
 */
async function terminateWindows(
  child: ChildProcess,
  pid: number,
  graceMs: number,
): Promise<TerminationScope> {
  // Once the leader has ended, its numeric PID may identify an unrelated
  // process. Safety outranks reaching descendants that outlived the leader.
  if (hasEnded(child)) {
    return TERMINATION_SCOPE.DIRECT_CHILD_ONLY;
  }

  const taskkill = resolveTaskkill();
  if (taskkill === null) {
    killDirectChild(child);
    await waitForExit(child, graceMs);
    return TERMINATION_SCOPE.DIRECT_CHILD_ONLY;
  }

  const issued = await runTaskkill(taskkill, pid);
  if (!issued) {
    killDirectChild(child);
    await waitForExit(child, graceMs);
    return TERMINATION_SCOPE.DIRECT_CHILD_ONLY;
  }

  await waitForExit(child, graceMs);
  return TERMINATION_SCOPE.PROCESS_TREE_REQUESTED;
}

/** Dispatch termination to the platform strategy. */
async function terminate(
  child: ChildProcess,
  platform: TransportPlatform,
  graceMs: number,
): Promise<TerminationScope> {
  const pid = child.pid;
  if (pid === undefined) {
    // Never started, so nothing beyond the handle can be reached. Reported as
    // degraded rather than as a successful group or tree request.
    return TERMINATION_SCOPE.DIRECT_CHILD_ONLY;
  }
  return platform === 'posix'
    ? terminatePosix(child, pid, graceMs)
    : terminateWindows(child, pid, graceMs);
}

/**
 * Release a child whose mandatory post-spawn dispatch hardening failed.
 *
 * Both halves of this operate on a handle already observed to be hostile:
 * {@link terminate} can reject when an accessor it consults throws, and each
 * cleanup step can throw either while reading `stdout`/`stderr` or on the value
 * such an accessor yields. This function therefore **never rejects and never
 * abandons a later step**, which is what lets its caller reach the one
 * rejection the exchange owes on every hostile path.
 *
 * Nothing here strengthens any guarantee. Termination stays a bounded
 * *attempt*, a failed kill stays a failed kill, and cleanup stays best effort;
 * only the obligation to settle is absolute. The one thing this does insist on
 * is that the attempt is actually *made*: when the platform strategy faults
 * before it can signal, a single direct-child signal follows, and no process
 * group, tree, or descendant is claimed on that path.
 */
async function releaseUnprotectedChild(
  child: ChildProcess,
  platform: TransportPlatform,
  graceMs: number,
): Promise<void> {
  try {
    await terminate(child, platform, graceMs);
  } catch {
    // A bounded termination attempt that fails is still only an attempt. The
    // exchange's obligation is to settle, not to prove the child is gone.
    //
    // *No* attempt is a different thing. Termination consults the handle's own
    // `exitCode`/`signalCode` before it signals anything, so a hostile accessor
    // can abort the attempt on its very first observation — before any signal
    // has been delivered, and on Windows before the helper that would deliver
    // one has even been started. Releasing responsibility there would abandon a
    // live direct child, so exactly one guarded direct-child signal is
    // delivered here first. {@link killDirectChild} is the same primitive
    // {@link reapUnprotectedHelper} already relies on: it goes through the
    // captured `kill` intrinsic, reads no property of the handle, and absorbs
    // its own failure. Nothing is waited on and nothing beyond the direct child
    // is attempted, so this can neither re-enter a hostile accessor nor defer
    // the rejection the caller is owed, and a fallback that fails stays a
    // failure rather than becoming a claim.
    killDirectChild(child);
  }
  attemptCleanup(() => {
    destroyReadable(child.stdout);
  });
  attemptCleanup(() => {
    destroyReadable(child.stderr);
  });
  clearEventsKeepingAbsorber(child);
}

/**
 * Run one process exchange.
 *
 * **Total.** Resolves to exactly one frozen {@link AgentExchange} on every
 * validation, spawn, I/O, timeout, cancellation, overflow, termination, and
 * close path. It never rejects and never throws by design. Catches are placed
 * only around defined operational failures — `spawn`, `kill`, a broken stdin
 * pipe, a hostile `AbortSignal` getter — so a programmer defect still surfaces
 * as a defect rather than being laundered into a failure code.
 *
 * **Deterministic precedence.** Every detected terminal cause is compared with
 * `TERMINAL_CAUSE_PRECEDENCE`; callback arrival order cannot demote a stronger
 * cause. Overflow, cancellation, and timeout are detected eagerly, while
 * `SIGNALLED` and `EXITED` are detected when stdio closes.
 *
 * **No policy.** Nothing here decides whether this process should run. That
 * question belongs to `evaluateActionRequest` and to a later adapter that must
 * hold an unforgeable capability before calling this function.
 *
 * @param spec Process specification. Validated structurally; never trusted to
 *   be well-typed at runtime.
 * @param limits Bounds and optional cancellation for this exchange.
 */
export function invokeAgentProcess(
  spec: AgentProcessSpec,
  limits: TransportLimits,
): Promise<AgentExchange> {
  const platform: TransportPlatform =
    runtimeProcess.platform === 'win32' ? 'win32' : 'posix';

  // Precedence step 1: structural validation runs before the abort check, so a
  // request that is both malformed and already aborted is SPEC_REJECTED.
  const read = readInvocation(spec, limits, platform);
  if (read.rejection !== null) {
    return resolved(
      unspawnedExchange(TRANSPORT_OUTCOME.SPEC_REJECTED, read.rejection),
    );
  }
  const invocation = read.value;

  let abortPending = false;
  let abortDispatch: (() => void) | null = null;
  const onAbort: EventListener = () => {
    if (abortDispatch === null) {
      abortPending = true;
      return;
    }
    abortDispatch();
  };
  if (invocation.signal !== null) {
    const beforeRegistration = readAbortState(invocation.signal);
    if (beforeRegistration === null) {
      return resolved(
        unspawnedExchange(
          TRANSPORT_OUTCOME.SPEC_REJECTED,
          'ABORT_SIGNAL_INVALID',
        ),
      );
    }
    if (beforeRegistration) {
      return resolved(unspawnedExchange(TRANSPORT_OUTCOME.CANCELLED, null));
    }
    if (!addAbortListener(invocation.signal, onAbort)) {
      return resolved(
        unspawnedExchange(
          TRANSPORT_OUTCOME.SPEC_REJECTED,
          'ABORT_SIGNAL_INVALID',
        ),
      );
    }
    const afterRegistration = readAbortState(invocation.signal);
    if (afterRegistration === null || afterRegistration) {
      removeAbortListener(invocation.signal, onAbort);
      return resolved(
        unspawnedExchange(
          afterRegistration === null
            ? TRANSPORT_OUTCOME.SPEC_REJECTED
            : TRANSPORT_OUTCOME.CANCELLED,
          afterRegistration === null ? 'ABORT_SIGNAL_INVALID' : null,
        ),
      );
    }
  }

  return new NativePromise<AgentExchange>((resolve, reject) => {
    let child: ChildProcess;
    try {
      child = spawn(invocation.executablePath, invocation.args, {
        cwd: invocation.workingDirectory,
        env: invocation.environment,
        stdio: ['pipe', 'pipe', 'pipe'],
        shell: false,
        windowsHide: true,
        windowsVerbatimArguments: false,
        // POSIX only: makes the child a process-group leader so its ordinary
        // descendants can be signalled together. On Windows `detached` would
        // allocate a new console instead, which does not help termination.
        detached: platform === 'posix',
      });
    } catch {
      if (invocation.signal !== null) {
        removeAbortListener(invocation.signal, onAbort);
      }
      resolve(unspawnedExchange(TRANSPORT_OUTCOME.SPAWN_FAILED, null));
      return;
    }
    // Before anything else can throw: an asynchronous spawn failure is already
    // queued by now, and the real handler below is not installed until hardening
    // has succeeded.
    rearmSpawnFailureAbsorber(child);
    try {
      protectChildDispatch(child);
    } catch (error: unknown) {
      if (invocation.signal !== null) {
        removeAbortListener(invocation.signal, onAbort);
      }
      // Normalised here, before the asynchronous release, so the reason this
      // exchange rejects with is already fixed and cannot itself be lost to a
      // later hostile read.
      const hardeningFailure =
        error instanceof Error
          ? error
          : new Error('Process dispatch hardening failed', { cause: error });
      // `releaseUnprotectedChild` runs every step and never rejects, and the
      // rejection is scheduled on *both* settlement paths of the chain anyway,
      // so neither a termination failure nor a cleanup step that throws on a
      // poisoned `stdout`/`stderr` value can leave this exchange pending or
      // leave an internal rejection unhandled. The mandatory hardening failure
      // stays the externally visible reason on every one of those paths.
      void releaseUnprotectedChild(child, platform, invocation.graceMs).then(
        () => {
          reject(hardeningFailure);
        },
        () => {
          reject(hardeningFailure);
        },
      );
      return;
    }

    const stdoutSink = createSink(invocation.maxStdoutBytes);
    const stderrSink = createSink(invocation.maxStderrBytes);

    let cause: TransportOutcome | null = null;
    let settled = false;
    let closed = false;
    /** Set once a termination lifecycle begins, and never cleared thereafter. */
    let terminating = false;
    let exitCode: number | null = null;
    let terminatingSignal: string | null = null;
    let terminationScope: TerminationScope = TERMINATION_SCOPE.NOT_REQUIRED;
    let deadline: NodeJS.Timeout | null = null;
    let notifyClosed: (() => void) | null = null;

    /** Promote only to a stronger declared cause. */
    const claim = (next: TransportOutcome): boolean => {
      if (cause === null || precedenceRank(next) < precedenceRank(cause)) {
        cause = next;
        return true;
      }
      return false;
    };

    const dispatchAbort = (): void => {
      if (claim(TRANSPORT_OUTCOME.CANCELLED)) {
        void runTermination();
      }
    };

    const cleanup = (): void => {
      if (deadline !== null) {
        cancelTimeout(deadline);
        deadline = null;
      }
      if (notifyClosed !== null) {
        // Releases the bounded close-wait timer so no timer outlives the
        // exchange, even on a path that settles while that wait is pending.
        const notify = notifyClosed;
        notifyClosed = null;
        notify();
      }
      if (invocation.signal !== null) {
        removeAbortListener(invocation.signal, onAbort);
      }
      if (child.stdout !== null) {
        removeAllEvents(child.stdout);
      }
      if (child.stderr !== null) {
        removeAllEvents(child.stderr);
      }
      if (child.stdin !== null) {
        removeAllEvents(child.stdin);
      }
      removeAllEvents(child);
    };

    const settle = (): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      const out = decodeSink(stdoutSink);
      const err = decodeSink(stderrSink);
      resolve(
        objectFreeze({
          outcome: cause ?? TRANSPORT_OUTCOME.EXITED,
          rejection: null,
          exitCode,
          terminatingSignal,
          stdout: out.text,
          stderr: err.text,
          stdoutTruncated: stdoutSink.truncated,
          stderrTruncated: stderrSink.truncated,
          stdoutBytes: out.bytes,
          stderrBytes: err.bytes,
          terminationScope,
        }),
      );
    };

    /** Resolve true on close, false when the bounded close wait expires. */
    function awaitClose(ms: number): Promise<boolean> {
      if (closed) {
        return resolved(true);
      }
      return new NativePromise<boolean>((resolveWait) => {
        const waiter = scheduleTimeout(() => {
          notifyClosed = null;
          resolveWait(false);
        }, ms);
        notifyClosed = (): void => {
          cancelTimeout(waiter);
          resolveWait(true);
        };
      });
    }

    /**
     * Terminate, then settle.
     *
     * Settling is deferred until termination has finished reporting, so an
     * exchange can never resolve with `NOT_REQUIRED` while a kill it initiated
     * is still in flight.
     *
     * **This always settles.** Waiting for `close` alone is not safe: a
     * descendant that inherited the stdio pipes keeps them open after the direct
     * child is gone, and one that escaped termination keeps them open forever,
     * so `close` may never arrive. Once termination has reported, stdio gets one
     * bounded chance to close and the exchange resolves regardless. Totality
     * outranks a complete transcript, and the transcript is already known to be
     * partial whenever this path runs.
     *
     * **Entered at most once.** The guard covers the whole lifecycle — the kill
     * itself, the bounded close wait, and settlement — not just the kill. A
     * stronger terminal cause arriving mid-flight still promotes the reported
     * cause through {@link claim}, because that decision is independent of this
     * function; what it must not do is start a second lifecycle, which would
     * overwrite an already-reported {@link TerminationScope}, arm a second
     * close-wait timer whose predecessor can then no longer be released, and
     * leave that timer running after the exchange has settled.
     *
     * **Nothing is allocated after settlement.** The kill is an asynchronous
     * suspension point, and a stronger cause can settle the exchange while it is
     * in flight — an asynchronous spawn failure racing a cancellation is the
     * reachable case. {@link cleanup} has then already run and released every
     * handler that could report a close, so arming the bounded close wait past
     * that point would create a timer nothing is left to release, keeping the
     * host alive for a further grace period after the caller's exchange has
     * resolved. Once settled there is also nothing left to wait for, so this
     * lifecycle simply stops.
     */
    async function runTermination(): Promise<void> {
      if (terminating) {
        return;
      }
      terminating = true;
      terminationScope = await terminate(child, platform, invocation.graceMs);

      if (settled) {
        return;
      }

      if (!closed) {
        if (!hasEnded(child)) {
          terminationScope = TERMINATION_SCOPE.ESCALATION_FAILED;
        }
        const closeObserved = await awaitClose(invocation.graceMs);
        if (!closeObserved) {
          // A detached descendant can retain the inherited pipe handles after
          // the direct child ends. Release this process's local ends before the
          // forced settlement so the caller is not kept alive by leaked wraps.
          destroyReadable(child.stdout);
          destroyReadable(child.stderr);
        }
      }
      settle();
    }

    const onStdout = (chunk: unknown): void => {
      if (!bufferIsBuffer(chunk)) {
        return;
      }
      if (pushChunk(stdoutSink, chunk) && claim(TRANSPORT_OUTCOME.OUTPUT_LIMIT_EXCEEDED)) {
        void runTermination();
      }
    };

    const onStderr = (chunk: unknown): void => {
      if (!bufferIsBuffer(chunk)) {
        return;
      }
      if (pushChunk(stderrSink, chunk) && claim(TRANSPORT_OUTCOME.OUTPUT_LIMIT_EXCEEDED)) {
        void runTermination();
      }
    };

    if (child.stdout !== null) {
      onEvent(child.stdout, 'error', () => {
        // A read-side pipe failure must not escape as an uncaught EventEmitter
        // error. The child close path remains the provider-neutral outcome.
      });
      onReadableData(child.stdout, onStdout);
    }
    if (child.stderr !== null) {
      onEvent(child.stderr, 'error', () => {
        // Kept separate from stdout so neither stream can contaminate the
        // other's transcript or settlement path.
      });
      onReadableData(child.stderr, onStderr);
    }

    onEvent(child, 'error', () => {
      // Only a failure to start is terminal on its own. A post-spawn error such
      // as a broken pipe is recorded by the close path instead.
      if (child.pid === undefined) {
        claim(TRANSPORT_OUTCOME.SPAWN_FAILED);
        settle();
      }
    });

    onEvent(child, 'exit', (code: number | null, signalName: NodeJS.Signals | null) => {
      exitCode = code;
      terminatingSignal = signalName;
    });

    onEvent(child, 'close', () => {
      closed = true;
      // Claimed here rather than on 'exit', so output that arrives between exit
      // and close can still promote the exchange to OUTPUT_LIMIT_EXCEEDED.
      claim(
        terminatingSignal !== null
          ? TRANSPORT_OUTCOME.SIGNALLED
          : TRANSPORT_OUTCOME.EXITED,
      );
      if (notifyClosed !== null) {
        const notify = notifyClosed;
        notifyClosed = null;
        notify();
      }
      // A termination lifecycle that has begun owns settlement for the rest of
      // its run: the notification above releases its bounded close wait, and it
      // settles from there. Settling here as well would only race that lifecycle.
      if (!terminating) {
        settle();
      }
    });

    const stdin = child.stdin;
    if (stdin !== null) {
      onEvent(stdin, 'error', () => {
        // A child that exits before reading breaks the pipe. That is the
        // child's behaviour, not a transport failure, and the close path
        // decides the outcome.
      });
      reflectApply(writableEnd, stdin, [invocation.stdin, 'utf8']);
    }

    abortDispatch = dispatchAbort;
    if (abortPending || (invocation.signal !== null && readAbortState(invocation.signal))) {
      dispatchAbort();
    }

    deadline = scheduleTimeout(() => {
      if (claim(TRANSPORT_OUTCOME.TIMED_OUT)) {
        void runTermination();
      }
    }, invocation.timeoutMs);
  });
}

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
// Continuation scheduling, captured away from the property lookup that reaches
// it. The settlement paths below hand the caller its mandatory failure from a
// continuation installed on an internal release promise, and an ordinary
// `release.then(...)` resolves `then` through `Promise.prototype` — an
// ordinary, writable property of an ordinary, mutable object. Both of those
// settlement sites are reached only *after* a value engineered to run code on
// inspection has already had its turn, so a hostile path gets to substitute
// the scheduler strictly before the continuation is installed. A replacement
// that simply returns installs no continuation at all and leaves the caller
// pending for good — the exchange deadline cannot rescue it, because on these
// paths that deadline is not armed yet; a replacement that throws replaces the
// mandatory failure with the hostile value. Read from a binding fixed at module
// load, the scheduling call is the intrinsic regardless of what
// `Promise.prototype` holds by the time it is reached.
//
// What the capture alone does not make total is the intrinsic's own prologue:
// `then` derives its result promise through `SpeciesConstructor`, which reads
// `constructor` off the promise — another mutable inherited property — before
// it registers anything. Every use below is therefore wrapped so that a fault
// raised before registration still delivers exactly the settlement the
// continuation would have delivered. The registration itself cannot be
// subverted once it is reached: the derived promise is discarded here, and the
// handlers are attached to the real promise whatever the species constructor
// returned.
// eslint-disable-next-line @typescript-eslint/unbound-method
const promiseThen = Promise.prototype.then;
// The constructor this module builds its own failures with. `Error` is an
// ordinary writable global, and the hardening-failure path below has to
// construct through it *after* having touched a value engineered to run code
// on inspection. Captured here, at module load, that construction can no
// longer be routed through whatever such a value installed in the meantime.
const NativeError = Error;
// The `instanceof` *operation*, captured away from the `instanceof` *operator*.
//
// The operator does not test the prototype chain directly: it first looks up
// `@@hasInstance` on its right-hand operand, and only walks the chain when that
// lookup finds nothing. Capturing the constructor therefore fixes only *which*
// object is asked; it leaves the question itself answerable by an own hook
// installed on that object. `Error` is a mutable object as well as a mutable
// global, and a hostile path reachable before classification can define an own
// `Error[Symbol.hasInstance]` returning `true` for anything — laundering a
// non-Error into the ordinary-Error branch, so that the raw hostile value
// becomes the caller-facing reason and the normalization below never runs.
//
// `Function.prototype[Symbol.hasInstance]` is the intrinsic that performs the
// plain chain walk, and it is a non-writable, non-configurable data property of
// `Function.prototype`, so no code — before this capture or after it — can
// substitute it. Invoked through the captured `Reflect.apply` with the captured
// constructor as its `this`, it answers the same question the operator was
// asked, without the own-property lookup that made the answer forgeable. What
// it does *not* skip is the operand's own prototype chain: that read is still a
// call into the value's own code, which is why every use stays inside a `try`.
const ordinaryHasInstance = Function.prototype[Symbol.hasInstance];
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

/**
 * The promise kind this module awaits.
 *
 * `await` does not read `then` off an ordinary native promise: `PromiseResolve`
 * recognises the promise as its own kind and hands it straight to the internal
 * reaction machinery. The recognition test is `Get(promise, "constructor")`,
 * and for a promise carrying no own `constructor` that read walks up to
 * `Promise.prototype.constructor` — an ordinary, writable property of an
 * ordinary, mutable object. Replace it with anything that is not the intrinsic
 * and the fast path is abandoned: the awaited value is then resolved as a plain
 * thenable, which *does* read `then`, reaching whatever a hostile path
 * installed on `Promise.prototype` in the meantime. A replacement that installs
 * no continuation leaves the `await` suspended for good, and everything waiting
 * behind it with it — including the mandatory hardening rejection and the
 * ordinary timeout settlement, neither of which has any further deadline left
 * to rescue it.
 *
 * {@link protectPromiseResolution} answers that lookup with an own property. It
 * cannot answer it *unconditionally*: defining a property requires an
 * extensible target, and a promise this module allocates is not private between
 * the allocation and the next statement. Ordinary Node facilities — an
 * `async_hooks` `init` hook is the reachable one, which receives each newly
 * allocated promise as its own resource — can observe it first and seal it, and
 * the definition then throws before it can land. Nothing in this file can
 * prevent that, because the observation happens inside the allocation itself.
 *
 * The lookup is a *chain* walk, though, and only its last step is the mutable
 * one. A promise whose immediate prototype is an object this module owns never
 * reaches `Promise.prototype` at all: the walk stops one link earlier, at a
 * `constructor` fixed to the captured {@link NativePromise} on a prototype
 * created and frozen at module load, before any hostile path can run. That
 * answer needs no own property on the instance, so sealing the instance — the
 * one thing this module cannot prevent — no longer decides anything.
 *
 * Every promise this module reports through is therefore allocated from here,
 * and {@link internalStep} exists so that the promises the runtime allocates
 * for `async` functions are never among them.
 *
 * `Symbol.species` is a different matter. It is not consulted on the `await`
 * route, but nothing here takes that route any more: continuations are
 * registered through the captured `then`, and that intrinsic resolves a species
 * constructor before it registers anything. A hostile `@@species` can therefore
 * make registration itself throw. That is not defended against here — it is
 * *reported*, by {@link whenSettled}, so the caller can fall back synchronously
 * instead of waiting for a continuation that was never installed.
 *
 * The prototype's `constructor` is redefined rather than added, so a sealed
 * prototype could not defeat this step either: the class definition already
 * gave it that own property, and redefining a configurable own property does
 * not require extensibility.
 */
class InternalPromise<T> extends Promise<T> {}
// `void`: both intrinsics return their own first argument, which here is typed
// as a promise because a promise prototype is one.
void objectDefineProperty(InternalPromise.prototype, 'constructor', {
  configurable: false,
  enumerable: false,
  value: NativePromise,
  writable: false,
});
void objectFreeze(InternalPromise.prototype);
void objectFreeze(InternalPromise);

/**
 * Report one internal asynchronous step through a promise this module owns.
 *
 * An `async` function's own promise comes from the runtime's intrinsic
 * capability, so it inherits `constructor` straight from `Promise.prototype`
 * and carries no own one. Awaiting it is exactly the lookup {@link
 * InternalPromise} exists to avoid, and it cannot be repaired after the fact:
 * the promise may already be sealed, and the only way to observe it — `then` —
 * is the property under mutation. So no `async` function's promise is ever
 * awaited here. The step reports its result through the capability it is
 * handed, and the promise the runtime made for it is never consulted.
 *
 * That makes the step responsible for absorbing its own faults into `fail`,
 * which every one of them does. The absorber below is a second layer for a
 * programmer defect only: settlement never depends on it being installed, so a
 * fault in the intrinsic's own species prologue costs nothing here.
 */
function internalStep<T>(
  step: (settle: (value: T) => void, fail: (reason: unknown) => void) => void,
): Promise<T> {
  return new InternalPromise<T>((resolve, reject) => {
    try {
      step(resolve, reject);
    } catch (error) {
      // A step reports through the capability it is handed, so reaching here is
      // a step that threw before it could. The reason is still owed to the
      // caller, and this is the only place left to hand it over.
      reject(error);
    }
  });
}

/**
 * Register a continuation on a promise this module owns, without awaiting it.
 *
 * `await` is the one operation this module cannot use on its own promises. It
 * resolves the awaited value through `PromiseResolve`, which reads
 * `constructor` off it to decide whether the internal fast path applies — and
 * that read is a property lookup on an object an ordinary `async_hooks` `init`
 * hook has already seen. The hook receives each promise inside the allocation
 * that produced it, while it is still extensible, and may both *reparent* it to
 * the ordinary `Promise.prototype` and seal it there. Neither of this module's
 * two answers to that lookup survives the pair: the own property cannot be
 * defined on a sealed target, and the prototype that would have answered it is
 * no longer on the instance's chain. The lookup then reaches a mutated
 * `Promise.prototype.constructor`, the value is assimilated as a plain thenable
 * through a mutated `then`, and a `then` that installs no continuation leaves
 * the `await` suspended for good — including the ordinary timeout settlement
 * and the mandatory hardening rejection, neither of which has any deadline left
 * to rescue it.
 *
 * `Promise.prototype.then` applied through {@link reflectApply} reads none of
 * that. It is the intrinsic captured at module load, invoked on the promise
 * directly, and it works from the promise's own internal state: no `constructor`
 * lookup, no `then` lookup, and nothing that a prototype change or a seal can
 * reach. The same idiom the taskkill reaper already relies on, applied to every
 * internal continuation rather than to one.
 *
 * **Registration failure is not operation failure, and is reported apart from
 * it.** The intrinsic runs `SpeciesConstructor` before it registers anything:
 * it reads `constructor` off the promise and `@@species` off whatever that
 * yields. On a reparented, sealed instance both reads reach attacker-controlled
 * objects, so the intrinsic can throw with no continuation installed. Answering
 * that with `onFault` would say the operation reported a failure, when what
 * actually happened is that the operation is still running and will never be
 * heard from. A caller that owns a bounded termination or a cleanup would then
 * abandon it mid-flight — the escalation never sent, the retained pipes never
 * released — while settling as though termination had reported.
 *
 * So the answer is a boolean: `true` when a continuation was registered, `false`
 * when it was not. On `false` **nothing is called**, which is what lets each
 * caller run its own synchronous fallback without risking a second settlement.
 * Synchronous is the only option worth having here: the same hostile `@@species`
 * defeats every later registration too, so a fallback that needs a continuation
 * is no fallback at all.
 *
 * **It does not catch throws from `onValue`.** A continuation runs from a
 * promise job, outside every `try` that lexically encloses the call, so a fault
 * raised there reaches no `catch` at all: it becomes an unhandled rejection on
 * a promise nothing observes, and whatever the continuation was going to settle
 * stays pending for good. Every continuation that reads the child handle —
 * `hasEnded`, `pid`, `stdout`, `stderr`, or anything reached through
 * {@link waitForExit} — therefore carries its own guard and routes the fault to
 * the capability it was given. The guarded steps in the termination strategies
 * and in the exchange lifecycle exist for exactly that reason.
 */
function whenSettled<T>(
  promise: Promise<T>,
  onValue: (value: T) => void,
  onFault: (reason: unknown) => void,
): boolean {
  try {
    void reflectApply(promiseThen, promise, [onValue, onFault]);
    return true;
  } catch {
    return false;
  }
}

/**
 * Fix one promise's `constructor` lookup with an own property.
 *
 * A second layer over {@link InternalPromise}, and the only one available for a
 * promise handed to a caller outside this module. It answers the same
 * recognition test one step earlier in the chain, and non-configurably, so
 * nothing that runs later can take it back off again.
 *
 * **It can fail, and its failure is survivable.** Defining a property requires
 * an extensible target, and an ordinary Node facility can seal a promise inside
 * the allocation that produced it — before any statement of this module runs
 * against it. The definition then throws. Returning the promise unchanged keeps
 * this helper from becoming a rejection path of its own; what makes that
 * *safe*, rather than a silent downgrade, is that every promise this module
 * awaits itself already answers the same lookup from a prototype it owns, where
 * no own property is needed. A promise that only leaves this module — the
 * settled exchange handed back by {@link resolved} — is not awaited here, and
 * how an external caller consumes it is that caller's own runtime.
 */
function protectPromiseResolution<T>(promise: Promise<T>): Promise<T> {
  try {
    // `void`: the intrinsic returns its own argument, which here is a promise.
    void objectDefineProperty(promise, 'constructor', {
      configurable: false,
      enumerable: false,
      value: NativePromise,
      writable: false,
    });
  } catch {
    // Reachable: the target may have been sealed inside its own allocation.
    // See the doc comment for why returning it unchanged is survivable.
  }
  return promise;
}

/** An already-settled promise for a caller outside this module. */
function resolved<T>(value: T): Promise<T> {
  return protectPromiseResolution(
    new NativePromise<T>((resolve) => {
      resolve(value);
    }),
  );
}

/**
 * An already-settled promise this module goes on to `await` itself.
 *
 * Separate from {@link resolved} because the two have different consumers and
 * therefore different requirements. This one is allocated from {@link
 * InternalPromise}, whose prototype answers the recognition test without
 * needing an own property on the instance, so an `await` of it stays on its
 * fast path even when the instance was sealed inside its own allocation.
 */
function internallyResolved<T>(value: T): Promise<T> {
  return protectPromiseResolution(
    new InternalPromise<T>((resolve) => {
      resolve(value);
    }),
  );
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
    return internallyResolved(true);
  }
  const exited = new InternalPromise<boolean>((resolve) => {
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
  return protectPromiseResolution(exited);
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

/**
 * Kill and reap a helper whose post-spawn dispatch hardening failed.
 *
 * Reports through `done` rather than through a promise the caller would have to
 * await: the wait itself is registered with {@link whenSettled}, and `done` runs
 * on both of its outcomes. The steps after the wait operate on a handle already
 * observed to be hostile and can throw, which must not stop `done` from being
 * called — the caller's own settlement depends on it.
 */
function reapUnprotectedHelper(child: ChildProcess, done: () => void): void {
  const finish = (): void => {
    try {
      removeAllEvents(child);
      // Clearing the listeners also cleared the absorber, and this helper's own
      // spawn failure may still be queued, so cover the handle again.
      rearmSpawnFailureAbsorber(child);
    } catch {
      // Best effort on a hostile handle; the reap is over either way.
    }
    done();
  };
  killDirectChild(child);
  // Constructed before the continuation is registered, and guarded separately.
  // {@link waitForExit} observes `exitCode` and `signalCode` before it has a
  // promise to hand back, so a hostile accessor faults here — before
  // {@link whenSettled} runs and therefore before `finish` is attached to
  // anything. Ending through the same `finish` keeps the reap total: the
  // listeners are cleared, the absorber is rearmed, and `done` is called
  // exactly once. Guarding only the construction is deliberate — a `catch`
  // around the whole registration would also catch a throw from `finish`
  // itself and call it a second time.
  let wait: Promise<boolean>;
  try {
    wait = waitForExit(child, TASKKILL_TIMEOUT_MS);
  } catch {
    finish();
    return;
  }
  if (!whenSettled(wait, finish, finish)) {
    // The continuation was never installed, so the reap ends here — through the
    // same `finish` every other route takes, and exactly once.
    finish();
  }
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
  const issued = new InternalPromise<boolean>((resolve) => {
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
      //
      // Scheduled through the captured {@link promiseThen}: this module stays
      // loaded across exchanges, so any earlier hostile path in the process —
      // including the dispatch-hardening one this helper is itself the fallback
      // for — may already have replaced `Promise.prototype.then`. An ordinary
      // lookup here would reach that replacement, and a replacement that
      // installs nothing would leave this helper's promise pending, hanging the
      // `await` in `terminateWindows` and with it the whole bounded release.
      // The `catch` covers the intrinsic's own pre-registration prologue, so a
      // fault there still degrades to the same honest "not issued" answer the
      // continuations give rather than rejecting a promise the callers of this
      // helper treat as total.
      try {
        reapUnprotectedHelper(killer, () => {
          resolve(false);
        });
      } catch {
        resolve(false);
      }
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
  return protectPromiseResolution(issued);
}

/**
 * POSIX termination: signal the process group, then escalate.
 *
 * The child was spawned `detached`, so it leads its own process group and
 * `kill(-pid, ...)` reaches its ordinary descendants. A descendant that called
 * `setsid` itself has left that group and is not reached — which is why the
 * returned scope says *requested*, never *completed*.
 */
function terminatePosix(
  child: ChildProcess,
  pid: number,
  graceMs: number,
): Promise<TerminationScope> {
  return internalStep<TerminationScope>((settle, fail) => {
    const scopeFor = (groupReached: boolean): TerminationScope =>
      groupReached
        ? TERMINATION_SCOPE.PROCESS_GROUP_REQUESTED
        : TERMINATION_SCOPE.DIRECT_CHILD_ONLY;

    try {
      if (hasEnded(child)) {
        settle(TERMINATION_SCOPE.DIRECT_CHILD_ONLY);
        return;
      }

      const groupReached = signalProcessGroup(pid, 'SIGTERM');
      if (!groupReached) {
        killDirectChild(child, 'SIGTERM');
      }
      if (
        !whenSettled(
          waitForExit(child, graceMs),
          (ended: boolean) => {
            if (ended) {
              settle(scopeFor(groupReached));
              return;
            }
            escalate(groupReached);
          },
          fail,
        )
      ) {
        // SIGTERM is away, and nothing will report whether it worked. The
        // escalation this path exists to reach is the one thing still worth
        // doing, so it is done synchronously and without waiting: a signal a
        // POSIX child may catch has already been sent, and `SIGKILL` is the one
        // it may not. Only the direct child — no group is targeted here, so the
        // reported scope claims nothing the ratified PID-reuse position forbids.
        killDirectChild(child, 'SIGKILL');
        settle(TERMINATION_SCOPE.DIRECT_CHILD_ONLY);
      }
    } catch (error) {
      // Every observation above reads the handle, and a hostile accessor can
      // fault on any of them. The reason reaches the caller unchanged: this is
      // the same rejection the `async` form produced, reported through the
      // capability instead of through a promise nothing here may await.
      fail(error);
    }

    // The escalation half, entered only when the grace window expired with the
    // child still running. Its own guard, because every observation it makes
    // reads the handle and a hostile accessor can fault on any of them.
    function escalate(groupReached: boolean): void {
      try {
        // The grace timer and child exit can become ready in the same event-loop
        // turn. Once the child is observed ended, its numeric process-group ID
        // may be reused, so it must not receive the escalation signal.
        if (hasEnded(child)) {
          settle(scopeFor(groupReached));
          return;
        }

        let reached = groupReached;
        if (!signalProcessGroup(pid, 'SIGKILL')) {
          killDirectChild(child, 'SIGKILL');
          reached = false;
        }
        if (
          !whenSettled(
            waitForExit(child, graceMs),
            () => {
              settle(scopeFor(reached));
            },
            fail,
          )
        ) {
          // The escalation signal is already delivered; only the confirming
          // wait was lost. The scope is what it always was on this route.
          settle(scopeFor(reached));
        }
      } catch (error) {
        fail(error);
      }
    }
  });
}

/**
 * Windows termination: ask `taskkill /T /F`, and fall back honestly.
 *
 * Returns only after the `taskkill` attempt has finished or reached its own
 * bounded failure path, and after the direct child has been waited on. When
 * `taskkill` cannot start, fails, or times out, the direct child is terminated
 * and the scope degrades to `DIRECT_CHILD_ONLY` — descendants are not claimed.
 */
function terminateWindows(
  child: ChildProcess,
  pid: number,
  graceMs: number,
): Promise<TerminationScope> {
  return internalStep<TerminationScope>((settle, fail) => {
    // The degraded ending, shared by both paths that could not reach the tree:
    // signal the direct child, wait out the grace window, and claim nothing
    // beyond it. Its own guard, for the same reason the POSIX strategy needs
    // one — every step here reads the handle.
    const killDirectAndSettle = (): void => {
      try {
        killDirectChild(child);
        if (
          !whenSettled(
            waitForExit(child, graceMs),
            () => {
              settle(TERMINATION_SCOPE.DIRECT_CHILD_ONLY);
            },
            fail,
          )
        ) {
          // The signal is already delivered; only the confirming wait was lost.
          settle(TERMINATION_SCOPE.DIRECT_CHILD_ONLY);
        }
      } catch (error) {
        fail(error);
      }
    };

    // The tree-requested ending, entered once `taskkill` reported conclusively.
    // Its own guard, for the same reason the degraded ending needs one:
    // {@link waitForExit} observes the handle before it waits, this runs from a
    // continuation the function-wide `try` below does not cover, and a fault
    // that escapes a continuation reaches no `catch` at all.
    const awaitTreeExit = (): void => {
      try {
        if (
          !whenSettled(
            waitForExit(child, graceMs),
            () => {
              settle(TERMINATION_SCOPE.PROCESS_TREE_REQUESTED);
            },
            fail,
          )
        ) {
          // `taskkill` already reported conclusively; only the confirming wait
          // was lost, and the tree was still what was requested.
          settle(TERMINATION_SCOPE.PROCESS_TREE_REQUESTED);
        }
      } catch (error) {
        fail(error);
      }
    };

    try {
      // Once the leader has ended, its numeric PID may identify an unrelated
      // process. Safety outranks reaching descendants that outlived the leader.
      if (hasEnded(child)) {
        settle(TERMINATION_SCOPE.DIRECT_CHILD_ONLY);
        return;
      }

      const taskkill = resolveTaskkill();
      if (taskkill === null) {
        killDirectAndSettle();
        return;
      }

      if (
        !whenSettled(
          runTaskkill(taskkill, pid),
          (issued: boolean) => {
            if (!issued) {
              killDirectAndSettle();
              return;
            }
            awaitTreeExit();
          },
          fail,
        )
      ) {
        // The helper may be running, but whether it succeeded will never be
        // heard. Nothing may be claimed about the tree on that evidence, so this
        // degrades to the direct child — the same ending an inconclusive
        // `taskkill` already takes.
        killDirectAndSettle();
      }
    } catch (error) {
      // Same contract as the POSIX strategy: the handle reads above can fault,
      // and the reason reaches the caller unchanged.
      fail(error);
    }
  });
}

/**
 * Dispatch termination to the platform strategy.
 *
 * The platform result is **awaited and returned as a value**, never returned as
 * the platform promise itself. Handing a promise back out of an async function
 * does not pass it through; it resolves this function's own promise capability
 * *with* it, and resolving a capability with an object reads `then` off that
 * object. For an ordinary promise that read reaches `Promise.prototype.then` —
 * writable, inherited, and by this point already reachable by code the handle
 * ran on inspection. A replacement that installs no continuation makes this
 * function's promise permanently pending, and with it {@link
 * releaseUnprotectedChild}, the mandatory hardening rejection that waits on it,
 * and every ordinary timeout, cancellation, and overflow settlement that runs
 * through {@link runTermination} — all on paths where the exchange deadline is
 * either not yet armed or already spent, so nothing is left to end the wait.
 * Capturing `then` at module load does not help here: this lookup is performed
 * by the runtime's own resolution step, not by any call site in this file.
 *
 * Awaiting instead settles this function with a {@link TerminationScope}, which
 * is a string. Resolving a capability with a primitive reads nothing at all, so
 * the assimilation step that made the lookup reachable no longer occurs.
 *
 * That leaves the `await` itself, which decides whether it may skip
 * assimilation by reading `constructor` off the awaited promise. An own
 * property answers that read only while the promise is extensible, and a
 * promise is not private between its allocation and the next statement, so the
 * platform strategies report through {@link internalStep} — an {@link
 * InternalPromise}, whose prototype answers the read with no own property
 * involved. This function reports the same way, for the same reason: its own
 * promise is awaited by {@link releaseUnprotectedChild} and by {@link
 * runTermination}, and the promise the runtime would have made for an `async`
 * function is not one either of them could safely await.
 *
 * Rejection behaviour is unchanged: a platform strategy that faults still
 * rejects this function's promise with the same value, for the same callers to
 * handle.
 */
function terminate(
  child: ChildProcess,
  platform: TransportPlatform,
  graceMs: number,
): Promise<TerminationScope> {
  return internalStep<TerminationScope>((settle, fail) => {
    try {
      const pid = child.pid;
      if (pid === undefined) {
        // Never started, so nothing beyond the handle can be reached. Reported
        // as degraded rather than as a successful group or tree request.
        settle(TERMINATION_SCOPE.DIRECT_CHILD_ONLY);
        return;
      }
      if (
        !whenSettled(
          platform === 'posix'
            ? terminatePosix(child, pid, graceMs)
            : terminateWindows(child, pid, graceMs),
          settle,
          fail,
        )
      ) {
        // The strategy is running and has already made its own bounded attempt;
        // what was lost is only the report of how far it reached. Nothing beyond
        // the direct child may be claimed without that report.
        settle(TERMINATION_SCOPE.DIRECT_CHILD_ONLY);
      }
    } catch (error) {
      fail(error);
    }
  });
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
 * before it can signal, a single non-ignorable direct-child signal follows, and
 * no process group, tree, or descendant is claimed on that path.
 */
function releaseUnprotectedChild(
  child: ChildProcess,
  platform: TransportPlatform,
  graceMs: number,
  done: () => void,
): void {
  // The cleanup half, reached on both outcomes of the bounded attempt.
  const cleanUp = (): void => {
    attemptCleanup(() => {
      destroyReadable(child.stdout);
    });
    attemptCleanup(() => {
      destroyReadable(child.stderr);
    });
    clearEventsKeepingAbsorber(child);
    done();
  };

  const onAttemptFailed = (): void => {
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
    //
    // The signal is named rather than left to the default because this attempt
    // gets exactly one shot. The graceful path is an *escalating* one — signal,
    // wait out the grace window, escalate — and waiting is precisely what this
    // fallback may not do. A lone `SIGTERM` is a request a POSIX child may
    // catch or ignore outright, so a child that does would predictably outlive
    // the one attempt on offer here; `SIGKILL` is the signal POSIX does not
    // allow the target to handle, block, or ignore. On Windows the choice
    // changes nothing: every signal Node accepts there terminates the target
    // unconditionally, so this is the same operation the default already was.
    // It is still only the direct child — `SIGKILL` is delivered to one
    // process, is not inherited by descendants, and claims nothing about them.
    attemptCleanup(() => {
      killDirectChild(child, 'SIGKILL');
    });
    cleanUp();
  };

  try {
    if (!whenSettled(terminate(child, platform, graceMs), cleanUp, onAttemptFailed)) {
      // No continuation was installed, so the attempt will never report. That is
      // the same position a faulted attempt leaves this in, and it takes the
      // same ending: one guarded direct-child signal, then the cleanup.
      onAttemptFailed();
    }
  } catch {
    onAttemptFailed();
  }
}

/**
 * Run one process exchange.
 *
 * **Defined operational results.** For the defined operational results this
 * transport represents as exchange outcomes — validation, spawn, I/O,
 * timeout, cancellation, overflow, termination, and close — resolves to
 * exactly one frozen {@link AgentExchange}. Nothing outside that handled set
 * is promised to resolve. Deliberate fail-closed rejection: when mandatory
 * post-spawn child-dispatch hardening cannot be established, the transport
 * runs its bounded, platform-qualified termination procedure, destroys the
 * local stdout and stderr ends, clears the child's listeners, re-arms the
 * spawn-failure absorber over the cleared handle, and then rejects. The local
 * stdin end is left as it is, and termination stays a request rather than a
 * completion guarantee. That rejection is not `SPAWN_FAILED` and is not an
 * `AgentExchange` outcome at all. Catches are placed only around defined
 * operational failures — `spawn`, `kill`, a broken stdin pipe, a hostile
 * `AbortSignal` getter — so a programmer or security-boundary defect still
 * surfaces as a defect rather than being laundered into a failure code.
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
      // Decided first, and decided *completely*, before anything else touches
      // the handle. Two separate hazards meet here and only this order answers
      // both.
      //
      // Classifying the caught value is not a neutral read: the classification
      // consults the value's own prototype chain, and a value engineered to
      // refuse that makes the classification itself throw. That is what the
      // surrounding `try` is for — the block below is total, so a
      // classification fault cannot escape, and therefore cannot cost an
      // already-created child the one bounded release attempt it is owed.
      // Total, though, only because every `Error` here is the captured
      // {@link NativeError}. A prototype-chain read is a call into the value's
      // own code, and the cheapest thing that code can do is overwrite the
      // `Error` global it knows this path is about to construct through. A
      // fresh lookup would then reach that replacement — in the ternary's
      // fallback *and* again in the `catch` that exists to cover it — and the
      // second throw would escape with the release still unreached. Reading the
      // constructor from a binding fixed before the value existed is what makes
      // the guard cover anything at all.
      // Releasing first would answer that hazard too, but at the price of the
      // second one: `releaseUnprotectedChild` consults `pid`, `exitCode`, and
      // `signalCode` synchronously before its first suspension, so a hostile
      // accessor gets to run before this line does. An ordinary Error that had
      // its prototype chain rewritten by such an accessor would then fail
      // classification and be replaced by the generic fallback, losing the very
      // identity the caller is owed. Reading the value here, where nothing
      // hostile has been invoked since it was thrown, is what makes the
      // classification a decision about the value as it was actually raised.
      //
      // The ordinary case keeps the original Error as the caller-visible
      // reason; a value that is not an Error — or that faults while being
      // classified — yields the same stable hardening failure instead, with the
      // original value retained as `cause`. Retaining it is safe because a
      // `cause` is only stored, never read. Neither branch can escape, so the
      // reason is fixed before the release begins and cannot afterwards be lost
      // to a hostile read.
      let hardeningFailure: Error;
      try {
        hardeningFailure = reflectApply(ordinaryHasInstance, NativeError, [error])
          ? (error as Error)
          : new NativeError('Process dispatch hardening failed', {
              cause: error,
            });
      } catch {
        hardeningFailure = new NativeError('Process dispatch hardening failed', {
          cause: error,
        });
      }
      // Unconditional: the block above has no escaping path, so the release is
      // reached on every route through it. Nothing above decides anything this
      // call depends on — it is ordered second only to keep hostile accessors
      // away from the caught value, not because it is contingent on the result.
      // `releaseUnprotectedChild` runs every step, never rejects, and reports
      // through the callback it is handed, so neither a termination failure nor
      // a cleanup step that throws on a poisoned `stdout`/`stderr` value can
      // leave this exchange pending. The mandatory hardening failure stays the
      // externally visible reason on every one of those paths.
      //
      // The release registers its own continuations through the captured
      // intrinsic rather than through an `await`. The value that faulted
      // hardening has already run its own code by this point, and the cheapest
      // thing that code can do is replace the scheduler this path is about to
      // reach. The `catch` covers a release that throws before it can report:
      // the rejection is still owed, and this is the last place to deliver it.
      try {
        releaseUnprotectedChild(child, platform, invocation.graceMs, () => {
          reject(hardeningFailure);
        });
      } catch {
        reject(hardeningFailure);
      }
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
        runTermination();
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
        return internallyResolved(true);
      }
      const observed = new InternalPromise<boolean>((resolveWait) => {
        const waiter = scheduleTimeout(() => {
          notifyClosed = null;
          resolveWait(false);
        }, ms);
        notifyClosed = (): void => {
          cancelTimeout(waiter);
          resolveWait(true);
        };
      });
      return protectPromiseResolution(observed);
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
    function runTermination(): void {
      if (terminating) {
        return;
      }
      terminating = true;

      /**
       * The close wait and the settlement, once termination has reported.
       *
       * Guarded as a whole. Every observation left in this lifecycle reads the
       * handle — `hasEnded`, and the two pipe releases — and each of them runs
       * from a continuation no enclosing `try` covers. A fault that escaped one
       * would leave this exchange pending with its deadline already spent,
       * which is the failure this repair exists to remove. Settlement is the
       * one obligation that is absolute, so every route through here reaches
       * {@link settle}.
       */
      const finishTermination = (): void => {
        try {
          if (settled) {
            return;
          }

          if (closed) {
            settle();
            return;
          }

          if (!hasEnded(child)) {
            terminationScope = TERMINATION_SCOPE.ESCALATION_FAILED;
          }
          // A detached descendant can retain the inherited pipe handles after
          // the direct child ends. Releasing this process's local ends before a
          // forced settlement is what keeps the caller from being held alive by
          // leaked wraps, and it is best effort on a handle that can fault.
          const releaseLocalPipes = (): void => {
            try {
              destroyReadable(child.stdout);
              destroyReadable(child.stderr);
            } catch {
              // The settlement that follows is not contingent on this.
            }
          };

          if (
            !whenSettled(
              awaitClose(invocation.graceMs),
              (closeObserved: boolean) => {
                if (!closeObserved) {
                  releaseLocalPipes();
                }
                settle();
              },
              () => {
                // The close wait could not report. Nothing further is
                // observable and the exchange is still owed its settlement.
                settle();
              },
            )
          ) {
            // No close will ever be observed, which is the same standing as a
            // close wait that expired: release the local ends before settling.
            releaseLocalPipes();
            settle();
          }
        } catch {
          // A handle read faulted after termination had already reported.
          settle();
        }
      };

      /**
       * A platform strategy that faulted before it could report.
       *
       * The `async` form left this exchange pending on a rejection nothing was
       * waiting for. The fault is reported the way an incomplete termination
       * already is — as {@link TERMINATION_SCOPE.ESCALATION_FAILED} — and the
       * same lifecycle continues. Nothing stronger is claimed: a strategy that
       * faulted proved nothing about the child, which is exactly what that
       * scope says.
       */
      const onTerminationFault = (): void => {
        terminationScope = TERMINATION_SCOPE.ESCALATION_FAILED;
        finishTermination();
      };

      const afterTermination = (scope: TerminationScope): void => {
        terminationScope = scope;
        finishTermination();
      };

      if (
        !whenSettled(
          terminate(child, platform, invocation.graceMs),
          afterTermination,
          onTerminationFault,
        )
      ) {
        // The termination is running and will never report. Treating that as a
        // reported fault would run the rest of this lifecycle on a promise that
        // can no longer install continuations either, so the remaining work is
        // done here and now: the scope is the honest one for an escalation
        // whose outcome is unknown, the local pipe ends are released so nothing
        // retains them, and the exchange settles.
        terminationScope = TERMINATION_SCOPE.ESCALATION_FAILED;
        finishTermination();
      }
    }

    const onStdout = (chunk: unknown): void => {
      if (!bufferIsBuffer(chunk)) {
        return;
      }
      if (pushChunk(stdoutSink, chunk) && claim(TRANSPORT_OUTCOME.OUTPUT_LIMIT_EXCEEDED)) {
        runTermination();
      }
    };

    const onStderr = (chunk: unknown): void => {
      if (!bufferIsBuffer(chunk)) {
        return;
      }
      if (pushChunk(stderrSink, chunk) && claim(TRANSPORT_OUTCOME.OUTPUT_LIMIT_EXCEEDED)) {
        runTermination();
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

    // Armed before the dispatch below, and that order is load-bearing.
    //
    // Registering a continuation is synchronous, and so is the fallback when
    // registration fails, so an already-aborted signal can run an entire
    // termination lifecycle — settlement and {@link cleanup} included — before
    // the dispatch returns. A deadline armed after that would be a ref'd timer
    // created past the cleanup that was supposed to release it, and nothing
    // left would cancel it: a completed exchange holding the host for as long
    // as it was allowed to run. Arming it first leaves {@link cleanup}
    // authoritative over every resource this exchange owns, whenever it runs.
    deadline = scheduleTimeout(() => {
      if (claim(TRANSPORT_OUTCOME.TIMED_OUT)) {
        runTermination();
      }
    }, invocation.timeoutMs);

    // The last statement of this executor, and the only one that can settle
    // synchronously. Nothing may follow it: everything after this point would
    // be running against an exchange that may already be over.
    abortDispatch = dispatchAbort;
    if (abortPending || (invocation.signal !== null && readAbortState(invocation.signal))) {
      dispatchAbort();
    }
  });
}

/**
 * Provider-neutral local process transport contract.
 *
 * This module describes *how to ask the operating system to run one process and
 * hand back what it wrote*. It contains no policy, no authority, no provider
 * vocabulary, and no I/O: every export here is a type, a frozen vocabulary, a
 * bound, or a pure reader. `node:child_process` lives in `process-transport.ts`
 * and nowhere else.
 *
 * What this contract deliberately does **not** contain, and must never gain:
 *
 * - A `GateDecision`, `ActionRequest`, capability, grant, or any other
 *   authorization input. PR 003's `evaluateActionRequest` remains the single
 *   authority computation, and this seam performs none of it. A later adapter
 *   must enforce an unforgeable, single-use authorization capability *before*
 *   invoking the transport.
 * - Provider identity, provider routing, prompt text, flag allowlists, or flag
 *   deny-lists. A deny-list would be both incomplete and provider-specific;
 *   argv arrives already constructed by a caller that owns that policy.
 * - Any interpretation of what the child wrote. `stdout` and `stderr` leave here
 *   as untrusted text. Decoding them into an `AgentReport`, parsing JSON,
 *   judging completion, or calling `ingestInvocationReport` belong to a later
 *   bounded PR.
 *
 * Two inputs meet here and are kept strictly apart:
 *
 * - **Trusted for shape** — the {@link AgentProcessSpec} and
 *   {@link TransportLimits} supplied by the caller. They are still validated
 *   structurally, because a "trusted" object can still be a Proxy, carry
 *   accessors, or hold values of the wrong runtime type.
 * - **Untrusted entirely** — everything the child process writes. It is
 *   captured, bounded, and echoed. It is never parsed and never reaches a
 *   decision.
 */

/**
 * Intrinsics captured at module load, before any untrusted property access is
 * possible.
 *
 * Validation reads caller-supplied objects that may be Proxies or carry
 * accessors, and such a trap can repoint prototype methods while it runs.
 * Capturing first removes that lever. Same pattern as `evidence.ts`,
 * `review.ts`, and `agent-invocation.ts`.
 */
const objectFreeze = Object.freeze;
const objectDefineProperty = Object.defineProperty;
const objectCreate = Object.create;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetOwnPropertyNames = Object.getOwnPropertyNames;
const objectGetOwnPropertySymbols = Object.getOwnPropertySymbols;
const arrayIsArray = Array.isArray;
const numberIsInteger = Number.isInteger;
const reflectApply = Reflect.apply;
// Captured unbound on purpose and invoked through `Reflect.apply`, so neither a
// poisoned prototype method nor a poisoned `Function.prototype.call` is on the
// path. `this` is supplied explicitly at every call site. `Buffer.byteLength`
// is a static that ignores `this`; it is captured for the same reason.
/* eslint-disable @typescript-eslint/unbound-method */
const bufferByteLength = Buffer.byteLength;
// Node's Buffer prototype is typed through `any`; the runtime method is captured
// with the precise call signature used below.
// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
const bufferSubarray: (this: Buffer, start: number, end?: number) => Buffer =
  // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
  Buffer.prototype.subarray;
const stringIndexOf = String.prototype.indexOf;
const stringSlice = String.prototype.slice;
const stringToLowerCase = String.prototype.toLowerCase;
const stringCharCodeAt = String.prototype.charCodeAt;
const numberToString = Number.prototype.toString;
const abortSignalAborted: ((this: AbortSignal) => boolean) | undefined =
  Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')?.get;
/* eslint-enable @typescript-eslint/unbound-method */

/** Append by defining an own element, bypassing inherited index setters. */
function append<T>(list: T[], value: T): void {
  objectDefineProperty(list, list.length, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

/**
 * Which absolute-path grammar applies.
 *
 * Passed in rather than read from `process.platform`, so this module stays pure
 * and both grammars are testable on either host.
 */
export type TransportPlatform = 'win32' | 'posix';

/**
 * Why an exchange ended.
 *
 * This records the *initiating cause*, independently of what termination then
 * achieved. A child that was killed because its output overflowed is
 * `OUTPUT_LIMIT_EXCEEDED`, not `SIGNALLED`: the signal was ours, and reporting
 * it as an external signal would erase the reason.
 *
 * `EXITED` is not a synonym for success. It means the process ran to completion
 * and `exitCode` is set; a zero exit code is recorded, never interpreted.
 */
export const TRANSPORT_OUTCOME = objectFreeze({
  /** Ran to completion. `exitCode` is set. Says nothing about correctness. */
  EXITED: 'EXITED',
  /** Died by a signal this transport did not send. */
  SIGNALLED: 'SIGNALLED',
  /** The deadline elapsed. This transport terminated it. */
  TIMED_OUT: 'TIMED_OUT',
  /** The caller's `AbortSignal` fired. This transport terminated it. */
  CANCELLED: 'CANCELLED',
  /** A stream bound was reached. This transport terminated it. */
  OUTPUT_LIMIT_EXCEEDED: 'OUTPUT_LIMIT_EXCEEDED',
  /** The operating system refused to start the process. */
  SPAWN_FAILED: 'SPAWN_FAILED',
  /** Structural validation refused the request. Nothing was spawned. */
  SPEC_REJECTED: 'SPEC_REJECTED',
} as const);

export type TransportOutcome =
  (typeof TRANSPORT_OUTCOME)[keyof typeof TRANSPORT_OUTCOME];

/** Every member of the {@link TransportOutcome} union. */
export const TRANSPORT_OUTCOMES: readonly TransportOutcome[] = objectFreeze([
  TRANSPORT_OUTCOME.EXITED,
  TRANSPORT_OUTCOME.SIGNALLED,
  TRANSPORT_OUTCOME.TIMED_OUT,
  TRANSPORT_OUTCOME.CANCELLED,
  TRANSPORT_OUTCOME.OUTPUT_LIMIT_EXCEEDED,
  TRANSPORT_OUTCOME.SPAWN_FAILED,
  TRANSPORT_OUTCOME.SPEC_REJECTED,
]);

/**
 * Terminal-cause precedence, highest first.
 *
 * When several terminal events compete, this ranking decides the reported
 * outcome, not callback arrival order. The exchange reports the highest-ranked
 * cause claimed before it settles: a later stronger cause promotes the result,
 * while a weaker cause can never demote it.
 *
 * Two mechanisms produce this ordering rather than one:
 *
 * 1. The pre-spawn checks run in this order — structural validation first, then
 *    an already-aborted signal — so a request that is both malformed and
 *    aborted is `SPEC_REJECTED`.
 * 2. After spawn, every detected cause is compared with the current cause. A
 *    child that overflows its bound and then exits zero is therefore
 *    `OUTPUT_LIMIT_EXCEEDED`, never `EXITED`; a cancellation that races a
 *    failure to start is `SPAWN_FAILED`, regardless of callback order.
 */
export const TERMINAL_CAUSE_PRECEDENCE: readonly TransportOutcome[] = objectFreeze([
  TRANSPORT_OUTCOME.SPEC_REJECTED,
  TRANSPORT_OUTCOME.SPAWN_FAILED,
  TRANSPORT_OUTCOME.OUTPUT_LIMIT_EXCEEDED,
  TRANSPORT_OUTCOME.CANCELLED,
  TRANSPORT_OUTCOME.TIMED_OUT,
  TRANSPORT_OUTCOME.SIGNALLED,
  TRANSPORT_OUTCOME.EXITED,
]);

/**
 * What termination was *asked* of the operating system.
 *
 * Every member is deliberately phrased as a request or a degradation. **None
 * asserts completion**, because completion is not provable from either
 * mechanism this transport can use: `kill(-pgid, ...)` reaches a POSIX process
 * group, and `taskkill /T /F` walks the parent-child links Windows recorded, and
 * a descendant that deliberately detached itself is in neither.
 *
 * There is deliberately no `terminationComplete`, `treeTerminated`,
 * `descendantsTerminated`, or `allDescendantsTerminated` field anywhere in this
 * contract, and a test asserts that none can appear.
 *
 * The direct child is the only process whose termination this transport
 * observes. A degraded scope means descendants were *not* reached, and
 * `PROCESS_GROUP_REQUESTED` / `PROCESS_TREE_REQUESTED` mean the request was
 * issued — never that it succeeded for every descendant.
 */
export const TERMINATION_SCOPE = objectFreeze({
  /** The child ended on its own. This transport terminated nothing. */
  NOT_REQUIRED: 'NOT_REQUIRED',
  /** POSIX: the process group was signalled. Detached descendants escape. */
  PROCESS_GROUP_REQUESTED: 'PROCESS_GROUP_REQUESTED',
  /** Windows: `taskkill /T /F` was issued. Re-parented descendants escape. */
  PROCESS_TREE_REQUESTED: 'PROCESS_TREE_REQUESTED',
  /** Degraded: only the direct child could be reached. */
  DIRECT_CHILD_ONLY: 'DIRECT_CHILD_ONLY',
  /** Degraded: escalation ran and the direct child was still not observed to end. */
  ESCALATION_FAILED: 'ESCALATION_FAILED',
} as const);

export type TerminationScope =
  (typeof TERMINATION_SCOPE)[keyof typeof TERMINATION_SCOPE];

/** Every member of the {@link TerminationScope} union. */
export const TERMINATION_SCOPES: readonly TerminationScope[] = objectFreeze([
  TERMINATION_SCOPE.NOT_REQUIRED,
  TERMINATION_SCOPE.PROCESS_GROUP_REQUESTED,
  TERMINATION_SCOPE.PROCESS_TREE_REQUESTED,
  TERMINATION_SCOPE.DIRECT_CHILD_ONLY,
  TERMINATION_SCOPE.ESCALATION_FAILED,
]);

/**
 * Scopes that mean descendants were not reached.
 *
 * Exported so a caller can branch on degradation without matching strings, and
 * so the qualified guarantee is expressible in data rather than only in prose.
 */
export const DEGRADED_TERMINATION_SCOPES: readonly TerminationScope[] = objectFreeze([
  TERMINATION_SCOPE.DIRECT_CHILD_ONLY,
  TERMINATION_SCOPE.ESCALATION_FAILED,
]);

/**
 * Why structural validation refused a request.
 *
 * Every member describes *shape*. None describes permission, provider policy,
 * or intent: this transport has no opinion about which flags are acceptable,
 * only about whether it was handed a well-formed argv at all.
 */
export const TRANSPORT_REJECTION = objectFreeze({
  SPEC_UNREADABLE: 'SPEC_UNREADABLE',
  LIMITS_UNREADABLE: 'LIMITS_UNREADABLE',

  EXECUTABLE_INVALID: 'EXECUTABLE_INVALID',
  EXECUTABLE_NOT_ABSOLUTE: 'EXECUTABLE_NOT_ABSOLUTE',
  EXECUTABLE_SUFFIX_FORBIDDEN: 'EXECUTABLE_SUFFIX_FORBIDDEN',

  WORKING_DIRECTORY_INVALID: 'WORKING_DIRECTORY_INVALID',
  WORKING_DIRECTORY_NOT_ABSOLUTE: 'WORKING_DIRECTORY_NOT_ABSOLUTE',

  ARGV_NOT_ARRAY: 'ARGV_NOT_ARRAY',
  ARGV_UNREADABLE: 'ARGV_UNREADABLE',
  ARGV_COUNT_EXCEEDED: 'ARGV_COUNT_EXCEEDED',
  ARGUMENT_UNREADABLE: 'ARGUMENT_UNREADABLE',
  ARGUMENT_NOT_STRING: 'ARGUMENT_NOT_STRING',
  ARGUMENT_CONTAINS_NUL: 'ARGUMENT_CONTAINS_NUL',
  ARGUMENT_LONE_SURROGATE: 'ARGUMENT_LONE_SURROGATE',
  ARGUMENT_BYTES_EXCEEDED: 'ARGUMENT_BYTES_EXCEEDED',
  ARGV_TOTAL_BYTES_EXCEEDED: 'ARGV_TOTAL_BYTES_EXCEEDED',

  ENVIRONMENT_NOT_RECORD: 'ENVIRONMENT_NOT_RECORD',
  ENVIRONMENT_UNREADABLE: 'ENVIRONMENT_UNREADABLE',
  ENVIRONMENT_COUNT_EXCEEDED: 'ENVIRONMENT_COUNT_EXCEEDED',
  ENVIRONMENT_ENTRY_INVALID: 'ENVIRONMENT_ENTRY_INVALID',
  ENVIRONMENT_NAME_DUPLICATED: 'ENVIRONMENT_NAME_DUPLICATED',
  ENVIRONMENT_REQUIRED_VARIABLE_MISSING: 'ENVIRONMENT_REQUIRED_VARIABLE_MISSING',
  ENVIRONMENT_BYTES_EXCEEDED: 'ENVIRONMENT_BYTES_EXCEEDED',

  STDIN_NOT_STRING: 'STDIN_NOT_STRING',
  STDIN_LONE_SURROGATE: 'STDIN_LONE_SURROGATE',
  STDIN_BYTES_EXCEEDED: 'STDIN_BYTES_EXCEEDED',

  TIMEOUT_OUT_OF_RANGE: 'TIMEOUT_OUT_OF_RANGE',
  GRACE_OUT_OF_RANGE: 'GRACE_OUT_OF_RANGE',
  STDOUT_LIMIT_OUT_OF_RANGE: 'STDOUT_LIMIT_OUT_OF_RANGE',
  STDERR_LIMIT_OUT_OF_RANGE: 'STDERR_LIMIT_OUT_OF_RANGE',
  ABORT_SIGNAL_INVALID: 'ABORT_SIGNAL_INVALID',
} as const);

export type TransportRejection =
  (typeof TRANSPORT_REJECTION)[keyof typeof TRANSPORT_REJECTION];

/**
 * V1 bounds.
 *
 * Every unbounded dimension is capped **before** anything is spawned, following
 * the rule established in PR 005 and PR 006.
 *
 * `MAX_ARGV_TOTAL_BYTES` bounds caller input before
 * `MAX_ARGV_COUNT * MAX_ARG_BYTES` could bind. Windows also composes the
 * executable and argv into one quoted command line. A separate private check
 * measures that serialized form, including separators and its terminating NUL,
 * against the operating-system limit.
 *
 * `MAX_ENV_KEY_BYTES` equals PR 005's and PR 006's `MAX_IDENTIFIER_LENGTH`; a
 * test pins the three together.
 */
export const TRANSPORT_BOUNDS = objectFreeze({
  /** Arguments permitted in one argv vector. */
  MAX_ARGV_COUNT: 64,
  /** UTF-8 bytes permitted in one argument. */
  MAX_ARG_BYTES: 4_096,
  /** UTF-8 bytes permitted across the whole argv vector. */
  MAX_ARGV_TOTAL_BYTES: 30_000,
  /** UTF-8 bytes permitted in `executablePath` and `workingDirectory`. */
  MAX_PATH_BYTES: 4_096,
  /** UTF-8 bytes permitted in the stdin payload. */
  MAX_STDIN_BYTES: 1_048_576,
  /** Ceiling the caller's `maxStdoutBytes` is measured against. */
  MAX_STDOUT_BYTES_CEILING: 8_388_608,
  /** Ceiling the caller's `maxStderrBytes` is measured against. */
  MAX_STDERR_BYTES_CEILING: 1_048_576,
  /** Entries permitted in the child environment. */
  MAX_ENV_ENTRIES: 64,
  /** UTF-8 bytes permitted in one environment key. */
  MAX_ENV_KEY_BYTES: 256,
  /** UTF-8 bytes permitted in one environment value. */
  MAX_ENV_VALUE_BYTES: 32_768,
  MIN_TIMEOUT_MS: 1,
  MAX_TIMEOUT_MS: 3_600_000,
  MIN_GRACE_MS: 0,
  MAX_GRACE_MS: 60_000,
} as const);

/**
 * Executable suffixes that cannot be spawned without a shell.
 *
 * `.cmd` and `.bat` are interpreted by `cmd.exe` and `.ps1` by PowerShell, so
 * running one requires `shell: true` or an explicit interpreter — and
 * `shell: true` reintroduces exactly the argument-injection class this
 * transport exists to avoid. They are rejected on every platform, not only on
 * Windows, so the rule cannot be sidestepped by where the code happens to run.
 */
const FORBIDDEN_EXECUTABLE_SUFFIXES: readonly string[] = objectFreeze([
  '.cmd',
  '.bat',
  '.ps1',
]);

/** Variables libuv otherwise copies from the parent on Windows. */
const WINDOWS_REQUIRED_ENVIRONMENT_NAMES: readonly string[] = objectFreeze([
  'HOMEDRIVE',
  'HOMEPATH',
  'LOGONSERVER',
  'PATH',
  'SYSTEMDRIVE',
  'SYSTEMROOT',
  'TEMP',
  'USERDOMAIN',
  'USERNAME',
  'USERPROFILE',
  'WINDIR',
]);

/**
 * One process to run. Every field is required; nothing has a default.
 *
 * `workingDirectory` is whatever absolute path the caller assigns, and this
 * transport does not care whether it is a managed-repository worktree. What an
 * external agent does inside its own assigned worktree, under its own
 * credentials, is that agent's authority — documented in
 * `docs/architecture/006-agent-invocation-boundary.md`. This transport itself
 * writes no file and runs no Git command.
 *
 * Deliberately absent, and never to be added: credentials, tokens, secrets,
 * prompt templates, provider identity, repository identity, callbacks, streams,
 * file handles, API clients, or any authorization object.
 */
export interface AgentProcessSpec {
  /** Absolute path to a directly spawnable executable. Never PATH-searched. */
  readonly executablePath: string;
  /** Fully constructed argv. Never composed, never interpolated. */
  readonly args: readonly string[];
  /** Absolute path the child runs in. */
  readonly workingDirectory: string;
  /**
   * The child's environment. This transport never merges it with its own
   * `process.env`, and never reads `process.env` to populate it.
   *
   * On Windows the caller must explicitly provide every name libuv would
   * otherwise copy from the parent environment. Missing names and
   * case-insensitive duplicates are rejected before spawn; empty values are
   * permitted. The transport never obtains or fills those values itself.
   */
  readonly environment: Readonly<Record<string, string>>;
  /** Payload written to the child's stdin, after which stdin is closed. */
  readonly stdin: string;
}

/** Bounds and cancellation for one exchange. Only `signal` is optional. */
export interface TransportLimits {
  /** Deadline in milliseconds. Required; there is no default to forget. */
  readonly timeoutMs: number;
  /** Milliseconds between the polite and the forceful termination step. */
  readonly graceMs: number;
  readonly maxStdoutBytes: number;
  readonly maxStderrBytes: number;
  /** External cancellation. The one optional field. */
  readonly signal?: AbortSignal;
}

/**
 * The result of one exchange. Frozen, JSON-serializable, lossless on round trip.
 *
 * `stdout` and `stderr` are **untrusted text**. Nothing in this transport reads
 * them, and nothing downstream may treat them as an `AgentReport` until a later
 * bounded PR normalizes them through PR 006's `ingestInvocationReport`.
 *
 * There is deliberately no `success`, `status`, `ok`, `complete`, `report`,
 * `claims`, `authorized`, `decision`, `freshness`, `duration`, or timestamp
 * field, and no field asserting that termination finished.
 */
export interface AgentExchange {
  /** The initiating cause, independent of what termination achieved. */
  readonly outcome: TransportOutcome;
  /** Non-null only when `outcome` is `SPEC_REJECTED`. */
  readonly rejection: TransportRejection | null;
  /** Exit status when the process ran to completion. */
  readonly exitCode: number | null;
  /** Signal name when the process died by signal. */
  readonly terminatingSignal: string | null;
  /** Untrusted child stdout, bounded and decoded at a complete UTF-8 boundary. */
  readonly stdout: string;
  /** Untrusted child stderr. Never merged with stdout. */
  readonly stderr: string;
  readonly stdoutTruncated: boolean;
  readonly stderrTruncated: boolean;
  /** Source bytes retained behind `stdout`, after bounding and boundary trim. */
  readonly stdoutBytes: number;
  /** Source bytes retained behind `stderr`, after bounding and boundary trim. */
  readonly stderrBytes: number;
  /** What termination was asked of the OS. Never a claim that it finished. */
  readonly terminationScope: TerminationScope;
}

/** A specification whose every field has been read exactly once and validated. */
export interface ValidatedInvocation {
  readonly executablePath: string;
  readonly args: readonly string[];
  readonly workingDirectory: string;
  readonly environment: Readonly<Record<string, string>>;
  readonly stdin: string;
  readonly timeoutMs: number;
  readonly graceMs: number;
  readonly maxStdoutBytes: number;
  readonly maxStderrBytes: number;
  readonly signal: AbortSignal | null;
}

/** Either a refusal or a fully snapshotted invocation. Never both. */
export type InvocationReadResult =
  | { readonly rejection: TransportRejection; readonly value: null }
  | { readonly rejection: null; readonly value: ValidatedInvocation };

/**
 * Read one **own data** property of an untrusted object.
 *
 * Accessors are not invoked: a getter is a caller-controlled function, and
 * running one during validation would let a specification validate as one value
 * and spawn as another. An accessor, an inherited value, or a throwing trap all
 * read as `undefined`, which then fails the field's own type check.
 */
function readOwnData(target: object, key: string): unknown {
  try {
    const descriptor = objectGetOwnPropertyDescriptor(target, key);
    if (descriptor === undefined) {
      return undefined;
    }
    if (!('value' in descriptor)) {
      return undefined;
    }
    return descriptor.value;
  } catch {
    return undefined;
  }
}

/** True when the value is a non-array object that can be probed at all. */
function isReadableObject(value: unknown): value is object {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  try {
    return !arrayIsArray(value);
  } catch {
    return false;
  }
}

/** UTF-8 byte length, computed without invoking any caller-supplied method. */
export function utf8ByteLength(value: string): number {
  const length: unknown = reflectApply(bufferByteLength, Buffer, [value, 'utf8']);
  return typeof length === 'number' && numberIsInteger(length) ? length : 0;
}

/** True when the string contains a NUL, which no OS accepts in argv or a path. */
export function containsNul(value: string): boolean {
  const index: unknown = reflectApply(stringIndexOf, value, ['\u0000']);
  return typeof index !== 'number' || index !== -1;
}

/**
 * True when the string holds an unpaired UTF-16 surrogate.
 *
 * A JavaScript string is a sequence of UTF-16 code units and may contain a
 * surrogate with no partner, which UTF-8 cannot represent. Both boundaries this
 * transport promises to carry verbatim — the argument vector and the stdin
 * payload — are encoded as UTF-8 on the way to the child, and that encoding
 * silently substitutes U+FFFD for such a code unit. The child would then receive
 * a value different from the one that was validated, which is exactly what the
 * single-read snapshot exists to prevent. Refusing before spawn is the only
 * answer that keeps the promise honest.
 *
 * This asks one question and nothing more. Ordinary characters, valid surrogate
 * pairs — every supplementary-plane character is one — mixed strings, and the
 * empty string are all well-formed and pass through untouched. Nothing here
 * normalizes, substitutes, reorders, or reinterprets any text.
 */
export function containsLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = reflectApply(stringCharCodeAt, value, [index]);
    if (unit < 0xd800 || unit > 0xdfff) {
      continue;
    }
    if (unit > 0xdbff) {
      // A low surrogate seen on its own. One that completes a pair is consumed
      // by the branch below and is never inspected here.
      return true;
    }
    // A high surrogate must be *immediately* followed by a low one. Reading past
    // the end yields NaN, so this is written as a negated in-range test: every
    // comparison against NaN is false, and the loose form would accept a
    // trailing high surrogate.
    const low = reflectApply(stringCharCodeAt, value, [index + 1]);
    if (!(low >= 0xdc00 && low <= 0xdfff)) {
      return true;
    }
    index += 1;
  }
  return false;
}

/** CreateProcess command-line capacity in UTF-16 code units, including NUL. */
const WINDOWS_COMMAND_LINE_LIMIT = 32_767;

/**
 * Length of one argument after libuv's non-verbatim Windows quoting.
 *
 * Arguments without a space, tab, or quote are emitted unchanged. Every other
 * argument is quoted. Within quotes, backslashes are doubled only when they
 * precede a quote or the closing quote; a literal quote gains one additional
 * escaping backslash.
 */
function quotedWindowsArgumentLength(value: string): number {
  let needsQuotes = value.length === 0;
  for (let index = 0; index < value.length && !needsQuotes; index += 1) {
    const character = reflectApply(stringCharCodeAt, value, [index]);
    needsQuotes = character === 0x09 || character === 0x20 || character === 0x22;
  }
  if (!needsQuotes) {
    return value.length;
  }

  let emitted = 2;
  let backslashes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const character = reflectApply(stringCharCodeAt, value, [index]);
    if (character === 0x5c) {
      backslashes += 1;
      continue;
    }
    if (character === 0x22) {
      emitted += backslashes * 2 + 2;
      backslashes = 0;
      continue;
    }
    emitted += backslashes + 1;
    backslashes = 0;
  }
  return emitted + backslashes * 2;
}

/** Serialized Windows command-line length, including separators and final NUL. */
function windowsCommandLineLength(
  executablePath: string,
  args: readonly string[],
): number {
  let total = quotedWindowsArgumentLength(executablePath) + 1;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === undefined) {
      return WINDOWS_COMMAND_LINE_LIMIT + 1;
    }
    total += 1 + quotedWindowsArgumentLength(argument);
  }
  return total;
}

/**
 * True when the path is absolute under the given grammar.
 *
 * Implemented by character inspection rather than `node:path`, so this module
 * stays free of Node imports and both grammars are checkable on either host. A
 * bare command name and every relative path fail here, which is what keeps PATH
 * out of the picture entirely.
 */
export function isAbsolutePath(value: string, platform: TransportPlatform): boolean {
  if (value.length === 0) {
    return false;
  }
  if (platform === 'posix') {
    return reflectApply(stringCharCodeAt, value, [0]) === 0x2f;
  }
  const first = reflectApply(stringCharCodeAt, value, [0]);
  const isUnc =
    (first === 0x5c || first === 0x2f) &&
    (reflectApply(stringCharCodeAt, value, [1]) === 0x5c ||
      reflectApply(stringCharCodeAt, value, [1]) === 0x2f);
  if (isUnc) {
    return true;
  }
  const isLetter =
    (first >= 0x41 && first <= 0x5a) || (first >= 0x61 && first <= 0x7a);
  const separator = reflectApply(stringCharCodeAt, value, [2]);
  return (
    isLetter &&
    reflectApply(stringCharCodeAt, value, [1]) === 0x3a &&
    (separator === 0x5c || separator === 0x2f)
  );
}

/** True when the path ends in a suffix that cannot be spawned without a shell. */
function hasForbiddenSuffix(value: string): boolean {
  if (value.length < 4) {
    return false;
  }
  const tail: unknown = reflectApply(stringSlice, value, [value.length - 4]);
  if (typeof tail !== 'string') {
    return true;
  }
  const lowered: unknown = reflectApply(stringToLowerCase, tail, []);
  if (typeof lowered !== 'string') {
    return true;
  }
  for (let index = 0; index < FORBIDDEN_EXECUTABLE_SUFFIXES.length; index += 1) {
    if (FORBIDDEN_EXECUTABLE_SUFFIXES[index] === lowered) {
      return true;
    }
  }
  return false;
}

/** A refusal, shaped for {@link InvocationReadResult}. */
function refuse(rejection: TransportRejection): InvocationReadResult {
  return { rejection, value: null };
}

/** Narrow an untrusted value to an in-range integer, or `null`. */
function readBoundedInteger(value: unknown, min: number, max: number): number | null {
  if (typeof value !== 'number') {
    return null;
  }
  if (!numberIsInteger(value)) {
    return null;
  }
  return value >= min && value <= max ? value : null;
}

/** Validate an untrusted path field once, in a fixed order of failure reasons. */
function checkPath(
  value: unknown,
  platform: TransportPlatform,
  invalid: TransportRejection,
  notAbsolute: TransportRejection,
): TransportRejection | null {
  if (typeof value !== 'string' || value.length === 0) {
    return invalid;
  }
  if (containsNul(value)) {
    return invalid;
  }
  if (utf8ByteLength(value) > TRANSPORT_BOUNDS.MAX_PATH_BYTES) {
    return invalid;
  }
  if (!isAbsolutePath(value, platform)) {
    return notAbsolute;
  }
  return null;
}

/**
 * Snapshot and validate argv.
 *
 * Elements are read through own **data** descriptors, so a hostile array cannot
 * supply a value via a getter, via an inherited numeric property, or via a hole.
 * The vector is rebuilt into a fresh array with indexed appends, so neither a
 * poisoned iterator nor an inherited index setter is on the path between
 * validation and spawn.
 */
function readArgs(raw: unknown): {
  readonly rejection: TransportRejection | null;
  readonly value: readonly string[];
} {
  let isArray = false;
  try {
    isArray = arrayIsArray(raw);
  } catch {
    return { rejection: TRANSPORT_REJECTION.ARGV_UNREADABLE, value: [] };
  }
  if (!isArray) {
    return { rejection: TRANSPORT_REJECTION.ARGV_NOT_ARRAY, value: [] };
  }

  let rawLength: unknown;
  try {
    rawLength = (raw as { readonly length: unknown }).length;
  } catch {
    return { rejection: TRANSPORT_REJECTION.ARGV_UNREADABLE, value: [] };
  }
  if (typeof rawLength !== 'number' || !numberIsInteger(rawLength) || rawLength < 0) {
    return { rejection: TRANSPORT_REJECTION.ARGV_UNREADABLE, value: [] };
  }
  if (rawLength > TRANSPORT_BOUNDS.MAX_ARGV_COUNT) {
    return { rejection: TRANSPORT_REJECTION.ARGV_COUNT_EXCEEDED, value: [] };
  }

  const args: string[] = [];
  let totalBytes = 0;
  for (let index = 0; index < rawLength; index += 1) {
    let descriptor;
    try {
      const indexName = reflectApply(numberToString, index, []);
      descriptor = objectGetOwnPropertyDescriptor(raw as object, indexName);
    } catch {
      return { rejection: TRANSPORT_REJECTION.ARGUMENT_UNREADABLE, value: [] };
    }
    if (descriptor === undefined || !('value' in descriptor)) {
      return { rejection: TRANSPORT_REJECTION.ARGUMENT_UNREADABLE, value: [] };
    }
    const element: unknown = descriptor.value;
    if (typeof element !== 'string') {
      return { rejection: TRANSPORT_REJECTION.ARGUMENT_NOT_STRING, value: [] };
    }
    if (containsNul(element)) {
      return { rejection: TRANSPORT_REJECTION.ARGUMENT_CONTAINS_NUL, value: [] };
    }
    // Checked before the byte measurement, because the measurement of an
    // ill-formed argument is already the length of the substitution the child
    // would have received rather than of the argument the caller supplied.
    if (containsLoneSurrogate(element)) {
      return { rejection: TRANSPORT_REJECTION.ARGUMENT_LONE_SURROGATE, value: [] };
    }
    const bytes = utf8ByteLength(element);
    if (bytes > TRANSPORT_BOUNDS.MAX_ARG_BYTES) {
      return { rejection: TRANSPORT_REJECTION.ARGUMENT_BYTES_EXCEEDED, value: [] };
    }
    totalBytes += bytes;
    if (totalBytes > TRANSPORT_BOUNDS.MAX_ARGV_TOTAL_BYTES) {
      return { rejection: TRANSPORT_REJECTION.ARGV_TOTAL_BYTES_EXCEEDED, value: [] };
    }
    append(args, element);
  }

  return { rejection: null, value: objectFreeze(args) };
}

/**
 * Snapshot and validate the child environment.
 *
 * The result is a fresh null-prototype object built with `defineProperty`, so
 * nothing inherited and no accessor survives into what is handed to `spawn`.
 * Own symbol keys are a refusal rather than a silent omission: a caller that
 * attached one meant something by it, and quietly dropping it would hide the
 * mismatch between what was asked for and what the child receives.
 */
function readEnvironment(raw: unknown, platform: TransportPlatform): {
  readonly rejection: TransportRejection | null;
  readonly value: Readonly<Record<string, string>>;
} {
  const empty: Readonly<Record<string, string>> = objectFreeze(
    objectCreate(null) as Record<string, string>,
  );
  if (!isReadableObject(raw)) {
    return { rejection: TRANSPORT_REJECTION.ENVIRONMENT_NOT_RECORD, value: empty };
  }

  let symbols: readonly symbol[];
  let names: readonly string[];
  try {
    symbols = objectGetOwnPropertySymbols(raw);
    names = objectGetOwnPropertyNames(raw);
  } catch {
    return { rejection: TRANSPORT_REJECTION.ENVIRONMENT_UNREADABLE, value: empty };
  }
  if (symbols.length > 0) {
    return { rejection: TRANSPORT_REJECTION.ENVIRONMENT_ENTRY_INVALID, value: empty };
  }
  if (names.length > TRANSPORT_BOUNDS.MAX_ENV_ENTRIES) {
    return { rejection: TRANSPORT_REJECTION.ENVIRONMENT_COUNT_EXCEEDED, value: empty };
  }

  const environment = objectCreate(null) as Record<string, string>;
  const normalizedNames = objectCreate(null) as Record<string, true>;
  for (let index = 0; index < names.length; index += 1) {
    const key = names[index];
    if (typeof key !== 'string' || key.length === 0) {
      return { rejection: TRANSPORT_REJECTION.ENVIRONMENT_ENTRY_INVALID, value: empty };
    }
    if (containsNul(key) || reflectApply(stringIndexOf, key, ['=']) !== -1) {
      return { rejection: TRANSPORT_REJECTION.ENVIRONMENT_ENTRY_INVALID, value: empty };
    }
    // The environment crosses the same UTF-8 boundary as argv and stdin, so an
    // ill-formed name would reach the child as a *different* name. Checked with
    // the other content rules and before the byte measurement, for the reason
    // given in `readArgs`.
    if (containsLoneSurrogate(key)) {
      return { rejection: TRANSPORT_REJECTION.ENVIRONMENT_ENTRY_INVALID, value: empty };
    }
    if (utf8ByteLength(key) > TRANSPORT_BOUNDS.MAX_ENV_KEY_BYTES) {
      return { rejection: TRANSPORT_REJECTION.ENVIRONMENT_BYTES_EXCEEDED, value: empty };
    }

    if (platform === 'win32') {
      const normalized = reflectApply(stringToLowerCase, key, []);
      if (typeof normalized !== 'string') {
        return { rejection: TRANSPORT_REJECTION.ENVIRONMENT_ENTRY_INVALID, value: empty };
      }
      if (objectGetOwnPropertyDescriptor(normalizedNames, normalized) !== undefined) {
        return { rejection: TRANSPORT_REJECTION.ENVIRONMENT_NAME_DUPLICATED, value: empty };
      }
      objectDefineProperty(normalizedNames, normalized, {
        value: true,
        writable: false,
        enumerable: true,
        configurable: false,
      });
    }

    let descriptor;
    try {
      descriptor = objectGetOwnPropertyDescriptor(raw, key);
    } catch {
      return { rejection: TRANSPORT_REJECTION.ENVIRONMENT_UNREADABLE, value: empty };
    }
    if (descriptor === undefined || !('value' in descriptor)) {
      return { rejection: TRANSPORT_REJECTION.ENVIRONMENT_ENTRY_INVALID, value: empty };
    }
    const value: unknown = descriptor.value;
    if (typeof value !== 'string') {
      return { rejection: TRANSPORT_REJECTION.ENVIRONMENT_ENTRY_INVALID, value: empty };
    }
    if (containsNul(value)) {
      return { rejection: TRANSPORT_REJECTION.ENVIRONMENT_ENTRY_INVALID, value: empty };
    }
    // Same rule as the name above: what the child reads back must be what the
    // caller supplied, and an unpaired surrogate cannot survive the encoding.
    if (containsLoneSurrogate(value)) {
      return { rejection: TRANSPORT_REJECTION.ENVIRONMENT_ENTRY_INVALID, value: empty };
    }
    if (utf8ByteLength(value) > TRANSPORT_BOUNDS.MAX_ENV_VALUE_BYTES) {
      return { rejection: TRANSPORT_REJECTION.ENVIRONMENT_BYTES_EXCEEDED, value: empty };
    }

    objectDefineProperty(environment, key, {
      value,
      writable: false,
      enumerable: true,
      configurable: false,
    });
  }

  if (platform === 'win32') {
    for (let index = 0; index < WINDOWS_REQUIRED_ENVIRONMENT_NAMES.length; index += 1) {
      const required = WINDOWS_REQUIRED_ENVIRONMENT_NAMES[index];
      if (required === undefined) {
        return {
          rejection: TRANSPORT_REJECTION.ENVIRONMENT_REQUIRED_VARIABLE_MISSING,
          value: empty,
        };
      }
      const normalized = reflectApply(stringToLowerCase, required, []);
      if (
        typeof normalized !== 'string' ||
        objectGetOwnPropertyDescriptor(normalizedNames, normalized) === undefined
      ) {
        return {
          rejection: TRANSPORT_REJECTION.ENVIRONMENT_REQUIRED_VARIABLE_MISSING,
          value: empty,
        };
      }
    }
  }

  // Node copies a parent NODE_V8_COVERAGE value into an options.env object
  // that lacks this exact own key. A non-enumerable own value blocks that
  // runtime mutation without adding anything to the child's environment.
  if (objectGetOwnPropertyDescriptor(environment, 'NODE_V8_COVERAGE') === undefined) {
    objectDefineProperty(environment, 'NODE_V8_COVERAGE', {
      value: '',
      writable: false,
      enumerable: false,
      configurable: false,
    });
  }

  return { rejection: null, value: objectFreeze(environment) };
}

/**
 * Narrow an untrusted value to something usable as an `AbortSignal`.
 *
 * The captured platform getter performs the brand check without consulting
 * caller-controlled properties or methods. Cross-realm signals with compatible
 * platform internal slots remain accepted.
 */
function readSignal(raw: unknown): {
  readonly rejection: TransportRejection | null;
  readonly value: AbortSignal | null;
} {
  if (raw === undefined || raw === null) {
    return { rejection: null, value: null };
  }
  if (typeof raw !== 'object') {
    return { rejection: TRANSPORT_REJECTION.ABORT_SIGNAL_INVALID, value: null };
  }
  if (abortSignalAborted === undefined) {
    return { rejection: TRANSPORT_REJECTION.ABORT_SIGNAL_INVALID, value: null };
  }
  try {
    const aborted: unknown = reflectApply(abortSignalAborted, raw, []);
    if (typeof aborted !== 'boolean') {
      return { rejection: TRANSPORT_REJECTION.ABORT_SIGNAL_INVALID, value: null };
    }
  } catch {
    return { rejection: TRANSPORT_REJECTION.ABORT_SIGNAL_INVALID, value: null };
  }
  return { rejection: null, value: raw as AbortSignal };
}

/**
 * Validate a specification and its limits, reading every field exactly once.
 *
 * Pure, total, and deterministic: it never throws, never spawns, never touches
 * the filesystem, and returns the same refusal for the same malformed input.
 *
 * **Single-read discipline.** Every field is read once into a local and the
 * snapshot is what later reaches `spawn`. A getter that returns one value when
 * validated and another when used cannot exist here, because accessors are
 * never invoked and the original object is never consulted again.
 *
 * Fields are checked in a fixed order, so a request with several problems
 * always reports the same one.
 */
export function readInvocation(
  spec: AgentProcessSpec,
  limits: TransportLimits,
  platform: TransportPlatform,
): InvocationReadResult {
  const rawSpec: unknown = spec;
  if (!isReadableObject(rawSpec)) {
    return refuse(TRANSPORT_REJECTION.SPEC_UNREADABLE);
  }
  const rawLimits: unknown = limits;
  if (!isReadableObject(rawLimits)) {
    return refuse(TRANSPORT_REJECTION.LIMITS_UNREADABLE);
  }

  const rawExecutable: unknown = readOwnData(rawSpec, 'executablePath');
  const executableFailure = checkPath(
    rawExecutable,
    platform,
    TRANSPORT_REJECTION.EXECUTABLE_INVALID,
    TRANSPORT_REJECTION.EXECUTABLE_NOT_ABSOLUTE,
  );
  if (executableFailure !== null) {
    return refuse(executableFailure);
  }
  const executablePath = rawExecutable as string;
  if (hasForbiddenSuffix(executablePath)) {
    return refuse(TRANSPORT_REJECTION.EXECUTABLE_SUFFIX_FORBIDDEN);
  }

  const rawWorkingDirectory: unknown = readOwnData(rawSpec, 'workingDirectory');
  const workingDirectoryFailure = checkPath(
    rawWorkingDirectory,
    platform,
    TRANSPORT_REJECTION.WORKING_DIRECTORY_INVALID,
    TRANSPORT_REJECTION.WORKING_DIRECTORY_NOT_ABSOLUTE,
  );
  if (workingDirectoryFailure !== null) {
    return refuse(workingDirectoryFailure);
  }

  const argsResult = readArgs(readOwnData(rawSpec, 'args'));
  if (argsResult.rejection !== null) {
    return refuse(argsResult.rejection);
  }
  if (
    platform === 'win32' &&
    windowsCommandLineLength(executablePath, argsResult.value) >
      WINDOWS_COMMAND_LINE_LIMIT
  ) {
    return refuse(TRANSPORT_REJECTION.ARGV_TOTAL_BYTES_EXCEEDED);
  }

  const environmentResult = readEnvironment(
    readOwnData(rawSpec, 'environment'),
    platform,
  );
  if (environmentResult.rejection !== null) {
    return refuse(environmentResult.rejection);
  }

  const rawStdin: unknown = readOwnData(rawSpec, 'stdin');
  if (typeof rawStdin !== 'string') {
    return refuse(TRANSPORT_REJECTION.STDIN_NOT_STRING);
  }
  // Same reason as argv: the payload is written to the pipe as UTF-8, so an
  // ill-formed code unit would reach the child as a substitution instead.
  if (containsLoneSurrogate(rawStdin)) {
    return refuse(TRANSPORT_REJECTION.STDIN_LONE_SURROGATE);
  }
  if (utf8ByteLength(rawStdin) > TRANSPORT_BOUNDS.MAX_STDIN_BYTES) {
    return refuse(TRANSPORT_REJECTION.STDIN_BYTES_EXCEEDED);
  }

  const timeoutMs = readBoundedInteger(
    readOwnData(rawLimits, 'timeoutMs'),
    TRANSPORT_BOUNDS.MIN_TIMEOUT_MS,
    TRANSPORT_BOUNDS.MAX_TIMEOUT_MS,
  );
  if (timeoutMs === null) {
    return refuse(TRANSPORT_REJECTION.TIMEOUT_OUT_OF_RANGE);
  }
  const graceMs = readBoundedInteger(
    readOwnData(rawLimits, 'graceMs'),
    TRANSPORT_BOUNDS.MIN_GRACE_MS,
    TRANSPORT_BOUNDS.MAX_GRACE_MS,
  );
  if (graceMs === null) {
    return refuse(TRANSPORT_REJECTION.GRACE_OUT_OF_RANGE);
  }
  const maxStdoutBytes = readBoundedInteger(
    readOwnData(rawLimits, 'maxStdoutBytes'),
    0,
    TRANSPORT_BOUNDS.MAX_STDOUT_BYTES_CEILING,
  );
  if (maxStdoutBytes === null) {
    return refuse(TRANSPORT_REJECTION.STDOUT_LIMIT_OUT_OF_RANGE);
  }
  const maxStderrBytes = readBoundedInteger(
    readOwnData(rawLimits, 'maxStderrBytes'),
    0,
    TRANSPORT_BOUNDS.MAX_STDERR_BYTES_CEILING,
  );
  if (maxStderrBytes === null) {
    return refuse(TRANSPORT_REJECTION.STDERR_LIMIT_OUT_OF_RANGE);
  }

  const signalResult = readSignal(readOwnData(rawLimits, 'signal'));
  if (signalResult.rejection !== null) {
    return refuse(signalResult.rejection);
  }

  return {
    rejection: null,
    value: objectFreeze({
      executablePath,
      args: argsResult.value,
      workingDirectory: rawWorkingDirectory as string,
      environment: environmentResult.value,
      stdin: rawStdin,
      timeoutMs,
      graceMs,
      maxStdoutBytes,
      maxStderrBytes,
      signal: signalResult.value,
    }),
  };
}

/**
 * Drop a trailing incomplete UTF-8 sequence.
 *
 * Bounding happens in bytes, so a cap can land in the middle of a multi-byte
 * character. Decoding that directly would emit U+FFFD for a character the child
 * actually wrote in full — the transcript would misrepresent its own source. The
 * partial tail is dropped instead, and the caller already knows the value was
 * cut because truncation is flagged separately.
 *
 * Only a *trailing partial* sequence is removed. Genuinely invalid UTF-8
 * elsewhere in the buffer is left alone and decodes to U+FFFD, because it is not
 * an artefact of bounding and hiding it would be a different kind of lie.
 */
export function trimPartialUtf8(buffer: Buffer): Buffer {
  const length = buffer.length;
  if (length === 0) {
    return buffer;
  }
  const last = buffer[length - 1];
  if (last === undefined || last < 0x80) {
    return buffer;
  }

  let start = length - 1;
  let steps = 0;
  while (start >= 0 && steps < 3) {
    const byte = buffer[start];
    if (byte === undefined) {
      return buffer;
    }
    if ((byte & 0xc0) !== 0x80) {
      break;
    }
    start -= 1;
    steps += 1;
  }
  if (start < 0) {
    return buffer;
  }

  const lead = buffer[start];
  if (lead === undefined) {
    return buffer;
  }
  let expected = 0;
  if ((lead & 0x80) === 0x00) {
    expected = 1;
  } else if (lead >= 0xc2 && lead <= 0xdf) {
    expected = 2;
  } else if (lead >= 0xe0 && lead <= 0xef) {
    expected = 3;
  } else if (lead >= 0xf0 && lead <= 0xf4) {
    expected = 4;
  } else {
    return buffer;
  }

  const second = buffer[start + 1];
  if (
    second !== undefined &&
    ((lead === 0xe0 && second < 0xa0) ||
      (lead === 0xed && second > 0x9f) ||
      (lead === 0xf0 && second < 0x90) ||
      (lead === 0xf4 && second > 0x8f))
  ) {
    return buffer;
  }

  const available = length - start;
  return available >= expected
    ? buffer
    : reflectApply(bufferSubarray, buffer, [0, start]);
}

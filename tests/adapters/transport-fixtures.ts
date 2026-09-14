/**
 * Shared inputs and independently declared expectations for the process
 * transport.
 *
 * Expected vocabulary values are written as bare string literals, **not** as
 * `TRANSPORT_OUTCOME.*` and friends, so the suite cannot ratify a production
 * mapping that has been changed incorrectly. Only types are imported from
 * `src/`, following `tests/domain/expected-policy.ts` and
 * `tests/domain/invocation-fixtures.ts`.
 *
 * Stub agents are `process.execPath` running an inline `-e` script. That keeps
 * every stub cross-platform, adds no fixture executable, needs no new
 * dependency, and — crucially — never needs a shell.
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { AgentProcessSpec, TransportLimits } from '../../src/adapters/agent-transport.js';

/** The stub interpreter. Absolute, directly spawnable, no forbidden suffix. */
export const NODE_EXECUTABLE = process.execPath;

/**
 * The smallest environment in which `node` reliably starts on each platform.
 *
 * Tests may read `process.env`; the transport may not, and a separate invariant
 * asserts that it does not. Windows needs `SystemRoot` for a spawned process to
 * initialise its networking and crypto stack.
 */
export function baseEnvironment(): Record<string, string> {
  const environment: Record<string, string> = {};
  if (process.platform === 'win32') {
    for (const name of WINDOWS_REQUIRED_ENVIRONMENT_VARIABLES) {
      environment[name] = '';
    }
    const systemRoot = process.env['SystemRoot'];
    if (systemRoot !== undefined) {
      environment['SYSTEMROOT'] = systemRoot;
    }
  }
  return environment;
}

/**
 * Variables callers must provide so libuv cannot copy parent values on Windows.
 *
 * `uv_spawn` copies this fixed list from the parent when a name is missing.
 * The fixtures supply every name explicitly so tests exercise the transport's
 * fail-closed mitigation without exposing real parent values.
 */
export const WINDOWS_REQUIRED_ENVIRONMENT_VARIABLES: readonly string[] = Object.freeze([
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

/** Options accepted by {@link makeSpec}, each defaulting to a valid value. */
export interface SpecOverrides {
  readonly executablePath?: string;
  readonly args?: readonly string[];
  readonly workingDirectory?: string;
  readonly environment?: Readonly<Record<string, string>>;
  readonly stdin?: string;
}

/** Build a well-formed specification. */
export function makeSpec(overrides: SpecOverrides = {}): AgentProcessSpec {
  return {
    executablePath: overrides.executablePath ?? NODE_EXECUTABLE,
    args: overrides.args ?? ['-e', STUB.WRITE_OK],
    workingDirectory: overrides.workingDirectory ?? tmpdir(),
    environment: overrides.environment ?? baseEnvironment(),
    stdin: overrides.stdin ?? '',
  };
}

/** Options accepted by {@link makeLimits}, each defaulting to a valid value. */
export interface LimitOverrides {
  readonly timeoutMs?: number;
  readonly graceMs?: number;
  readonly maxStdoutBytes?: number;
  readonly maxStderrBytes?: number;
}

/** Build well-formed limits. `signal` is added separately by {@link withSignal}. */
export function makeLimits(overrides: LimitOverrides = {}): TransportLimits {
  return {
    timeoutMs: overrides.timeoutMs ?? 15_000,
    graceMs: overrides.graceMs ?? 1_000,
    maxStdoutBytes: overrides.maxStdoutBytes ?? 65_536,
    maxStderrBytes: overrides.maxStderrBytes ?? 16_384,
  };
}

/**
 * Attach a cancellation signal.
 *
 * A separate helper because `exactOptionalPropertyTypes` forbids assigning an
 * explicit `undefined` to an optional property.
 */
export function withSignal(limits: TransportLimits, signal: AbortSignal): TransportLimits {
  return { ...limits, signal };
}

/** A grandchild that appends to a heartbeat file forever. */
const HEARTBEAT_GRANDCHILD =
  'const fs=require("node:fs");' +
  'const p=process.argv[1];' +
  'fs.writeFileSync(p+".pid",String(process.pid));' +
  'setInterval(()=>{fs.appendFileSync(p,"x");},20);';

/**
 * A stub that spawns one heartbeat grandchild and then refuses to die.
 *
 * With `detached` false the grandchild is an ordinary descendant: it shares the
 * POSIX process group and appears in the Windows process tree, so termination
 * must reach it. With `detached` true it deliberately leaves that grouping,
 * which is the escape case the transport explicitly does not claim to cover.
 */
export function heartbeatStub(detached: boolean): string {
  const spawnOptions = detached
    ? '{stdio:"ignore",detached:true}'
    : '{stdio:"ignore",detached:false}';
  return (
    'const cp=require("node:child_process");' +
    'const p=process.argv[1];' +
    `const g=cp.spawn(process.execPath,["-e",${JSON.stringify(HEARTBEAT_GRANDCHILD)},p],${spawnOptions});` +
    (detached ? 'g.unref();' : '') +
    'process.on("SIGTERM",()=>{});' +
    'process.stdout.write("spawned");' +
    'setInterval(()=>{},1000);'
  );
}

/** Inline stub programs, each run as `node -e <script> [args...]`. */
export const STUB = {
  /** Writes a fixed marker and exits zero. */
  WRITE_OK: 'process.stdout.write("ok");',
  /** Echoes stdin back on stdout. */
  ECHO_STDIN:
    'let d="";process.stdin.setEncoding("utf8");' +
    'process.stdin.on("data",(c)=>{d+=c;});' +
    'process.stdin.on("end",()=>{process.stdout.write(d);});',
  /** Reports whether stdin reached end-of-file. */
  STDIN_EOF:
    'process.stdin.resume();process.stdin.on("end",()=>{process.stdout.write("eof");});',
  /** Serializes the arguments it received after the script. */
  PRINT_ARGV: 'process.stdout.write(JSON.stringify(process.argv.slice(1)));',
  /** Serializes its entire environment. */
  PRINT_ENV: 'process.stdout.write(JSON.stringify(process.env));',
  /** Writes its working directory. */
  PRINT_CWD: 'process.stdout.write(process.cwd());',
  /** Exits with the code given as the first argument. */
  EXIT_WITH: 'process.exit(Number(process.argv[1]));',
  /** Writes N bytes of ASCII to stdout, where N is the first argument. */
  WRITE_BYTES: 'process.stdout.write("x".repeat(Number(process.argv[1])));',
  /** Writes N bytes to stdout and then exits zero straight away. */
  WRITE_BYTES_THEN_EXIT:
    'process.stdout.write("x".repeat(Number(process.argv[1])));process.exit(0);',
  /** Writes distinct markers to both streams, interleaved. */
  BOTH_STREAMS:
    'process.stdout.write("OUT-A");process.stderr.write("ERR-A");' +
    'process.stdout.write("OUT-B");process.stderr.write("ERR-B");',
  /** Writes only to stderr, then exits non-zero. */
  STDERR_ONLY: 'process.stderr.write("diagnostic");process.exit(3);',
  /** Never exits. */
  SLEEP: 'setInterval(()=>{},1000);',
  /** Ignores SIGTERM and never exits. */
  IGNORE_SIGTERM: 'process.on("SIGTERM",()=>{});setInterval(()=>{},1000);',
  /** Floods stdout without stopping. */
  FLOOD_STDOUT:
    'const b="x".repeat(65536);setInterval(()=>{process.stdout.write(b);},1);',
  /** Floods stderr without stopping. */
  FLOOD_STDERR:
    'const b="x".repeat(65536);setInterval(()=>{process.stderr.write(b);},1);',
  /** Writes one long line with no newline at all. */
  LONG_LINE: 'process.stdout.write("y".repeat(Number(process.argv[1])));',
  /** Writes a repeated 4-byte astral character. */
  MULTIBYTE: 'process.stdout.write("\\u{1F600}".repeat(Number(process.argv[1])));',
  /** Writes bytes that are not valid UTF-8. */
  INVALID_UTF8: 'process.stdout.write(Buffer.from([0xff,0xfe,0x41,0xff]));',
  /** Writes comma-separated numeric byte values supplied as the first argument. */
  WRITE_RAW_BYTES:
    'process.stdout.write(Buffer.from(process.argv[1].split(",").map(Number)));',
  /** Exits zero without reading stdin, breaking the pipe. */
  EXIT_IMMEDIATELY: 'process.exit(0);',
  /** Kills itself with SIGKILL. POSIX only. */
  SELF_KILL: 'process.kill(process.pid,"SIGKILL");setInterval(()=>{},1000);',
  /** Closes stdout early but keeps running. */
  CLOSE_STDOUT_KEEP_RUNNING:
    'process.stdout.end();process.on("SIGTERM",()=>{});setInterval(()=>{},1000);',
  /**
   * Spawns a descendant that inherits stdout and stderr, then exits at once.
   *
   * The direct child is gone immediately, but the inherited pipes stay open, so
   * `close` never arrives on its own. An exchange must still settle.
   */
  LEAK_STDIO_THEN_EXIT:
    'const cp=require("node:child_process");' +
    'cp.spawn(process.execPath,["-e","setTimeout(()=>{process.exit(0);},4000);"],' +
    '{stdio:["ignore","inherit","inherit"]});' +
    'process.exit(0);',
} as const;

/** Create a throwaway directory the tests own. */
export function makeTempDirectory(): string {
  return mkdtempSync(join(tmpdir(), 'agentbridge-pr010-'));
}

/** Remove a throwaway directory, ignoring an already-removed one. */
export function removeTempDirectory(path: string): void {
  rmSync(path, { recursive: true, force: true });
}

/** A string of exactly `length` ASCII characters. */
export function ascii(length: number): string {
  return 'x'.repeat(length);
}

/** Sleep, for sampling a heartbeat file across an interval. */
export function delay(ms: number): Promise<void> {
  return new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 * Values that are not usable strings. Mirrors
 * `tests/domain/invocation-fixtures.ts` so both boundaries face one corpus.
 */
export const MALFORMED_VALUES: readonly (readonly [string, unknown])[] = Object.freeze([
  ['undefined', undefined],
  ['null', null],
  ['a number', 42],
  ['a zero', 0],
  ['a boolean', true],
  ['an object', {}],
  ['an array', []],
  ['a function', (): string => 'x'],
  ['a symbol', Symbol('s')],
  ['a bigint', 7n],
]);

/** Top-level values that are not objects at all. */
export const NON_OBJECTS: readonly (readonly [string, unknown])[] = Object.freeze([
  ['null', null],
  ['undefined', undefined],
  ['a string', 'spec'],
  ['a number', 42],
  ['a boolean', true],
  ['a function', (): string => 'x'],
  ['a symbol', Symbol('s')],
  ['a bigint', 3n],
]);

/**
 * Executable paths that must never be spawned: relative, bare, shell-only
 * suffixes, and traversal forms. Declared as literals, not derived from the
 * production suffix list.
 */
export const FORBIDDEN_EXECUTABLES: readonly (readonly [string, string])[] = Object.freeze([
  ['a bare command name', 'node'],
  ['a bare command with extension', 'node.exe'],
  ['a relative path', './node'],
  ['a parent-relative path', '../bin/node'],
  ['a traversal path', 'bin/../node'],
  ['an empty string', ''],
]);

/** Suffixes that cannot be spawned without a shell. */
export const SHELL_ONLY_EXECUTABLES: readonly (readonly [string, string])[] = Object.freeze([
  ['a .cmd shim', 'C:\\tools\\claude.cmd'],
  ['an uppercase .CMD shim', 'C:\\tools\\claude.CMD'],
  ['a .bat script', 'C:\\tools\\claude.bat'],
  ['a .ps1 script', 'C:\\tools\\claude.ps1'],
  ['a POSIX-style .cmd', '/usr/local/bin/claude.cmd'],
]);

/**
 * Argument payloads that a shell would interpret. Every one must reach the
 * child as a single verbatim argv element.
 */
export const SHELL_METACHARACTER_ARGUMENTS: readonly string[] = Object.freeze([
  '; rm -rf /',
  '&& whoami',
  '|| id',
  '$(id)',
  '`id`',
  '| cat /etc/passwd',
  '> /tmp/pwned',
  '< /etc/shadow',
  '%PATH%',
  '$HOME',
  '&echo hi',
  '"; echo hi; "',
  "'; echo hi; '",
  '\n echo newline',
  '\r\n echo crlf',
  '../../etc/passwd',
  '--dangerously-skip-permissions',
  '*',
  '~',
]);

/**
 * Strings holding an unpaired UTF-16 surrogate.
 *
 * None can be encoded as UTF-8, so every one would reach the child as U+FFFD
 * instead of as itself. Written with explicit `\uXXXX` escapes so the corpus
 * survives any re-encoding of this file.
 */
export const LONE_SURROGATE_STRINGS: readonly (readonly [string, string])[] = Object.freeze([
  ['a bare high surrogate', '\uD800'],
  ['a bare low surrogate', '\uDC00'],
  ['the last high surrogate alone', '\uDBFF'],
  ['the last low surrogate alone', '\uDFFF'],
  ['a high surrogate before ordinary text', '\uD83Dx'],
  ['a high surrogate at the very end', 'x\uD83D'],
  ['a low surrogate before ordinary text', '\uDE00x'],
  ['a reversed pair', '\uDE00\uD83D'],
  ['two high surrogates in a row', '\uD83D\uD83D'],
  ['a lone surrogate between two valid pairs', '\u{1F600}\uD800\u{1F600}'],
]);

/**
 * Well-formed strings that must keep validating, supplementary plane included.
 *
 * The point of the astral entries is that rejecting ill-formed UTF-16 must not
 * become a rejection of ordinary Unicode: every one of these *is* a surrogate
 * pair at the code-unit level.
 */
export const WELL_FORMED_STRINGS: readonly (readonly [string, string])[] = Object.freeze([
  ['an empty string', ''],
  ['plain ASCII', 'ordinary'],
  ['BMP text outside ASCII', 'é中文'],
  ['a supplementary-plane character', '\u{1F600}'],
  ['the first supplementary code point', '\u{10000}'],
  ['the last supplementary code point', '\u{10FFFF}'],
  ['a valid pair mixed with BMP text', 'a\u{1F600}b中'],
  ['adjacent valid pairs', '\u{1F600}\u{1F600}'],
]);

/**
 * Field names that must never appear on an exchange.
 *
 * The termination group is the point of this correction: no field may assert
 * that a process tree was actually destroyed, because that is not provable.
 */
export const FORBIDDEN_FIELD_NAMES: readonly string[] = Object.freeze([
  'success',
  'ok',
  'complete',
  'completed',
  'status',
  'report',
  'claims',
  'authorized',
  'approved',
  'mayExecute',
  'mayExecuteAutonomously',
  'requiresHumanApproval',
  'decision',
  'classification',
  'freshness',
  'current',
  'stale',
  'evidence',
  'providerId',
  'repositoryId',
  'invocationId',
  'nextAction',
  'shouldRetry',
  'attempt',
  'retries',
  'duration',
  'durationMs',
  'startedAt',
  'finishedAt',
  'timestamp',
  'terminationComplete',
  'treeTerminated',
  'descendantsTerminated',
  'allDescendantsTerminated',
  'processTreeKilled',
]);

/** Authority values that must never reach a serialized exchange. */
export const FORBIDDEN_VALUES: readonly string[] = Object.freeze([
  'ALLOW',
  'DENY',
  'ESCALATE',
  'AUTONOMOUS',
  'HUMAN_REVIEW_REQUIRED',
  'CURRENT',
  'STALE',
  'INGESTED',
  'reported-complete',
]);

/** Every member of the outcome vocabulary, as bare literals. */
export const ALL_OUTCOMES: readonly string[] = Object.freeze([
  'EXITED',
  'SIGNALLED',
  'TIMED_OUT',
  'CANCELLED',
  'OUTPUT_LIMIT_EXCEEDED',
  'SPAWN_FAILED',
  'SPEC_REJECTED',
]);

/** Every member of the termination-scope vocabulary, as bare literals. */
export const ALL_TERMINATION_SCOPES: readonly string[] = Object.freeze([
  'NOT_REQUIRED',
  'PROCESS_GROUP_REQUESTED',
  'PROCESS_TREE_REQUESTED',
  'DIRECT_CHILD_ONLY',
  'ESCALATION_FAILED',
]);

/** Scopes that mean descendants were not reached, as bare literals. */
export const DEGRADED_SCOPES: readonly string[] = Object.freeze([
  'DIRECT_CHILD_ONLY',
  'ESCALATION_FAILED',
]);

/**
 * Terminal-cause precedence, highest first, declared independently of the
 * production constant.
 */
export const EXPECTED_PRECEDENCE: readonly string[] = Object.freeze([
  'SPEC_REJECTED',
  'SPAWN_FAILED',
  'OUTPUT_LIMIT_EXCEEDED',
  'CANCELLED',
  'TIMED_OUT',
  'SIGNALLED',
  'EXITED',
]);

/** Independently declared bounds. */
export const EXPECTED_BOUNDS = Object.freeze({
  MAX_ARGV_COUNT: 64,
  MAX_ARG_BYTES: 4_096,
  MAX_ARGV_TOTAL_BYTES: 30_000,
  MAX_PATH_BYTES: 4_096,
  MAX_STDIN_BYTES: 1_048_576,
  MAX_STDOUT_BYTES_CEILING: 8_388_608,
  MAX_STDERR_BYTES_CEILING: 1_048_576,
  MAX_ENV_ENTRIES: 64,
  MAX_ENV_KEY_BYTES: 256,
  MAX_ENV_VALUE_BYTES: 32_768,
  MIN_TIMEOUT_MS: 1,
  MAX_TIMEOUT_MS: 3_600_000,
  MIN_GRACE_MS: 0,
  MAX_GRACE_MS: 60_000,
});

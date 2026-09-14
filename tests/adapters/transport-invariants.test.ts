/**
 * Security and structural invariants for the process transport.
 *
 * These assertions are the executable form of the guarantees in
 * `docs/architecture/010-commander-claude-bridge.md`. Several inspect the
 * module source text directly, because "there is no shell on any path" and
 * "this layer performs no policy" are properties of the code as written, not of
 * any single call.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  type AgentProcessSpec,
  containsLoneSurrogate,
  DEGRADED_TERMINATION_SCOPES,
  isAbsolutePath,
  readInvocation,
  TERMINAL_CAUSE_PRECEDENCE,
  TERMINATION_SCOPE,
  TERMINATION_SCOPES,
  TRANSPORT_BOUNDS,
  TRANSPORT_OUTCOME,
  TRANSPORT_OUTCOMES,
  TRANSPORT_REJECTION,
  type TransportLimits,
  trimPartialUtf8,
} from '../../src/adapters/agent-transport.js';
import { invokeAgentProcess } from '../../src/adapters/process-transport.js';
import { INVOCATION_BOUNDS, REVIEW_BOUNDS } from '../../src/domain/index.js';
import {
  ALL_OUTCOMES,
  ALL_TERMINATION_SCOPES,
  ascii,
  baseEnvironment,
  DEGRADED_SCOPES,
  EXPECTED_BOUNDS,
  EXPECTED_PRECEDENCE,
  FORBIDDEN_FIELD_NAMES,
  FORBIDDEN_VALUES,
  LONE_SURROGATE_STRINGS,
  makeLimits,
  makeSpec,
  MALFORMED_VALUES,
  NON_OBJECTS,
  SHELL_ONLY_EXECUTABLES,
  STUB,
  WELL_FORMED_STRINGS,
  WINDOWS_REQUIRED_ENVIRONMENT_VARIABLES,
} from './transport-fixtures.js';

const ADAPTER_DIRECTORY = fileURLToPath(new URL('../../src/adapters/', import.meta.url));

function sourceOf(file: string): string {
  return readFileSync(`${ADAPTER_DIRECTORY}${file}`, 'utf8');
}

const CONTRACT_SOURCE = sourceOf('agent-transport.ts');
const IMPLEMENTATION_SOURCE = sourceOf('process-transport.ts');
const ADAPTER_SOURCES = [CONTRACT_SOURCE, IMPLEMENTATION_SOURCE];

/** Strip block and line comments so prose cannot satisfy a source assertion. */
function code(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
}

const ADAPTER_CODE = ADAPTER_SOURCES.map(code);

const PLATFORM = process.platform === 'win32' ? 'win32' : 'posix';

/** An empty array is a *valid* argv, so it is not a malformed-argv case. */
const NON_ARGV_VALUES = MALFORMED_VALUES.filter(([, value]) => !Array.isArray(value));

/** An empty object is a *valid* environment, so it is not a malformed-env case. */
const NON_ENVIRONMENT_VALUES = MALFORMED_VALUES.filter(
  ([, value]) => !(typeof value === 'object' && value !== null && !Array.isArray(value)),
);

/** A specification with one field replaced by an arbitrary runtime value. */
function withRawSpecField(field: string, value: unknown): AgentProcessSpec {
  return { ...makeSpec(), [field]: value } as unknown as AgentProcessSpec;
}

/** Limits with one field replaced by an arbitrary runtime value. */
function withRawLimitField(field: string, value: unknown): TransportLimits {
  return { ...makeLimits(), [field]: value } as unknown as TransportLimits;
}

/**
 * Both arguments are required on purpose: a default would swallow an explicit
 * `undefined` and silently validate a well-formed request instead of the
 * malformed one under test.
 */
function rejectionFor(spec: AgentProcessSpec, limits: TransportLimits): string {
  const result = readInvocation(spec, limits, PLATFORM);
  return result.rejection ?? 'ACCEPTED';
}

/** Validate a specification against known-good limits. */
function rejectionForSpec(spec: AgentProcessSpec): string {
  return rejectionFor(spec, makeLimits());
}

describe('no shell on any path', () => {
  it.each([
    'shell: true',
    'shell:true',
    "require('child_process').exec",
    'execSync',
    'cmd.exe',
    '/c ',
    'powershell',
    '-Command',
  ])('never contains %j', (needle) => {
    for (const source of ADAPTER_CODE) {
      expect(source).not.toContain(needle);
    }
  });

  it('passes shell: false at every spawn site', () => {
    const executable = code(IMPLEMENTATION_SOURCE);
    const spawnCalls = executable.match(/spawn\(/g) ?? [];
    const shellFalse = executable.match(/shell: false/g) ?? [];

    expect(spawnCalls.length).toBe(2);
    expect(shellFalse.length).toBe(spawnCalls.length);
  });

  it('imports only child_process from Node, and no filesystem or network API', () => {
    for (const source of ADAPTER_CODE) {
      expect(source).not.toContain("from 'node:fs'");
      expect(source).not.toContain("from 'node:http'");
      expect(source).not.toContain("from 'node:https'");
      expect(source).not.toContain("from 'node:net'");
      expect(source).not.toContain("from 'node:path'");
      expect(source).not.toContain('require(');
    }
    expect(IMPLEMENTATION_SOURCE).toContain("from 'node:child_process'");
    expect(CONTRACT_SOURCE).not.toContain("from 'node:");
  });
});

describe('no policy, no provider, no decoding', () => {
  it('imports nothing from the domain kernel', () => {
    for (const source of ADAPTER_CODE) {
      expect(source).not.toContain('../domain/');
      expect(source).not.toContain('src/domain');
    }
  });

  it.each([
    'evaluateActionRequest',
    'GateDecision',
    'ActionRequest',
    'SpawnGrant',
    'WeakMap',
    'mayExecuteAutonomously',
    'ingestInvocationReport',
    'AgentReport',
    'JSON.parse',
    'Commander',
    'claude',
    'Claude',
    'anthropic',
    'openai',
  ])('never references %j', (needle) => {
    for (const source of ADAPTER_CODE) {
      expect(source).not.toContain(needle);
    }
  });

  it('performs no logging, no clock read, and no identifier generation', () => {
    for (const source of ADAPTER_CODE) {
      expect(source).not.toContain('console.');
      expect(source).not.toContain('Date.now');
      expect(source).not.toContain('new Date');
      expect(source).not.toContain('Math.random');
      expect(source).not.toContain('randomUUID');
    }
  });

  it('reads process.env only for the internal Windows termination path', () => {
    expect(code(CONTRACT_SOURCE)).not.toContain('process.env');
    const reads = code(IMPLEMENTATION_SOURCE).match(/runtimeProcess\.env/g) ?? [];

    expect(reads.length).toBe(2);
    expect(IMPLEMENTATION_SOURCE).toContain(
      "runtimeProcess.env['SystemRoot'] ?? runtimeProcess.env['windir']",
    );
  });
});

describe('termination vocabulary claims no more than the OS provides', () => {
  it('matches the independently declared scope list', () => {
    expect([...TERMINATION_SCOPES]).toEqual([...ALL_TERMINATION_SCOPES]);
  });

  it('marks exactly the degraded scopes as degraded', () => {
    expect([...DEGRADED_TERMINATION_SCOPES]).toEqual([...DEGRADED_SCOPES]);
  });

  it('has no member that asserts termination finished', () => {
    for (const scope of TERMINATION_SCOPES) {
      expect(scope).not.toContain('COMPLETE');
      expect(scope).not.toContain('TERMINATED');
      expect(scope).not.toContain('KILLED');
      expect(scope).not.toContain('SUCCESS');
    }
  });

  it('names the two attempt scopes as requests rather than results', () => {
    expect(TERMINATION_SCOPE.PROCESS_GROUP_REQUESTED).toContain('REQUESTED');
    expect(TERMINATION_SCOPE.PROCESS_TREE_REQUESTED).toContain('REQUESTED');
  });

  it('exposes no field claiming a process tree was destroyed', async () => {
    const exchange = await invokeAgentProcess(
      makeSpec({ args: ['-e', STUB.WRITE_OK] }),
      makeLimits(),
    );

    for (const forbidden of FORBIDDEN_FIELD_NAMES) {
      expect(Object.hasOwn(exchange, forbidden)).toBe(false);
    }
  });

  it('spawns taskkill directly with a fixed argument vector', () => {
    expect(IMPLEMENTATION_SOURCE).toContain("['/PID', decimalPid, '/T', '/F']");
    // No composed command line: the flags never appear inside one string.
    expect(code(IMPLEMENTATION_SOURCE)).not.toContain('taskkill /T');
    // The system directory is resolved, never assumed.
    expect(IMPLEMENTATION_SOURCE).not.toContain("'C:\\\\Windows'");
  });

  it('invalidates a POSIX group target before either possible signal', () => {
    const start = IMPLEMENTATION_SOURCE.indexOf('function terminatePosix');
    const end = IMPLEMENTATION_SOURCE.indexOf('function terminateWindows');
    const implementation = IMPLEMENTATION_SOURCE.slice(start, end);
    const firstGuard = implementation.indexOf('if (hasEnded(child))');
    const termSignal = implementation.indexOf("signalProcessGroup(pid, 'SIGTERM')");
    const graceWait = implementation.indexOf('if (await waitForExit(child, graceMs))');
    const secondGuard = implementation.indexOf('if (hasEnded(child))', firstGuard + 1);
    const killSignal = implementation.indexOf("signalProcessGroup(pid, 'SIGKILL')");

    expect(firstGuard).toBeGreaterThanOrEqual(0);
    expect(termSignal).toBeGreaterThanOrEqual(0);
    expect(graceWait).toBeGreaterThanOrEqual(0);
    expect(secondGuard).toBeGreaterThanOrEqual(0);
    expect(killSignal).toBeGreaterThanOrEqual(0);
    expect(firstGuard).toBeLessThan(termSignal);
    expect(secondGuard).toBeGreaterThan(graceWait);
    expect(secondGuard).toBeLessThan(killSignal);
  });

  it('invalidates a Windows PID before resolving or spawning taskkill', () => {
    const start = IMPLEMENTATION_SOURCE.indexOf('function terminateWindows');
    const end = IMPLEMENTATION_SOURCE.indexOf('/** Dispatch termination', start);
    const implementation = IMPLEMENTATION_SOURCE.slice(start, end);
    const guard = implementation.indexOf('if (hasEnded(child))');
    const resolve = implementation.indexOf('resolveTaskkill()');
    const signal = implementation.indexOf('runTaskkill(taskkill, pid)');

    expect(guard).toBeGreaterThanOrEqual(0);
    expect(resolve).toBeGreaterThanOrEqual(0);
    expect(signal).toBeGreaterThanOrEqual(0);
    expect(guard).toBeLessThan(resolve);
    expect(guard).toBeLessThan(signal);
  });
});

describe('outcome vocabulary and precedence', () => {
  it('matches the independently declared outcome list', () => {
    expect([...TRANSPORT_OUTCOMES]).toEqual([...ALL_OUTCOMES]);
  });

  it('declares the frozen terminal-cause precedence', () => {
    expect([...TERMINAL_CAUSE_PRECEDENCE]).toEqual([...EXPECTED_PRECEDENCE]);
  });

  it('covers every outcome exactly once in the precedence order', () => {
    expect(new Set(TERMINAL_CAUSE_PRECEDENCE)).toEqual(new Set(TRANSPORT_OUTCOMES));
    expect(TERMINAL_CAUSE_PRECEDENCE.length).toBe(TRANSPORT_OUTCOMES.length);
  });

  it('ranks an overflow above both signal and exit', () => {
    const rank = (outcome: string): number => EXPECTED_PRECEDENCE.indexOf(outcome);

    expect(rank('OUTPUT_LIMIT_EXCEEDED')).toBeLessThan(rank('SIGNALLED'));
    expect(rank('OUTPUT_LIMIT_EXCEEDED')).toBeLessThan(rank('EXITED'));
    expect(rank('CANCELLED')).toBeLessThan(rank('TIMED_OUT'));
    expect(rank('SPEC_REJECTED')).toBe(0);
  });

  it('prefers SPEC_REJECTED over an already-aborted signal', async () => {
    const exchange = await invokeAgentProcess(
      makeSpec({ executablePath: 'relative/node' }),
      { ...makeLimits(), signal: AbortSignal.abort() },
    );

    expect(exchange.outcome).toBe('SPEC_REJECTED');
  });
});

describe('no authority value can reach a serialized exchange', () => {
  it('carries none of the forbidden values', async () => {
    const exchange = await invokeAgentProcess(
      makeSpec({ args: ['-e', STUB.WRITE_OK] }),
      makeLimits(),
    );
    const serialized = JSON.stringify(exchange);

    for (const forbidden of FORBIDDEN_VALUES) {
      expect(serialized).not.toContain(forbidden);
    }
  });

  it('exposes only the declared fields', async () => {
    const exchange = await invokeAgentProcess(
      makeSpec({ args: ['-e', STUB.WRITE_OK] }),
      makeLimits(),
    );

    expect(Object.keys(exchange).sort()).toEqual(
      [
        'exitCode',
        'outcome',
        'rejection',
        'stderr',
        'stderrBytes',
        'stderrTruncated',
        'stdout',
        'stdoutBytes',
        'stdoutTruncated',
        'terminatingSignal',
        'terminationScope',
      ].sort(),
    );
  });
});

describe('structural validation is bounded, non-coercing and fail-closed', () => {
  it.each(NON_OBJECTS)('refuses a specification that is %s', (_label, value) => {
    expect(rejectionForSpec(value as AgentProcessSpec)).toBe('SPEC_UNREADABLE');
  });

  it.each(NON_OBJECTS)('refuses limits that are %s', (_label, value) => {
    expect(rejectionFor(makeSpec(), value as TransportLimits)).toBe('LIMITS_UNREADABLE');
  });

  it.each(MALFORMED_VALUES)('refuses an executable that is %s', (_label, value) => {
    expect(rejectionForSpec(withRawSpecField('executablePath', value))).toBe(
      'EXECUTABLE_INVALID',
    );
  });

  it.each(SHELL_ONLY_EXECUTABLES)('refuses %s', (_label, executablePath) => {
    const rejection = rejectionForSpec(withRawSpecField('executablePath', executablePath));

    expect(['EXECUTABLE_SUFFIX_FORBIDDEN', 'EXECUTABLE_NOT_ABSOLUTE']).toContain(rejection);
  });

  it('refuses an executable that is absolute but shell-only', () => {
    const path = PLATFORM === 'win32' ? 'C:\\tools\\agent.cmd' : '/usr/bin/agent.cmd';

    expect(rejectionForSpec(withRawSpecField('executablePath', path))).toBe(
      'EXECUTABLE_SUFFIX_FORBIDDEN',
    );
  });

  it('refuses a path containing a NUL', () => {
    const path = PLATFORM === 'win32' ? 'C:\\a\u0000b\\node.exe' : '/a\u0000b/node';

    expect(rejectionForSpec(withRawSpecField('executablePath', path))).toBe('EXECUTABLE_INVALID');
  });

  it('refuses an oversized path rather than truncating it', () => {
    const prefix = PLATFORM === 'win32' ? 'C:\\' : '/';
    const path = `${prefix}${ascii(TRANSPORT_BOUNDS.MAX_PATH_BYTES + 1)}`;

    expect(rejectionForSpec(withRawSpecField('executablePath', path))).toBe('EXECUTABLE_INVALID');
  });

  it.each(NON_ARGV_VALUES)('refuses argv that is %s', (_label, value) => {
    const rejection = rejectionForSpec(withRawSpecField('args', value));

    expect(['ARGV_NOT_ARRAY', 'ARGV_UNREADABLE']).toContain(rejection);
  });

  it('refuses an argument that is not a string', () => {
    expect(rejectionForSpec(withRawSpecField('args', ['-e', 42]))).toBe('ARGUMENT_NOT_STRING');
  });

  it('refuses an argument containing a NUL', () => {
    expect(rejectionForSpec(withRawSpecField('args', ['-e', 'a\u0000b']))).toBe(
      'ARGUMENT_CONTAINS_NUL',
    );
  });

  it('refuses an argv element supplied through a getter without invoking it', () => {
    let invoked = false;
    const hostile: unknown[] = [];
    Object.defineProperty(hostile, '0', {
      get() {
        invoked = true;
        return '--harmless';
      },
      enumerable: true,
      configurable: true,
    });
    Object.defineProperty(hostile, 'length', { value: 1, writable: true });

    expect(rejectionForSpec(withRawSpecField('args', hostile))).toBe('ARGUMENT_UNREADABLE');
    expect(invoked).toBe(false);
  });

  it('refuses an argv hole rather than reading an inherited value', () => {
    const withHole: unknown[] = [];
    withHole.length = 2;
    const prototype = Array.prototype as unknown as Record<string, unknown>;
    prototype['0'] = 'inherited-and-hostile';
    try {
      expect(rejectionForSpec(withRawSpecField('args', withHole))).toBe('ARGUMENT_UNREADABLE');
    } finally {
      delete prototype['0'];
    }
  });

  it('preserves validated argv despite an inherited numeric setter', () => {
    const descriptor = Object.getOwnPropertyDescriptor(Array.prototype, '0');
    const args = ['-e', 'kept'];
    Object.defineProperty(Array.prototype, '0', {
      set() {
        // Deliberately swallow indexed assignment.
      },
      configurable: true,
    });
    let rejection: string | null = null;
    let first: string | undefined;
    let second: string | undefined;
    let ownsFirst = false;
    try {
      const result = readInvocation(makeSpec({ args }), makeLimits(), PLATFORM);
      rejection = result.rejection;
      first = result.value?.args[0];
      second = result.value?.args[1];
      ownsFirst = Object.hasOwn(result.value?.args ?? [], 0);
    } finally {
      if (descriptor === undefined) {
        Reflect.deleteProperty(Array.prototype, '0');
      } else {
        Object.defineProperty(Array.prototype, '0', descriptor);
      }
    }
    expect(rejection).toBeNull();
    expect(first).toBe('-e');
    expect(second).toBe('kept');
    expect(ownsFirst).toBe(true);
  });

  it('uses captured string intrinsics after a validation Proxy poisons the prototype', () => {
    const original = Object.getOwnPropertyDescriptor(String.prototype, 'charCodeAt');
    const target = makeSpec();
    const hostile = new Proxy(target, {
      getOwnPropertyDescriptor(object, key) {
        String.prototype.charCodeAt = (): never => {
          throw new Error('poisoned charCodeAt');
        };
        return Reflect.getOwnPropertyDescriptor(object, key);
      },
    });
    try {
      const result = readInvocation(hostile, makeLimits(), PLATFORM);
      expect(result.rejection).toBeNull();
    } finally {
      if (original !== undefined) {
        Object.defineProperty(String.prototype, 'charCodeAt', original);
      }
    }
  });

  it('refuses an argv Proxy whose traps throw', () => {
    const hostile = new Proxy([] as unknown[], {
      get(): never {
        throw new Error('trap');
      },
    });

    expect(rejectionForSpec(withRawSpecField('args', hostile))).toBe('ARGV_UNREADABLE');
  });

  it('refuses a revoked argv Proxy', () => {
    const revocable = Proxy.revocable([] as unknown[], {});
    revocable.revoke();

    expect(rejectionForSpec(withRawSpecField('args', revocable.proxy))).toBe('ARGV_UNREADABLE');
  });

  it('refuses more arguments than the count bound', () => {
    const many = Array.from({ length: TRANSPORT_BOUNDS.MAX_ARGV_COUNT + 1 }, () => 'a');

    expect(rejectionForSpec(withRawSpecField('args', many))).toBe('ARGV_COUNT_EXCEEDED');
  });

  it('refuses a single argument past the per-argument bound', () => {
    const big = [ascii(TRANSPORT_BOUNDS.MAX_ARG_BYTES + 1)];

    expect(rejectionForSpec(withRawSpecField('args', big))).toBe('ARGUMENT_BYTES_EXCEEDED');
  });

  it('applies the total argv bound before the count bound could ever bind', () => {
    const maximal = Array.from({ length: TRANSPORT_BOUNDS.MAX_ARGV_COUNT }, () =>
      ascii(TRANSPORT_BOUNDS.MAX_ARG_BYTES),
    );

    expect(rejectionForSpec(withRawSpecField('args', maximal))).toBe(
      'ARGV_TOTAL_BYTES_EXCEEDED',
    );
    expect(
      TRANSPORT_BOUNDS.MAX_ARGV_COUNT * TRANSPORT_BOUNDS.MAX_ARG_BYTES,
    ).toBeGreaterThan(TRANSPORT_BOUNDS.MAX_ARGV_TOTAL_BYTES);
  });

  it('accepts argv exactly at the total byte bound', () => {
    const perArgument = TRANSPORT_BOUNDS.MAX_ARGV_TOTAL_BYTES / 8;
    const exact = Array.from({ length: 8 }, () => ascii(perArgument));

    expect(rejectionForSpec(withRawSpecField('args', exact))).toBe('ACCEPTED');
  });

  it('accepts a serialized Windows command line exactly at the OS boundary', () => {
    const args = Array.from({ length: 8 }, () => ascii(3_750));
    const exactPath = `C:\\${ascii(2_755)}`;
    const overPath = `${exactPath}x`;
    const environment: Record<string, string> = {};
    for (const name of WINDOWS_REQUIRED_ENVIRONMENT_VARIABLES) {
      environment[name] = '';
    }
    const windowsSpec = (executablePath: string): AgentProcessSpec =>
      makeSpec({ executablePath, workingDirectory: 'C:\\work', args, environment });

    expect(readInvocation(windowsSpec(exactPath), makeLimits(), 'win32').rejection).toBeNull();
    expect(readInvocation(windowsSpec(overPath), makeLimits(), 'win32').rejection).toBe(
      'ARGV_TOTAL_BYTES_EXCEEDED',
    );
  });

  it('rejects Windows quoting expansion even when raw argv bytes are below the bound', () => {
    const expands = '\\"'.repeat(2_048);
    const args = [expands, expands, expands, expands];
    const environment: Record<string, string> = {};
    for (const name of WINDOWS_REQUIRED_ENVIRONMENT_VARIABLES) {
      environment[name] = '';
    }
    const result = readInvocation(
      makeSpec({
        executablePath: 'C:\\node.exe',
        workingDirectory: 'C:\\work',
        args,
        environment,
      }),
      makeLimits(),
      'win32',
    );

    expect(args.join('').length).toBeLessThan(TRANSPORT_BOUNDS.MAX_ARGV_TOTAL_BYTES);
    expect(result.rejection).toBe('ARGV_TOTAL_BYTES_EXCEEDED');
  });

  it('accepts Windows empty, whitespace, quoted, and backslash argument forms in range', () => {
    const environment: Record<string, string> = {};
    for (const name of WINDOWS_REQUIRED_ENVIRONMENT_VARIABLES) {
      environment[name] = '';
    }
    const result = readInvocation(
      makeSpec({
        executablePath: 'C:\\Program Files\\node.exe',
        workingDirectory: 'C:\\work',
        args: ['', 'two words', 'a"b', 'a\\"b', 'trailing\\'],
        environment,
      }),
      makeLimits(),
      'win32',
    );

    expect(result.rejection).toBeNull();
  });

  it.each(NON_ENVIRONMENT_VALUES)('refuses an environment that is %s', (_label, value) => {
    const rejection = rejectionForSpec(withRawSpecField('environment', value));

    expect(['ENVIRONMENT_NOT_RECORD', 'ENVIRONMENT_ENTRY_INVALID']).toContain(rejection);
  });

  it('refuses an environment value supplied through a getter without invoking it', () => {
    let invoked = false;
    const hostile = {};
    Object.defineProperty(hostile, 'TOKEN', {
      get() {
        invoked = true;
        return 'secret';
      },
      enumerable: true,
      configurable: true,
    });

    expect(rejectionForSpec(withRawSpecField('environment', hostile))).toBe(
      'ENVIRONMENT_ENTRY_INVALID',
    );
    expect(invoked).toBe(false);
  });

  it('refuses an environment whose own-property reflection fails, before any spawn', async () => {
    let invoked = false;
    const enumerable = {};
    Object.defineProperty(enumerable, 'TOKEN', {
      get() {
        invoked = true;
        return 'secret';
      },
      enumerable: true,
      configurable: true,
    });
    // Key enumeration itself fails, so no entry is ever inspected.
    const keysDenied = new Proxy(enumerable, {
      ownKeys(): never {
        throw new Error('key enumeration denied');
      },
    });
    // Enumeration succeeds and the per-entry descriptor read fails instead,
    // which is the second, separately guarded reflection step.
    const descriptorDenied = new Proxy(
      { PATH: '/usr/bin' },
      {
        getOwnPropertyDescriptor(): never {
          throw new Error('descriptor read denied');
        },
      },
    );

    expect(rejectionForSpec(withRawSpecField('environment', keysDenied))).toBe(
      'ENVIRONMENT_UNREADABLE',
    );
    expect(rejectionForSpec(withRawSpecField('environment', descriptorDenied))).toBe(
      'ENVIRONMENT_UNREADABLE',
    );
    expect(invoked).toBe(false);

    // A revoked Proxy fails the earlier record gate, and a plain non-string
    // entry fails the per-entry content rules; neither is reported as an
    // unreadable environment.
    const revocable = Proxy.revocable({}, {});
    revocable.revoke();

    expect(rejectionForSpec(withRawSpecField('environment', revocable.proxy))).toBe(
      'ENVIRONMENT_NOT_RECORD',
    );
    expect(rejectionForSpec(withRawSpecField('environment', { PATH: 7 }))).toBe(
      'ENVIRONMENT_ENTRY_INVALID',
    );

    const exchange = await invokeAgentProcess(
      withRawSpecField('environment', keysDenied),
      makeLimits(),
    );

    expect(exchange.outcome).toBe('SPEC_REJECTED');
    expect(exchange.rejection).toBe('ENVIRONMENT_UNREADABLE');
    expect(exchange.exitCode).toBeNull();
    expect(exchange.terminatingSignal).toBeNull();
    expect(exchange.stdout).toBe('');
    expect(exchange.stderr).toBe('');
    expect(invoked).toBe(false);
  });

  it('refuses an environment carrying a symbol key', () => {
    const hostile: Record<string | symbol, unknown> = { PATH: '/usr/bin' };
    hostile[Symbol('hidden')] = 'value';

    expect(rejectionForSpec(withRawSpecField('environment', hostile))).toBe(
      'ENVIRONMENT_ENTRY_INVALID',
    );
  });

  it('refuses an environment value that is not a string', () => {
    expect(rejectionForSpec(withRawSpecField('environment', { COUNT: 7 }))).toBe(
      'ENVIRONMENT_ENTRY_INVALID',
    );
  });

  it('accepts an environment value exactly at its bound and rejects one byte more', () => {
    const exact = {
      ...baseEnvironment(),
      BOUNDED: ascii(TRANSPORT_BOUNDS.MAX_ENV_VALUE_BYTES),
    };
    const oversized = {
      ...baseEnvironment(),
      BOUNDED: ascii(TRANSPORT_BOUNDS.MAX_ENV_VALUE_BYTES + 1),
    };

    expect(rejectionForSpec(makeSpec({ environment: exact }))).toBe('ACCEPTED');
    expect(rejectionForSpec(makeSpec({ environment: oversized }))).toBe(
      'ENVIRONMENT_BYTES_EXCEEDED',
    );
  });

  it('refuses empty, NUL, and equals-containing environment names', () => {
    expect(rejectionForSpec(withRawSpecField('environment', { '': 'v' }))).toBe(
      'ENVIRONMENT_ENTRY_INVALID',
    );
    expect(rejectionForSpec(withRawSpecField('environment', { 'A\u0000B': 'v' }))).toBe(
      'ENVIRONMENT_ENTRY_INVALID',
    );
    expect(rejectionForSpec(withRawSpecField('environment', { 'A=B': 'v' }))).toBe(
      'ENVIRONMENT_ENTRY_INVALID',
    );
  });

  it('refuses case-insensitive duplicate environment names', () => {
    const spec = makeSpec({
      executablePath: 'C:\\node.exe',
      workingDirectory: 'C:\\work',
      environment: { PATH: 'a', Path: 'b' },
    });
    expect(readInvocation(spec, makeLimits(), 'win32').rejection).toBe(
      'ENVIRONMENT_NAME_DUPLICATED',
    );
  });

  it('keeps POSIX environment-name matching case-sensitive', () => {
    expect(
      readInvocation(
        makeSpec({
          executablePath: '/usr/bin/node',
          workingDirectory: '/tmp',
          environment: { PATH: 'a', Path: 'b' },
        }),
        makeLimits(),
        'posix',
      ).rejection,
    ).toBeNull();
  });

  it('requires every libuv-sensitive variable on Windows and permits empty values', () => {
    const complete = {
      HOMEDRIVE: '', HOMEPATH: '', LOGONSERVER: '', PATH: '', SYSTEMDRIVE: '',
      SYSTEMROOT: '', TEMP: '', USERDOMAIN: '', USERNAME: '', USERPROFILE: '', WINDIR: '',
    };
    const windowsSpec = (environment: Record<string, string>): AgentProcessSpec =>
      makeSpec({
        executablePath: 'C:\\node.exe',
        workingDirectory: 'C:\\work',
        environment,
      });
    expect(readInvocation(windowsSpec(complete), makeLimits(), 'win32').rejection)
      .toBeNull();
    const missing: Record<string, string> = { ...complete };
    Reflect.deleteProperty(missing, 'PATH');
    expect(readInvocation(windowsSpec(missing), makeLimits(), 'win32').rejection)
      .toBe('ENVIRONMENT_REQUIRED_VARIABLE_MISSING');
  });

  it('matches Windows-required environment names case-insensitively', () => {
    const complete = {
      homedrive: '', homepath: '', logonserver: '', path: '', systemdrive: '',
      systemroot: '', temp: '', userdomain: '', username: '', userprofile: '', windir: '',
    };
    expect(readInvocation(makeSpec({
      executablePath: 'C:\\node.exe',
      workingDirectory: 'C:\\work',
      environment: complete,
    }), makeLimits(), 'win32').rejection)
      .toBeNull();
  });

  it.each(WINDOWS_REQUIRED_ENVIRONMENT_VARIABLES)(
    'rejects Windows environment when %s is missing',
    (missingName) => {
      const environment: Record<string, string> = {};
      for (const name of WINDOWS_REQUIRED_ENVIRONMENT_VARIABLES) {
        if (name !== missingName) {
          environment[name] = '';
        }
      }
      const spec = makeSpec({
        executablePath: 'C:\\node.exe',
        workingDirectory: 'C:\\work',
        environment,
      });
      expect(readInvocation(spec, makeLimits(), 'win32').rejection).toBe(
        'ENVIRONMENT_REQUIRED_VARIABLE_MISSING',
      );
    },
  );

  it('refuses more environment entries than the bound', () => {
    const many: Record<string, string> = {};
    for (let index = 0; index <= TRANSPORT_BOUNDS.MAX_ENV_ENTRIES; index += 1) {
      many[`K${String(index)}`] = 'v';
    }

    expect(rejectionForSpec(withRawSpecField('environment', many))).toBe(
      'ENVIRONMENT_COUNT_EXCEEDED',
    );
  });

  it('ignores an inherited environment entry planted on a prototype', () => {
    const prototype = Object.prototype as unknown as Record<string, unknown>;
    prototype['INHERITED_TOKEN'] = 'secret';
    try {
      const result = readInvocation(
        makeSpec({
          executablePath: '/usr/bin/node',
          workingDirectory: '/tmp',
          environment: Object.create(prototype) as Record<string, string>,
        }),
        makeLimits(),
        'posix',
      );

      expect(result.rejection).toBeNull();
      expect(Object.keys(result.value?.environment ?? {})).toEqual([]);
    } finally {
      delete prototype['INHERITED_TOKEN'];
    }
  });

  it.each(MALFORMED_VALUES)('refuses stdin that is %s', (_label, value) => {
    expect(rejectionForSpec(withRawSpecField('stdin', value))).toBe('STDIN_NOT_STRING');
  });

  it('refuses a stdin payload past the bound', () => {
    expect(
      rejectionForSpec(withRawSpecField('stdin', ascii(TRANSPORT_BOUNDS.MAX_STDIN_BYTES + 1))),
    ).toBe('STDIN_BYTES_EXCEEDED');
  });

  it.each([
    ['zero', 0],
    ['negative', -1],
    ['fractional', 1.5],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['past the maximum', TRANSPORT_BOUNDS.MAX_TIMEOUT_MS + 1],
    ['a string', '1000'],
  ])('refuses a %s timeout', (_label, value) => {
    expect(rejectionFor(makeSpec(), withRawLimitField('timeoutMs', value))).toBe(
      'TIMEOUT_OUT_OF_RANGE',
    );
  });

  it('refuses a negative grace period', () => {
    expect(rejectionFor(makeSpec(), withRawLimitField('graceMs', -1))).toBe(
      'GRACE_OUT_OF_RANGE',
    );
  });

  it('refuses stream bounds past their ceilings', () => {
    expect(
      rejectionFor(
        makeSpec(),
        withRawLimitField('maxStdoutBytes', TRANSPORT_BOUNDS.MAX_STDOUT_BYTES_CEILING + 1),
      ),
    ).toBe('STDOUT_LIMIT_OUT_OF_RANGE');
    expect(
      rejectionFor(
        makeSpec(),
        withRawLimitField('maxStderrBytes', TRANSPORT_BOUNDS.MAX_STDERR_BYTES_CEILING + 1),
      ),
    ).toBe('STDERR_LIMIT_OUT_OF_RANGE');
  });

  it('refuses an object that is not a usable AbortSignal', () => {
    expect(rejectionFor(makeSpec(), withRawLimitField('signal', {}))).toBe(
      'ABORT_SIGNAL_INVALID',
    );
    expect(rejectionFor(makeSpec(), withRawLimitField('signal', 'abort'))).toBe(
      'ABORT_SIGNAL_INVALID',
    );
  });

  it('accepts a real AbortSignal', () => {
    const controller = new AbortController();

    expect(rejectionFor(makeSpec(), withRawLimitField('signal', controller.signal))).toBe(
      'ACCEPTED',
    );
  });

  it('does not invoke accessor-backed or revoked-Proxy signal properties', () => {
    let invoked = false;
    const fake = {};
    Object.defineProperty(fake, 'aborted', {
      get() {
        invoked = true;
        return false;
      },
    });
    expect(rejectionFor(makeSpec(), withRawLimitField('signal', fake))).toBe(
      'ABORT_SIGNAL_INVALID',
    );
    expect(invoked).toBe(false);

    const revocable = Proxy.revocable(new AbortController().signal, {});
    revocable.revoke();
    expect(rejectionFor(makeSpec(), withRawLimitField('signal', revocable.proxy))).toBe(
      'ABORT_SIGNAL_INVALID',
    );
  });

  it('reaches every rejection reason from at least one malformed request', () => {
    // Guards against a reason that exists in the vocabulary but is unreachable.
    const reachable = new Set<string>([
      rejectionForSpec(null as unknown as AgentProcessSpec),
      rejectionFor(makeSpec(), null as unknown as TransportLimits),
      rejectionForSpec(withRawSpecField('executablePath', 42)),
      rejectionForSpec(withRawSpecField('executablePath', 'relative')),
      rejectionForSpec(
        withRawSpecField(
          'executablePath',
          PLATFORM === 'win32' ? 'C:\\a.cmd' : '/a.cmd',
        ),
      ),
      rejectionForSpec(withRawSpecField('workingDirectory', 42)),
      rejectionForSpec(withRawSpecField('workingDirectory', 'relative')),
      rejectionForSpec(withRawSpecField('args', 'not-an-array')),
      rejectionForSpec(withRawSpecField('args', new Proxy([] as unknown[], {
        get(): never {
          throw new Error('trap');
        },
      }))),
      rejectionForSpec(
        withRawSpecField(
          'args',
          Array.from({ length: TRANSPORT_BOUNDS.MAX_ARGV_COUNT + 1 }, () => 'a'),
        ),
      ),
      rejectionForSpec(withRawSpecField('args', [42])),
      rejectionForSpec(withRawSpecField('args', ['a\u0000b'])),
      rejectionForSpec(withRawSpecField('args', [ascii(TRANSPORT_BOUNDS.MAX_ARG_BYTES + 1)])),
      rejectionForSpec(
        withRawSpecField(
          'args',
          Array.from({ length: TRANSPORT_BOUNDS.MAX_ARGV_COUNT }, () =>
            ascii(TRANSPORT_BOUNDS.MAX_ARG_BYTES),
          ),
        ),
      ),
      rejectionForSpec(withRawSpecField('environment', 'nope')),
      rejectionForSpec(withRawSpecField('environment', { A: 1 })),
      readInvocation(makeSpec({
        executablePath: 'C:\\node.exe',
        workingDirectory: 'C:\\work',
        environment: { PATH: 'a', Path: 'b' },
      }), makeLimits(), 'win32').rejection ?? 'ACCEPTED',
      readInvocation(makeSpec({
        executablePath: 'C:\\node.exe',
        workingDirectory: 'C:\\work',
        environment: {},
      }), makeLimits(), 'win32').rejection ??
        'ACCEPTED',
      rejectionForSpec(
        withRawSpecField(
          'environment',
          Object.fromEntries(
            Array.from({ length: TRANSPORT_BOUNDS.MAX_ENV_ENTRIES + 1 }, (_unused, index) => [
              `K${String(index)}`,
              'v',
            ]),
          ),
        ),
      ),
      rejectionForSpec(
        withRawSpecField('environment', {
          [ascii(TRANSPORT_BOUNDS.MAX_ENV_KEY_BYTES + 1)]: 'v',
        }),
      ),
      rejectionForSpec(withRawSpecField('args', ['-e', '\uD800'])),
      rejectionForSpec(withRawSpecField('stdin', 42)),
      rejectionForSpec(withRawSpecField('stdin', '\uD800')),
      rejectionForSpec(withRawSpecField('stdin', ascii(TRANSPORT_BOUNDS.MAX_STDIN_BYTES + 1))),
      rejectionFor(makeSpec(), withRawLimitField('timeoutMs', 0)),
      rejectionFor(makeSpec(), withRawLimitField('graceMs', -1)),
      rejectionFor(
        makeSpec(),
        withRawLimitField('maxStdoutBytes', TRANSPORT_BOUNDS.MAX_STDOUT_BYTES_CEILING + 1),
      ),
      rejectionFor(
        makeSpec(),
        withRawLimitField('maxStderrBytes', TRANSPORT_BOUNDS.MAX_STDERR_BYTES_CEILING + 1),
      ),
      rejectionFor(makeSpec(), withRawLimitField('signal', {})),
    ]);

    const declared = Object.values(TRANSPORT_REJECTION);
    const unreachable = declared.filter((reason) => !reachable.has(reason));

    // ARGUMENT_UNREADABLE and ENVIRONMENT_UNREADABLE are covered by their own
    // dedicated getter and revoked-Proxy cases above.
    expect(unreachable.sort()).toEqual(
      ['ARGUMENT_UNREADABLE', 'ENVIRONMENT_UNREADABLE'].sort(),
    );
  });
});

/**
 * Names `node:child_process` copies out of the parent into a supplied
 * `options.env`, in the order `normalizeSpawnArguments` copies them.
 *
 * `NODE_V8_COVERAGE` is copied on every platform; the nine that follow are
 * copied when Node's own `process.platform` is `os390`. That platform check is
 * Node's, not this transport's, and `TransportPlatform` has no z/OS member, so
 * the snapshot must be safe against all ten regardless of where it was built.
 */
const RUNTIME_PROPAGATED_NAMES: readonly string[] = Object.freeze([
  'NODE_V8_COVERAGE',
  '_BPXK_AUTOCVT',
  '_CEE_RUNOPTS',
  '_TAG_REDIR_ERR',
  '_TAG_REDIR_IN',
  '_TAG_REDIR_OUT',
  'STEPLIB',
  'LIBPATH',
  '_EDC_SIG_DFLT',
  '_EDC_SUSV3',
]);

/**
 * `copyProcessEnvToEnv` from `lib/child_process.js`, with the parent read
 * injected so the assertion never depends on this host's real environment.
 *
 * Node's copy is a plain assignment inside a strict-mode module, so it throws
 * rather than failing silently when the target is frozen. Reproducing the
 * assignment — instead of asserting a property descriptor and calling it done —
 * is what makes these tests a proof about the spawn path.
 */
function copyProcessEnvToEnv(
  env: Record<string, string>,
  name: string,
  optionEnv: Record<string, string> | undefined,
  parentEnv: Readonly<Record<string, string>>,
): void {
  const parentValue = parentEnv[name];
  if (
    parentValue !== undefined &&
    parentValue !== '' &&
    (optionEnv === undefined || !Object.prototype.hasOwnProperty.call(optionEnv, name))
  ) {
    env[name] = parentValue;
  }
}

/** The `for...in` walk `normalizeSpawnArguments` uses to build `envPairs`. */
function envPairsFor(env: Readonly<Record<string, string>>): readonly string[] {
  const keys: string[] = [];
  for (const key in env) {
    keys.push(key);
  }
  const pairs: string[] = [];
  for (const key of keys) {
    const value = env[key];
    if (value !== undefined) {
      pairs.push(`${key}=${value}`);
    }
  }
  return pairs;
}

/** The validated, frozen snapshot for an environment this host accepts. */
function validatedEnvironment(
  environment: Readonly<Record<string, string>>,
): Record<string, string> {
  const result = readInvocation(makeSpec({ environment }), makeLimits(), PLATFORM);

  expect(result.rejection).toBeNull();

  return (result.value?.environment ?? {}) as Record<string, string>;
}

/**
 * Runtime variables Node propagates into a supplied environment.
 *
 * Every name here is one Node would otherwise lift out of the parent process
 * and hand to the child behind the caller's back. The snapshot carries a
 * non-enumerable own blocker for each, which satisfies Node's own-property
 * guard so the copy is skipped, keeps the parent value out of the child, and
 * stays out of the enumeration that builds `envPairs`. Without the blocker the
 * assignment lands on a frozen record and throws, turning a valid invocation
 * into a spawn failure.
 */
describe('runtime variables Node would otherwise copy from the parent', () => {
  it.each(RUNTIME_PROPAGATED_NAMES)(
    'blocks %s with a non-enumerable own property when the caller omits it',
    (name) => {
      const snapshot = validatedEnvironment(baseEnvironment());
      const descriptor = Object.getOwnPropertyDescriptor(snapshot, name);

      expect(descriptor).toEqual({
        value: '',
        writable: false,
        enumerable: false,
        configurable: false,
      });
      expect(Object.prototype.hasOwnProperty.call(snapshot, name)).toBe(true);
    },
  );

  it.each(RUNTIME_PROPAGATED_NAMES)(
    'refuses Node the chance to copy a parent %s into the child',
    (name) => {
      const snapshot = validatedEnvironment(baseEnvironment());
      const before = envPairsFor(snapshot);

      expect(() => {
        copyProcessEnvToEnv(snapshot, name, snapshot, { [name]: 'PARENT_VALUE' });
      }).not.toThrow();

      expect(snapshot[name]).not.toBe('PARENT_VALUE');
      expect(envPairsFor(snapshot)).toEqual(before);
    },
  );

  it.each(RUNTIME_PROPAGATED_NAMES)('keeps %s out of the child environment', (name) => {
    const snapshot = validatedEnvironment(baseEnvironment());

    expect(Object.keys(snapshot)).not.toContain(name);
    expect(envPairsFor(snapshot)).not.toContain(`${name}=`);
    expect(envPairsFor(snapshot).some((pair) => pair.startsWith(`${name}=`))).toBe(false);
  });

  it.each(RUNTIME_PROPAGATED_NAMES)(
    'preserves a caller-supplied %s exactly and does not shadow it',
    (name) => {
      const snapshot = validatedEnvironment({ ...baseEnvironment(), [name]: 'CALLER_VALUE' });

      expect(snapshot[name]).toBe('CALLER_VALUE');
      expect(Object.getOwnPropertyDescriptor(snapshot, name)?.enumerable).toBe(true);
      expect(Object.keys(snapshot)).toContain(name);
      expect(envPairsFor(snapshot)).toContain(`${name}=CALLER_VALUE`);

      copyProcessEnvToEnv(snapshot, name, snapshot, { [name]: 'PARENT_VALUE' });

      expect(snapshot[name]).toBe('CALLER_VALUE');
    },
  );

  it('survives the whole propagation sequence against the frozen record', () => {
    const caller = baseEnvironment();
    const snapshot = validatedEnvironment(caller);
    const parent: Record<string, string> = {};
    for (const name of RUNTIME_PROPAGATED_NAMES) {
      parent[name] = 'PARENT_VALUE';
    }

    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(() => {
      for (const name of RUNTIME_PROPAGATED_NAMES) {
        copyProcessEnvToEnv(snapshot, name, snapshot, parent);
      }
    }).not.toThrow();

    expect(envPairsFor(snapshot)).toEqual(
      Object.entries(caller).map(([key, value]) => `${key}=${value}`),
    );
  });
});

/**
 * `copyPermissionModelFlagsToEnv` from `lib/child_process.js`, with the parent's
 * `execArgv` and flag list injected so the assertion never depends on how this
 * test run happened to be launched.
 *
 * The difference from `copyProcessEnvToEnv` above is the entire finding. That
 * one asks whether the supplied object already owns the name and skips the copy
 * when it does, which is what a blocker exploits. This one asks no such
 * question: when the parent runs under `--permission` it simply assigns, and a
 * plain strict-mode assignment against a frozen record throws.
 */
function copyPermissionModelFlagsToEnv(
  env: Record<string, string>,
  key: string,
  args: readonly string[],
  execArgv: readonly string[],
  flagsToCopy: readonly string[],
): void {
  if (args.includes('--permission') || (env[key] ?? '').includes('--permission')) {
    return;
  }
  for (const arg of execArgv) {
    for (const flag of flagsToCopy) {
      if (arg.startsWith(flag)) {
        const existing = env[key] ?? '';
        env[key] = existing === '' ? arg : `${existing} ${arg}`;
      }
    }
  }
}

/**
 * The variable Node writes to, rather than copies into, under the permission
 * model.
 *
 * A deployment that runs AgentBridge under `--permission` must pass
 * `--allow-child-process` for this transport to spawn anything at all, and that
 * is exactly the configuration in which Node tries to hand its own permission
 * flags down through `NODE_OPTIONS`. The snapshot has to absorb that write:
 * refusing it would turn a structurally valid invocation into a spawn failure,
 * and accepting it into the child would put the parent's flags in front of an
 * agent that was never told about them.
 */
describe('the variable Node assigns under the permission model', () => {
  const NAME = 'NODE_OPTIONS';
  /** What `process.execArgv` holds when the model is on. Never read from here. */
  const PERMISSION_EXEC_ARGV: readonly string[] = Object.freeze([
    '--permission',
    '--allow-child-process',
    '--allow-fs-read=*',
  ]);
  /** `permission.availableFlags()` plus `--permission`, declared independently. */
  const PERMISSION_FLAGS: readonly string[] = Object.freeze([
    '--allow-addons',
    '--allow-child-process',
    '--allow-fs-read',
    '--allow-fs-write',
    '--allow-net',
    '--allow-wasi',
    '--allow-worker',
    '--permission',
  ]);
  /** argv as Node builds it: the file, then the caller's arguments. */
  const CHILD_ARGS: readonly string[] = Object.freeze(['/usr/bin/node', '-e', '']);

  it('absorbs the assignment against the frozen record when the caller omits it', () => {
    const snapshot = validatedEnvironment(baseEnvironment());
    const before = envPairsFor(snapshot);

    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(() => {
      copyPermissionModelFlagsToEnv(
        snapshot,
        NAME,
        CHILD_ARGS,
        PERMISSION_EXEC_ARGV,
        PERMISSION_FLAGS,
      );
    }).not.toThrow();

    expect(envPairsFor(snapshot)).toEqual(before);
  });

  it('keeps the absorbing entry out of the child environment', () => {
    const snapshot = validatedEnvironment(baseEnvironment());
    copyPermissionModelFlagsToEnv(
      snapshot,
      NAME,
      CHILD_ARGS,
      PERMISSION_EXEC_ARGV,
      PERMISSION_FLAGS,
    );

    expect(Object.prototype.hasOwnProperty.call(snapshot, NAME)).toBe(true);
    expect(Object.keys(snapshot)).not.toContain(NAME);
    expect(envPairsFor(snapshot).some((pair) => pair.startsWith(`${NAME}=`))).toBe(false);
    expect(snapshot[NAME]).toBe('');
  });

  it('preserves a caller-supplied value exactly through the assignment', () => {
    const supplied = '--max-old-space-size=256';
    const snapshot = validatedEnvironment({ ...baseEnvironment(), [NAME]: supplied });

    expect(envPairsFor(snapshot)).toContain(`${NAME}=${supplied}`);
    expect(() => {
      copyPermissionModelFlagsToEnv(
        snapshot,
        NAME,
        CHILD_ARGS,
        PERMISSION_EXEC_ARGV,
        PERMISSION_FLAGS,
      );
    }).not.toThrow();

    expect(snapshot[NAME]).toBe(supplied);
    expect(envPairsFor(snapshot)).toContain(`${NAME}=${supplied}`);
  });

  it('leaves the variables Node copies blocked exactly as they were', () => {
    const snapshot = validatedEnvironment(baseEnvironment());
    copyPermissionModelFlagsToEnv(
      snapshot,
      NAME,
      CHILD_ARGS,
      PERMISSION_EXEC_ARGV,
      PERMISSION_FLAGS,
    );

    for (const name of RUNTIME_PROPAGATED_NAMES) {
      expect(Object.getOwnPropertyDescriptor(snapshot, name)).toEqual({
        value: '',
        writable: false,
        enumerable: false,
        configurable: false,
      });
    }
  });
});

/**
 * Well-formedness of the two strings this transport promises to carry verbatim.
 *
 * argv and stdin are both encoded as UTF-8 on the way to the child, and UTF-8
 * cannot represent an unpaired surrogate. Accepting one would mean validating
 * one value and delivering another, so both are refused before spawn. The
 * corresponding process-level proof — that the child really did receive U+FFFD
 * before this rule existed, and receives the exact character now — lives in
 * `process-transport.test.ts`.
 */
describe('well-formed UTF-16 on the exactly-transmitted fields', () => {
  it.each(LONE_SURROGATE_STRINGS)('refuses an argument holding %s', (_label, value) => {
    expect(rejectionForSpec(withRawSpecField('args', ['-e', value]))).toBe(
      'ARGUMENT_LONE_SURROGATE',
    );
  });

  it.each(LONE_SURROGATE_STRINGS)('refuses a stdin payload holding %s', (_label, value) => {
    expect(rejectionForSpec(withRawSpecField('stdin', value))).toBe('STDIN_LONE_SURROGATE');
  });

  it.each(WELL_FORMED_STRINGS)('accepts %s as an argument', (_label, value) => {
    const result = readInvocation(
      makeSpec({ args: ['-e', value] }),
      makeLimits(),
      PLATFORM,
    );

    expect(result.rejection).toBeNull();
    // Accepted means unchanged: no normalization, no substitution, no reordering.
    expect(result.value?.args).toEqual(['-e', value]);
  });

  it.each(WELL_FORMED_STRINGS)('accepts %s as a stdin payload', (_label, value) => {
    const result = readInvocation(makeSpec({ stdin: value }), makeLimits(), PLATFORM);

    expect(result.rejection).toBeNull();
    expect(result.value?.stdin).toBe(value);
  });

  it('rejects exactly the strings the UTF-8 boundary would alter', () => {
    // The oracle is the boundary itself rather than a restatement of the
    // implementation: a string survives a UTF-8 round trip if and only if it is
    // well-formed, and that round trip is what argv and the stdin pipe perform
    // on the way to the child.
    const corpus = [
      ...LONE_SURROGATE_STRINGS.map(([, value]) => value),
      ...WELL_FORMED_STRINGS.map(([, value]) => value),
    ];

    for (const value of corpus) {
      const roundTripped = Buffer.from(value, 'utf8').toString('utf8');

      expect(containsLoneSurrogate(value)).toBe(roundTripped !== value);
    }
  });

  it('reads through captured intrinsics after charCodeAt is poisoned', () => {
    const descriptor = Object.getOwnPropertyDescriptor(String.prototype, 'charCodeAt');
    Object.defineProperty(String.prototype, 'charCodeAt', {
      configurable: true,
      writable: true,
      value: (): number => 0x41,
    });
    try {
      expect(containsLoneSurrogate('\uD800')).toBe(true);
      expect(containsLoneSurrogate('\u{1F600}')).toBe(false);
      expect(rejectionForSpec(withRawSpecField('args', ['-e', '\uDC00']))).toBe(
        'ARGUMENT_LONE_SURROGATE',
      );
    } finally {
      if (descriptor !== undefined) {
        Object.defineProperty(String.prototype, 'charCodeAt', descriptor);
      }
    }
  });

  it.each(LONE_SURROGATE_STRINGS)(
    'refuses an environment value holding %s',
    (_label, value) => {
      const environment = { ...baseEnvironment(), AGENTBRIDGE_SURROGATE: value };

      expect(rejectionForSpec(withRawSpecField('environment', environment))).toBe(
        'ENVIRONMENT_ENTRY_INVALID',
      );
    },
  );

  it.each(LONE_SURROGATE_STRINGS)(
    'refuses an environment name holding %s',
    (_label, value) => {
      const environment = { ...baseEnvironment(), [`AGENTBRIDGE_${value}`]: 'ordinary' };

      expect(rejectionForSpec(withRawSpecField('environment', environment))).toBe(
        'ENVIRONMENT_ENTRY_INVALID',
      );
    },
  );

  it.each(WELL_FORMED_STRINGS)('accepts %s as an environment value', (_label, value) => {
    const environment = { ...baseEnvironment(), AGENTBRIDGE_WELL_FORMED: value };
    const result = readInvocation(makeSpec({ environment }), makeLimits(), PLATFORM);

    expect(result.rejection).toBeNull();
    expect(result.value?.environment['AGENTBRIDGE_WELL_FORMED']).toBe(value);
  });

  it.each(WELL_FORMED_STRINGS)('accepts %s inside an environment name', (_label, value) => {
    const name = `AGENTBRIDGE_${value}`;
    const environment = { ...baseEnvironment(), [name]: 'ordinary' };
    const result = readInvocation(makeSpec({ environment }), makeLimits(), PLATFORM);

    expect(result.rejection).toBeNull();
    // The snapshot carries the name through unchanged, byte for byte.
    expect(Object.keys(result.value?.environment ?? {})).toContain(name);
  });

  it('keeps the pre-existing rules reporting themselves', () => {
    expect(rejectionForSpec(withRawSpecField('args', ['-e', 42]))).toBe('ARGUMENT_NOT_STRING');
    expect(rejectionForSpec(withRawSpecField('args', ['-e', 'a b']))).toBe(
      'ARGUMENT_CONTAINS_NUL',
    );
  });
});

describe('single-read discipline', () => {
  it('snapshots argv so a later mutation cannot change what is spawned', () => {
    const mutable = ['-e', 'original'];
    const result = readInvocation(
      makeSpec({ args: mutable }),
      makeLimits(),
      PLATFORM,
    );
    mutable[1] = 'swapped';

    expect(result.value?.args[1]).toBe('original');
    expect(Object.isFrozen(result.value?.args)).toBe(true);
  });

  it('snapshots the environment into a null-prototype frozen record', () => {
    const result = readInvocation(
      makeSpec({
        executablePath: '/usr/bin/node',
        workingDirectory: '/tmp',
        environment: { A: '1' },
      }),
      makeLimits(),
      'posix',
    );

    expect(Object.getPrototypeOf(result.value?.environment)).toBeNull();
    expect(Object.isFrozen(result.value?.environment)).toBe(true);
  });

  it('freezes the validated invocation itself', () => {
    const result = readInvocation(makeSpec(), makeLimits(), PLATFORM);

    expect(Object.isFrozen(result.value)).toBe(true);
  });
});

describe('absolute-path grammar', () => {
  it.each([
    ['/usr/bin/node', 'posix', true],
    ['/', 'posix', true],
    ['usr/bin/node', 'posix', false],
    ['./node', 'posix', false],
    ['C:\\Windows\\node.exe', 'win32', true],
    ['c:/windows/node.exe', 'win32', true],
    ['\\\\server\\share\\node.exe', 'win32', true],
    ['C:node.exe', 'win32', false],
    ['node.exe', 'win32', false],
    ['\\node.exe', 'win32', false],
    ['/usr/bin/node', 'win32', false],
  ] as const)('treats %j on %s as absolute=%s', (value, platform, expected) => {
    expect(isAbsolutePath(value, platform)).toBe(expected);
  });
});

describe('UTF-8 boundary correctness', () => {
  it('leaves a complete sequence untouched', () => {
    const buffer = Buffer.from('a\u00e9\u4e2d\u{1F600}', 'utf8');

    expect(trimPartialUtf8(buffer)).toEqual(buffer);
  });

  it.each([1, 2, 3])('drops a four-byte character cut after %i byte(s)', (kept) => {
    const full = Buffer.from('\u{1F600}', 'utf8');
    const cut = full.subarray(0, kept);

    expect(trimPartialUtf8(cut).length).toBe(0);
  });

  it('drops a two-byte character cut in half', () => {
    const full = Buffer.from('\u00e9', 'utf8');

    expect(trimPartialUtf8(full.subarray(0, 1)).length).toBe(0);
  });

  it('keeps preceding complete characters when the tail is cut', () => {
    const buffer = Buffer.from('ab\u{1F600}', 'utf8').subarray(0, 4);
    const trimmed = trimPartialUtf8(buffer);

    expect(trimmed.toString('utf8')).toBe('ab');
  });

  it.each([
    ['an invalid lead byte', [0xff]],
    ['an overlong lead byte', [0xc0]],
    ['a continuation byte', [0x80]],
    ['an invalid partial sequence', [0xe0, 0x80]],
  ])('preserves %s at a truncation boundary', (_label, bytes) => {
    const buffer = Buffer.from(bytes);

    expect(trimPartialUtf8(buffer)).toEqual(buffer);
  });

  it('never produces a replacement character from a boundary cut', () => {
    const source = Buffer.from('\u{1F600}\u{1F600}\u{1F600}', 'utf8');
    for (let length = 0; length <= source.length; length += 1) {
      const trimmed = trimPartialUtf8(source.subarray(0, length));

      expect(trimmed.toString('utf8')).not.toContain('\uFFFD');
    }
  });

  it('handles an empty buffer', () => {
    expect(trimPartialUtf8(Buffer.alloc(0)).length).toBe(0);
  });
});

describe('bounds', () => {
  it('matches the independently declared bounds', () => {
    expect({ ...TRANSPORT_BOUNDS }).toEqual({ ...EXPECTED_BOUNDS });
  });

  it('pins the environment key bound to the identifier bound of PR 005 and PR 006', () => {
    expect(TRANSPORT_BOUNDS.MAX_ENV_KEY_BYTES).toBe(INVOCATION_BOUNDS.MAX_IDENTIFIER_LENGTH);
    expect(TRANSPORT_BOUNDS.MAX_ENV_KEY_BYTES).toBe(REVIEW_BOUNDS.MAX_IDENTIFIER_LENGTH);
  });

  it('keeps the total argv bound below the Windows command-line limit', () => {
    expect(TRANSPORT_BOUNDS.MAX_ARGV_TOTAL_BYTES).toBeLessThan(32_767);
  });

  it('freezes every exported vocabulary', () => {
    expect(Object.isFrozen(TRANSPORT_OUTCOME)).toBe(true);
    expect(Object.isFrozen(TRANSPORT_REJECTION)).toBe(true);
    expect(Object.isFrozen(TERMINATION_SCOPE)).toBe(true);
    expect(Object.isFrozen(TRANSPORT_BOUNDS)).toBe(true);
    expect(Object.isFrozen(TERMINAL_CAUSE_PRECEDENCE)).toBe(true);
  });
});

describe('the transport is dormant', () => {
  it('is absent from the package root export surface', () => {
    const root = readFileSync(
      fileURLToPath(new URL('../../src/index.ts', import.meta.url)),
      'utf8',
    );

    expect(root).not.toContain('adapters');
    expect(root).not.toContain('process-transport');
    expect(root).not.toContain('agent-transport');
  });

  it('is absent from the domain barrel', () => {
    const barrel = readFileSync(
      fileURLToPath(new URL('../../src/domain/index.ts', import.meta.url)),
      'utf8',
    );

    expect(barrel).not.toContain('adapters');
  });

  it('has no production caller anywhere in src', () => {
    const sourceRoot = fileURLToPath(new URL('../../src/', import.meta.url));
    const approved = new Set([
      join(sourceRoot, 'adapters', 'agent-transport.ts'),
      join(sourceRoot, 'adapters', 'process-transport.ts'),
    ]);
    const pending = [sourceRoot];
    const callers: string[] = [];
    while (pending.length > 0) {
      const directory = pending.pop();
      if (directory === undefined) {
        continue;
      }
      for (const name of readdirSync(directory)) {
        const path = join(directory, name);
        if (statSync(path).isDirectory()) {
          pending.push(path);
          continue;
        }
        if (!path.endsWith('.ts') || approved.has(path)) {
          continue;
        }
        const source = readFileSync(path, 'utf8');
        if (
          source.includes('agent-transport') ||
          source.includes('process-transport') ||
          source.includes('invokeAgentProcess')
        ) {
          callers.push(path);
        }
      }
    }
    expect(callers).toEqual([]);
  });
});

/**
 * C1-RJ-F1 — repair-job append descriptor isolation.
 *
 * The exported `append<T>` builds an own indexed element through the captured
 * `Object.defineProperty`. Before this repair it handed that call an ordinary
 * `Object.prototype`-inheriting descriptor literal, so a hostile getter that had
 * installed `Object.prototype.get`/`.set` earlier in the same evaluation caused
 * `ToPropertyDescriptor` to see inherited accessor keys beside the own
 * `value`/`writable` keys and throw `TypeError`, breaking the module's
 * documented never-throws / fail-closed contract on every append path.
 *
 * These tests pin that the repaired helper never throws under ambient or
 * mid-evaluation prototype poisoning, that the normal-realm semantics (descriptor
 * flags, element order, refusal reporting) are unchanged, and that the realm is
 * left exactly as found even when a test body throws.
 */
import { afterEach, describe, expect, it } from 'vitest';

import {
  append,
  findInvalidRepairJobFields,
  readRepairJobAuthorization,
  REPAIR_JOB_FIELD_ORDER,
  type RepairJobAuthorization,
} from '../../src/domain/repair-job.js';
import { buildJob } from './repair-job-fixtures.js';

/**
 * Install `value`-shaped poison on `Object.prototype` for the duration of `body`,
 * then restore the original descriptors exactly — including when `body` throws.
 *
 * The installer must not itself reproduce the bug under repair: installing `set`
 * while `get` is already present would hand `Object.defineProperty` a descriptor
 * that inherits the just-installed `Object.prototype.get`. Each descriptor is
 * therefore null-prototyped through the captured intrinsic before use, so the
 * harness stays neutral no matter which keys are installed together.
 */
const captureSetPrototypeOf = Object.setPrototypeOf;
function insulatedDescriptor(descriptor: PropertyDescriptor): PropertyDescriptor {
  captureSetPrototypeOf(descriptor, null);
  return descriptor;
}

function withPrototypePoison<T>(keys: readonly ('get' | 'set')[], body: () => T): T {
  const saved: Record<string, PropertyDescriptor | undefined> = {};
  for (const key of keys) {
    saved[key] = Object.getOwnPropertyDescriptor(Object.prototype, key);
    Object.defineProperty(
      Object.prototype,
      key,
      insulatedDescriptor({ value: function () {}, configurable: true, writable: true }),
    );
  }
  try {
    return body();
  } finally {
    for (const key of keys) {
      const descriptor = saved[key];
      if (descriptor === undefined) {
        Reflect.deleteProperty(Object.prototype, key);
      } else {
        Object.defineProperty(Object.prototype, key, insulatedDescriptor(descriptor));
      }
    }
  }
}

/**
 * An otherwise-valid job whose first-read field installs the poison through a
 * getter, so the prototype is polluted *after* validation has begun but *before*
 * the later `readList` append executes — the mid-evaluation shape the module's
 * intrinsic-capture defense exists to cover.
 */
function jobInstallingPoisonMidRead(kind: 'get' | 'set'): RepairJobAuthorization {
  const hostile: Record<string, unknown> = { ...buildJob() };
  Object.defineProperty(hostile, 'jobId', {
    enumerable: true,
    configurable: true,
    get() {
      Object.defineProperty(
        Object.prototype,
        kind,
        insulatedDescriptor({ value: function () {}, configurable: true, writable: true }),
      );
      return 'job-0001';
    },
  });
  return hostile as unknown as RepairJobAuthorization;
}

afterEach(() => {
  // No test may leak poison, whatever it did or however it failed.
  expect(Object.getOwnPropertyDescriptor(Object.prototype, 'get')).toBeUndefined();
  expect(Object.getOwnPropertyDescriptor(Object.prototype, 'set')).toBeUndefined();
});

describe('C1-RJ-F1: append survives prototype poisoning on the validated-list path', () => {
  const expectValidSnapshot = (result: ReturnType<typeof readRepairJobAuthorization>): void => {
    expect(result.invalidFields).toEqual([]);
    expect(result.snapshot).not.toBeNull();
    // The non-empty lists are the append path; they must round-trip intact.
    expect(result.snapshot?.authorizedPaths).toEqual([
      'src/domain/policy-gate.ts',
      'tests/domain/policy-gate.test.ts',
    ]);
    expect(result.snapshot?.authorizedCommandClasses).toEqual(['test', 'lint', 'typecheck']);
  };

  it('returns a normal snapshot for a valid job under Object.prototype.get poison', () => {
    const result = withPrototypePoison(['get'], () => readRepairJobAuthorization(buildJob()));
    expectValidSnapshot(result);
  });

  it('returns a normal snapshot for a valid job under Object.prototype.set poison', () => {
    const result = withPrototypePoison(['set'], () => readRepairJobAuthorization(buildJob()));
    expectValidSnapshot(result);
  });

  it('returns a normal snapshot for a valid job under get + set poison', () => {
    const result = withPrototypePoison(['get', 'set'], () =>
      readRepairJobAuthorization(buildJob()),
    );
    expectValidSnapshot(result);
  });
});

describe('C1-RJ-F1: append survives prototype poisoning on the invalidFields path', () => {
  // An empty object fails every field, so every `invalidFields` append fires.
  const empty = {} as RepairJobAuthorization;

  it('refuses (never throws) under Object.prototype.get poison, order preserved', () => {
    const invalid = withPrototypePoison(['get'], () => findInvalidRepairJobFields(empty));
    expect(invalid).toEqual(REPAIR_JOB_FIELD_ORDER);
  });

  it('refuses (never throws) under Object.prototype.set poison, order preserved', () => {
    const invalid = withPrototypePoison(['set'], () => findInvalidRepairJobFields(empty));
    expect(invalid).toEqual(REPAIR_JOB_FIELD_ORDER);
  });

  it('reports invalid fields in declaration order for a partially valid job', () => {
    // jobId + repositoryId invalid; the rest valid. Order must follow
    // REPAIR_JOB_FIELD_ORDER, proving append preserves append order under poison.
    const job = buildJob({ jobId: '', repositoryId: '' });
    const invalid = withPrototypePoison(['get', 'set'], () => findInvalidRepairJobFields(job));
    expect(invalid).toEqual(['jobId', 'repositoryId']);
  });
});

describe('C1-RJ-F1: append survives poison installed mid-evaluation', () => {
  // Reads the hostile job, then guarantees the poison it planted is removed
  // before any assertion (which the assertion library would otherwise trip on).
  function readWithMidEvalPoison(
    kind: 'get' | 'set',
  ): ReturnType<typeof readRepairJobAuthorization> {
    try {
      return readRepairJobAuthorization(jobInstallingPoisonMidRead(kind));
    } finally {
      Reflect.deleteProperty(Object.prototype, kind);
    }
  }

  it('never throws when a getter installs get poison before a later append', () => {
    const result = readWithMidEvalPoison('get');
    expect(result.invalidFields).toEqual([]);
    expect(result.snapshot).not.toBeNull();
    expect(result.snapshot?.jobId).toBe('job-0001');
    expect(result.snapshot?.authorizedPaths.length).toBe(2);
  });

  it('never throws when a getter installs set poison before a later append', () => {
    const result = readWithMidEvalPoison('set');
    expect(result.invalidFields).toEqual([]);
    expect(result.snapshot).not.toBeNull();
    expect(result.snapshot?.authorizedCommandClasses.length).toBe(3);
  });
});

describe('C1-RJ-F1: the exported append helper itself', () => {
  it('appends normally under Object.prototype.get poison', () => {
    const list: string[] = [];
    withPrototypePoison(['get'], () => {
      append(list, 'a');
    });
    expect(list).toEqual(['a']);
  });

  it('appends normally under Object.prototype.set poison', () => {
    const list: string[] = [];
    withPrototypePoison(['set'], () => {
      append(list, 'a');
    });
    expect(list).toEqual(['a']);
  });

  it('appends normally under get + set poison', () => {
    const list: string[] = [];
    withPrototypePoison(['get', 'set'], () => {
      append(list, 'a');
      append(list, 'b');
    });
    expect(list).toEqual(['a', 'b']);
  });

  it('defines an own data element with the exact descriptor flags', () => {
    const list: number[] = [];
    append(list, 7);
    const descriptor = Object.getOwnPropertyDescriptor(list, 0);
    expect(descriptor).toEqual({
      value: 7,
      writable: true,
      enumerable: true,
      configurable: true,
    });
    // A data property, never an accessor: no get/set leaked in from the fix.
    expect(descriptor && 'get' in descriptor).toBe(false);
    expect(descriptor && 'set' in descriptor).toBe(false);
    expect(list.length).toBe(1);
  });

  it('preserves element order across successive appends', () => {
    const list: string[] = [];
    for (const value of ['x', 'y', 'z']) {
      append(list, value);
    }
    expect(list).toEqual(['x', 'y', 'z']);
    expect(Object.keys(list)).toEqual(['0', '1', '2']);
  });

  it('restores the realm even when the poisoned body throws', () => {
    expect(() =>
      withPrototypePoison(['get', 'set'], () => {
        throw new Error('boom');
      }),
    ).toThrow('boom');
    // The afterEach hook independently asserts get/set are gone; assert here too
    // so this test fails at its own site if restoration regressed.
    expect(Object.getOwnPropertyDescriptor(Object.prototype, 'get')).toBeUndefined();
    expect(Object.getOwnPropertyDescriptor(Object.prototype, 'set')).toBeUndefined();
  });
});

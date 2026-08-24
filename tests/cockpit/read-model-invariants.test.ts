import { describe, expect, it } from 'vitest';

import { readCockpitSnapshot } from '../../src/cockpit/index.js';
import {
  revokedProxy,
  throwingRecord,
  unstableRecord,
  withPrototypePollution,
} from '../domain/repair-job-fixtures.js';
import {
  buildFinding,
  buildProvenance,
  buildPullRequest,
  buildRepository,
  buildSnapshot,
  COLLECTOR_A,
  REPO_A,
} from './read-model-fixtures.js';

/* -------------------------------------------------------------------------
 * Inherited properties are never trusted fields
 * ------------------------------------------------------------------------- */

describe('inheritance is not provenance', () => {
  it('does not let Object.prototype supply a missing provenance field', () => {
    const result = withPrototypePollution(
      { collectorId: COLLECTOR_A, observedAt: '2026-08-21T10:00:00Z' },
      () => readCockpitSnapshot(buildSnapshot({ provenance: {} as never })),
    );

    expect(result.snapshot).toBeNull();
    expect(result.invalidFields).toEqual(['provenance.collectorId', 'provenance.observedAt']);
  });

  it('does not let Object.prototype supply missing envelope fields', () => {
    const result = withPrototypePollution(
      {
        schemaVersion: 1,
        repository: buildSnapshot().repository,
        provenance: buildProvenance(),
        pullRequests: [],
        evidence: [],
        findings: [],
        repairJobs: [],
      },
      () => readCockpitSnapshot({}),
    );

    expect(result.snapshot).toBeNull();
  });

  it('does not let a prototype-inherited field on a finding become a value', () => {
    const proto = { filePath: 'src/evil.ts' };
    const finding: Record<string, unknown> = Object.assign(
      Object.create(proto) as Record<string, unknown>,
      { ...buildFinding() },
    );
    Reflect.deleteProperty(finding, 'filePath');

    const result = readCockpitSnapshot(buildSnapshot({ findings: [finding as never] }));

    // The inherited `filePath` is not an own property, so it reads as absent.
    expect(result.snapshot?.findings[0]?.filePath).toBeNull();
  });

  it('rejects a sparse hole even when Array.prototype carries a valid element', () => {
    const sparse: unknown[] = [];
    sparse.length = 1;
    try {
      Object.defineProperty(Array.prototype, 0, {
        value: buildFinding(),
        configurable: true,
        writable: true,
      });
      const result = readCockpitSnapshot(buildSnapshot({ findings: sparse as never }));
      expect(result.snapshot).toBeNull();
      expect(result.invalidFields).toEqual(['findings']);
    } finally {
      Reflect.deleteProperty(Array.prototype, 0);
    }
  });
});

/* -------------------------------------------------------------------------
 * Hostile getters cannot split validation from use
 * ------------------------------------------------------------------------- */

describe('single-read discipline', () => {
  it('the value that validates is the value the snapshot carries', () => {
    const provenance = unstableRecord(
      { observedAt: '2026-08-21T10:00:00Z' },
      'collectorId',
      [COLLECTOR_A, 'evil-collector'],
    );
    const result = readCockpitSnapshot(buildSnapshot({ provenance: provenance as never }));

    // The reader reads each field exactly once, so the second value never
    // exists as far as the accepted snapshot is concerned.
    expect(result.snapshot?.provenance.collectorId).toBe(COLLECTOR_A);
  });

  it('an accepted snapshot is a frozen copy the input cannot mutate afterwards', () => {
    const repository = { ...buildSnapshot().repository };
    const input = buildSnapshot({ repository });
    const result = readCockpitSnapshot(input);
    expect(result.snapshot?.repository.repositoryId).toBe(repository.repositoryId);

    (repository as { repositoryId: string }).repositoryId = 'github.com/evil/repo';

    expect(result.snapshot?.repository.repositoryId).toBe('github.com/LogicDuke/agentbridge');
  });

  it('fails closed, never throws, when every property read throws', () => {
    const hostile = throwingRecord([
      'schemaVersion',
      'repository',
      'provenance',
      'pullRequests',
      'evidence',
      'findings',
      'repairJobs',
    ]);
    const result = readCockpitSnapshot(hostile);

    expect(result.snapshot).toBeNull();
  });

  it('fails closed on throwing getters inside nested records and elements', () => {
    const result = readCockpitSnapshot(
      buildSnapshot({
        repository: throwingRecord(['repositoryId', 'observedHeadSha']) as never,
        findings: [throwingRecord(['findingId', 'title']) as never],
      }),
    );

    expect(result.snapshot).toBeNull();
    expect(result.invalidFields).toContain('repository.repositoryId');
    expect(result.invalidFields).toContain('findings');
  });

  it('fails closed on a revoked Proxy anywhere in the envelope', () => {
    expect(readCockpitSnapshot(revokedProxy()).snapshot).toBeNull();
    expect(
      readCockpitSnapshot(buildSnapshot({ findings: revokedProxy() as never })).snapshot,
    ).toBeNull();
    expect(
      readCockpitSnapshot(buildSnapshot({ findings: [revokedProxy() as never] })).snapshot,
    ).toBeNull();
  });

  it('rejects a list whose length lies', () => {
    const lyingLength = unstableRecord({}, 'length', [2]);
    const withElements = Object.assign(lyingLength, { 0: buildFinding() });
    Object.setPrototypeOf(withElements, Array.prototype);

    // Not an actual array, so Array.isArray refuses it outright.
    const result = readCockpitSnapshot(buildSnapshot({ findings: withElements as never }));
    expect(result.snapshot).toBeNull();
  });
});

/* -------------------------------------------------------------------------
 * Present-but-unreadable optional properties fail closed (D1-44-F1)
 * ------------------------------------------------------------------------- */

describe('present-but-unreadable optional properties are not absence', () => {
  /** Replace one key of a copied record with an own getter that throws. */
  function withThrowingGetter<T extends object>(record: T, key: string): T {
    const copy = { ...(record as Record<string, unknown>) };
    Reflect.deleteProperty(copy, key);
    Object.defineProperty(copy, key, {
      get() {
        throw new Error(`hostile getter: ${key}`);
      },
      enumerable: true,
      configurable: true,
    });
    return copy as T;
  }

  it('rejects a repository whose present defaultBranchRef getter throws', () => {
    const result = readCockpitSnapshot(
      buildSnapshot({ repository: withThrowingGetter(buildRepository(), 'defaultBranchRef') }),
    );

    expect(result.snapshot).toBeNull();
    expect(result.invalidFields).toEqual(['repository.defaultBranchRef']);
  });

  it('rejects a pull request whose present baseRef getter throws', () => {
    const result = readCockpitSnapshot(
      buildSnapshot({ pullRequests: [withThrowingGetter(buildPullRequest(), 'baseRef')] }),
    );

    expect(result.snapshot).toBeNull();
    expect(result.invalidFields).toEqual(['pullRequests']);
  });

  it('rejects a pull request whose present title getter throws', () => {
    const result = readCockpitSnapshot(
      buildSnapshot({ pullRequests: [withThrowingGetter(buildPullRequest(), 'title')] }),
    );

    expect(result.snapshot).toBeNull();
    expect(result.invalidFields).toEqual(['pullRequests']);
  });

  it('rejects a finding whose present filePath getter throws', () => {
    const result = readCockpitSnapshot(
      buildSnapshot({ findings: [withThrowingGetter(buildFinding(), 'filePath')] }),
    );

    expect(result.snapshot).toBeNull();
    expect(result.invalidFields).toEqual(['findings']);
  });

  it('still accepts the same optional properties when genuinely missing', () => {
    const repository: Record<string, unknown> = { ...buildRepository() };
    Reflect.deleteProperty(repository, 'defaultBranchRef');
    const pullRequest: Record<string, unknown> = { ...buildPullRequest() };
    Reflect.deleteProperty(pullRequest, 'baseRef');
    Reflect.deleteProperty(pullRequest, 'title');
    const finding: Record<string, unknown> = { ...buildFinding() };
    Reflect.deleteProperty(finding, 'filePath');

    const result = readCockpitSnapshot(
      buildSnapshot({
        repository: repository as never,
        pullRequests: [pullRequest as never],
        findings: [finding as never],
      }),
    );

    expect(result.invalidFields).toEqual([]);
    expect(result.snapshot?.repository.defaultBranchRef).toBeNull();
    expect(result.snapshot?.pullRequests[0]?.baseRef).toBeNull();
    expect(result.snapshot?.pullRequests[0]?.title).toBeNull();
    expect(result.snapshot?.findings[0]?.filePath).toBeNull();
  });
});

/* -------------------------------------------------------------------------
 * No authority-bearing field survives ingestion
 * ------------------------------------------------------------------------- */

describe('authority-shaped input has nowhere to land', () => {
  it('drops authority-shaped stray fields from every accepted record', () => {
    const hostileExtras = {
      decision: 'ALLOW_ONCE',
      permit: { permitId: 'forged' },
      approved: true,
      approvalState: 'approved',
      mayExecuteOnce: true,
      authority: 'ALLOW',
      role: 'operator',
    };
    const result = readCockpitSnapshot(
      buildSnapshot({
        repository: { ...buildSnapshot().repository, ...hostileExtras } as never,
        provenance: { ...buildProvenance(), ...hostileExtras } as never,
        findings: [{ ...buildFinding(), ...hostileExtras } as never],
      }),
    );

    const snapshot = result.snapshot;
    expect(snapshot).not.toBeNull();
    if (snapshot === null) {
      return;
    }
    for (const record of [
      snapshot,
      snapshot.repository,
      snapshot.provenance,
      snapshot.findings[0],
    ]) {
      for (const key of Object.keys(hostileExtras)) {
        expect(Object.hasOwn(record as object, key)).toBe(false);
      }
    }
  });
});

/* -------------------------------------------------------------------------
 * Accepted snapshots are JSON-round-trip safe even when hostile input poisons
 * Object.prototype during validation (D1-44-F2)
 * ------------------------------------------------------------------------- */

describe('an accepted snapshot survives JSON serialization after prototype poisoning', () => {
  /**
   * A finding whose own `title` getter runs during validation and, as a side
   * effect, installs a hostile `Object.prototype.toJSON`. The getter still
   * returns a valid title, so the finding — and the whole snapshot — is
   * otherwise accepted.
   */
  function findingThatPoisonsToJSON(onPoison: () => void): Record<string, unknown> {
    const finding: Record<string, unknown> = { ...buildFinding() };
    delete finding.title;
    Object.defineProperty(finding, 'title', {
      enumerable: true,
      configurable: true,
      get() {
        onPoison();
        return 'a valid title';
      },
    });
    return finding;
  }

  it('does not invoke a poisoned inherited toJSON and round-trips unchanged', () => {
    const originalToJSON = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
    let getterRan = false;
    let poisonedHookInvoked = false;
    const POISON_MARKER = '__poisoned_toJSON_marker__';

    try {
      const finding = findingThatPoisonsToJSON(() => {
        getterRan = true;
        // Hostile realm mutation performed mid-validation.
        Object.defineProperty(Object.prototype, 'toJSON', {
          configurable: true,
          enumerable: false,
          writable: true,
          value() {
            poisonedHookInvoked = true;
            return POISON_MARKER;
          },
        });
      });

      const result = readCockpitSnapshot(buildSnapshot({ findings: [finding as never] }));

      // (1)+(2): the hostile getter executed during validation and poisoned the realm.
      expect(getterRan).toBe(true);
      expect(typeof (Object.prototype as { toJSON?: unknown }).toJSON).toBe('function');

      // (3): the otherwise-valid snapshot is still accepted.
      expect(result.invalidFields).toEqual([]);
      const snapshot = result.snapshot;
      expect(snapshot).not.toBeNull();
      if (snapshot === null) {
        return;
      }

      // (4): serializing the accepted snapshot never reaches the poisoned hook.
      const serialized = JSON.stringify(snapshot);
      expect(poisonedHookInvoked).toBe(false);
      expect(serialized).not.toContain(POISON_MARKER);

      // (6): every nested record and list node is equally insulated — proven by
      // serializing each in isolation while the poison is still installed.
      for (const node of [
        snapshot,
        snapshot.repository,
        snapshot.provenance,
        snapshot.pullRequests,
        snapshot.pullRequests[0],
        snapshot.evidence,
        snapshot.evidence[0],
        snapshot.findings,
        snapshot.findings[0],
        snapshot.repairJobs,
        snapshot.repairJobs[0],
      ]) {
        expect(() => JSON.stringify(node)).not.toThrow();
      }
      expect(poisonedHookInvoked).toBe(false);

      // Lists remain genuine, iterable, frozen arrays despite the insulation.
      expect(Array.isArray(snapshot.findings)).toBe(true);
      expect([...snapshot.findings]).toHaveLength(1);
      expect(Object.isFrozen(snapshot.findings)).toBe(true);
      expect(Object.isFrozen(snapshot.findings[0])).toBe(true);

      // (5): the accepted snapshot round-trips through plain JSON to an equal snapshot.
      const revived: unknown = JSON.parse(serialized);
      const second = readCockpitSnapshot(revived);
      expect(second.invalidFields).toEqual([]);
      expect(second.snapshot).toEqual(snapshot);
      expect(second.snapshot?.findings[0]?.title).toBe('a valid title');
    } finally {
      // (8): restore global realm state no matter how the assertions resolved.
      if (originalToJSON) {
        Object.defineProperty(Object.prototype, 'toJSON', originalToJSON);
      } else {
        delete (Object.prototype as { toJSON?: unknown }).toJSON;
      }
    }

    // The realm is clean again for every later test.
    expect(Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON')).toBeUndefined();
  });

  it('(7) still round-trips a clean snapshot with no prototype poisoning', () => {
    const first = readCockpitSnapshot(buildSnapshot()).snapshot;
    expect(first).not.toBeNull();

    const serialized = JSON.stringify(first);
    const revived: unknown = JSON.parse(serialized);
    const second = readCockpitSnapshot(revived);

    expect(second.invalidFields).toEqual([]);
    expect(second.snapshot).toEqual(first);
  });
});

/* -------------------------------------------------------------------------
 * freezeList's descriptor never inherits accessor keys from a poisoned
 * Object.prototype (D1-46-F1)
 *
 * The descriptor object handed to `Object.defineProperty` inside `freezeList`
 * must not inherit `get`/`set` from `Object.prototype`, or `ToPropertyDescriptor`
 * would see inherited accessor keys beside the own `value`/`writable` keys and
 * throw — breaking the reader's never-throws contract. These cases genuinely
 * reach `freezeList`: an *earlier* legitimately-read scalar getter poisons the
 * realm, and every list is empty so the domain `append()` helper (a separate,
 * out-of-scope family site) never executes before `freezeList`.
 * ------------------------------------------------------------------------- */

describe('freezeList descriptor is insulated from Object.prototype accessor poisoning (D1-46-F1)', () => {
  /**
   * Install one accessor key on `Object.prototype` the way a prototype-pollution
   * attacker would. The descriptor itself is given a `null` prototype so this
   * installation is immune to the very bug under test — installing `set` after
   * `get` with an ordinary literal would otherwise throw here.
   */
  function installAccessorPoison(key: 'get' | 'set'): void {
    const descriptor: PropertyDescriptor = Object.assign(Object.create(null) as object, {
      value: () => undefined,
      writable: true,
      configurable: true,
    });
    Object.defineProperty(Object.prototype, key, descriptor);
  }

  /**
   * A repository whose own `repositoryId` getter is read early in
   * `readCockpitSnapshot` and, as a side effect, installs the named accessor
   * keys on `Object.prototype`. It returns a valid id, so the snapshot — whose
   * lists are all empty — is otherwise accepted and proceeds to `freezeList([])`.
   */
  function repositoryThatPoisons(keys: readonly ('get' | 'set')[]): Record<string, unknown> {
    const repository: Record<string, unknown> = { ...buildRepository() };
    delete repository.repositoryId;
    Object.defineProperty(repository, 'repositoryId', {
      enumerable: true,
      configurable: true,
      get() {
        for (const key of keys) {
          installAccessorPoison(key);
        }
        return REPO_A;
      },
    });
    return repository;
  }

  /** A snapshot whose lists are all empty, keeping `append()` off the path. */
  function emptyListSnapshot(repository: object) {
    return buildSnapshot({
      repository: repository as never,
      pullRequests: [],
      evidence: [],
      findings: [],
      repairJobs: [],
    });
  }

  /**
   * Run `body`, then restore `Object.prototype.get`/`.set` no matter how it
   * resolves. The restore must run *before* any assertion executes: while a
   * hostile accessor key is installed, the test runner's own descriptor-building
   * machinery would itself throw, so the poison window is confined to `body`.
   */
  function withAccessorRestore<T>(body: () => T): T {
    const saved: Record<string, PropertyDescriptor | undefined> = {
      get: Object.getOwnPropertyDescriptor(Object.prototype, 'get'),
      set: Object.getOwnPropertyDescriptor(Object.prototype, 'set'),
    };
    try {
      return body();
    } finally {
      for (const key of ['get', 'set'] as const) {
        const descriptor = saved[key];
        if (descriptor === undefined) {
          Reflect.deleteProperty(Object.prototype, key);
        } else {
          Object.defineProperty(Object.prototype, key, descriptor);
        }
      }
    }
  }

  /**
   * Read an empty-list snapshot while the given accessor keys are installed,
   * restoring the realm before returning so the caller can assert safely. On
   * the base implementation this throws inside `freezeList`; on the candidate it
   * returns a normal result.
   */
  function readUnderPoison(keys: readonly ('get' | 'set')[]) {
    return withAccessorRestore(() =>
      readCockpitSnapshot(emptyListSnapshot(repositoryThatPoisons(keys))),
    );
  }

  /** Assert totality (1–3) and returned list shape (5–7) under the poison. */
  function expectTotalUnderPoison(keys: readonly ('get' | 'set')[]): void {
    const result = readUnderPoison(keys);

    // The realm is clean again for every later assertion and test.
    expect(Object.getOwnPropertyDescriptor(Object.prototype, 'get')).toBeUndefined();
    expect(Object.getOwnPropertyDescriptor(Object.prototype, 'set')).toBeUndefined();

    // Totality: freezeList was reached under the poison and did not throw.
    expect(result.invalidFields).toEqual([]);
    const snapshot = result.snapshot;
    expect(snapshot).not.toBeNull();
    if (snapshot === null) {
      return;
    }

    for (const list of [
      snapshot.pullRequests,
      snapshot.evidence,
      snapshot.findings,
      snapshot.repairJobs,
    ]) {
      // (5) still a real array, (6) still frozen.
      expect(Array.isArray(list)).toBe(true);
      expect(Object.isFrozen(list)).toBe(true);
      // (7) the own inert non-enumerable toJSON shadow is unchanged.
      expect(Object.getOwnPropertyDescriptor(list, 'toJSON')).toEqual({
        value: undefined,
        enumerable: false,
        writable: false,
        configurable: false,
      });
    }
  }

  it('(1) returns normally when an earlier scalar getter installs Object.prototype.get', () => {
    expectTotalUnderPoison(['get']);
  });

  it('(2) returns normally when an earlier scalar getter installs Object.prototype.set', () => {
    expectTotalUnderPoison(['set']);
  });

  it('(3) returns normally when an earlier scalar getter installs both get and set', () => {
    expectTotalUnderPoison(['get', 'set']);
  });

  it('(4) restores Object.prototype.get/set even when the body throws', () => {
    expect(() =>
      withAccessorRestore(() => {
        installAccessorPoison('get');
        installAccessorPoison('set');
        throw new Error('simulated failure');
      }),
    ).toThrow('simulated failure');

    expect(Object.getOwnPropertyDescriptor(Object.prototype, 'get')).toBeUndefined();
    expect(Object.getOwnPropertyDescriptor(Object.prototype, 'set')).toBeUndefined();
  });

  it('(8) preserves the D1-44-F2 toJSON shadow so a poisoned inherited toJSON is never serialized', () => {
    const savedToJSON = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
    let poisonInvoked = false;
    const POISON_MARKER = '__d1_46_toJSON_marker__';

    try {
      const snapshot = readCockpitSnapshot(emptyListSnapshot(buildRepository())).snapshot;
      expect(snapshot).not.toBeNull();
      if (snapshot === null) {
        return;
      }

      Object.defineProperty(Object.prototype, 'toJSON', {
        configurable: true,
        enumerable: false,
        writable: true,
        value() {
          poisonInvoked = true;
          return POISON_MARKER;
        },
      });

      for (const list of [
        snapshot.pullRequests,
        snapshot.evidence,
        snapshot.findings,
        snapshot.repairJobs,
      ]) {
        const serialized = JSON.stringify(list);
        expect(serialized).toBe('[]');
        expect(serialized).not.toContain(POISON_MARKER);
      }
      expect(poisonInvoked).toBe(false);
    } finally {
      if (savedToJSON) {
        Object.defineProperty(Object.prototype, 'toJSON', savedToJSON);
      } else {
        delete (Object.prototype as { toJSON?: unknown }).toJSON;
      }
    }

    expect(Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON')).toBeUndefined();
  });

  it('(9) leaves clean input behaviour unchanged', () => {
    const result = readCockpitSnapshot(buildSnapshot());
    expect(result.invalidFields).toEqual([]);
    expect(result.snapshot).not.toBeNull();
  });
});

/* -------------------------------------------------------------------------
 * Cockpit list/invalidFields appends never inherit accessor keys from a
 * poisoned Object.prototype (D1-44-F3)
 *
 * `readCockpitList` appends every accepted element, and `readCockpitSnapshot`
 * appends every invalid field name. Both run on the reader's never-throws
 * path. If an earlier accepted getter has installed `Object.prototype.get`/
 * `.set`, an ordinary prototype-inheriting append descriptor would make
 * `Object.defineProperty`'s `ToPropertyDescriptor` observe inherited accessor
 * keys beside the own `value`/`writable` keys, reject the mixed descriptor,
 * and throw. These cases reach the append path that D1-46-F1's `freezeList`
 * hardening does not cover: a *non-empty* list (freezeList's own regression
 * used only empty lists) and the `invalidFields` collection. The Cockpit-local
 * append gives its descriptor a `null` prototype before `Object.defineProperty`
 * consumes it, the same insulation `freezeList` uses.
 * ------------------------------------------------------------------------- */

describe('Cockpit append is insulated from Object.prototype accessor poisoning (D1-44-F3)', () => {
  type AccessorKey = 'get' | 'set';

  /**
   * Install one accessor key on `Object.prototype` the way a prototype-pollution
   * attacker would. The installer's own descriptor has a `null` prototype so it
   * is immune to the very bug under test.
   */
  function installAccessorPoison(key: AccessorKey): void {
    const descriptor: PropertyDescriptor = Object.assign(Object.create(null) as object, {
      value: () => undefined,
      writable: true,
      configurable: true,
    });
    Object.defineProperty(Object.prototype, key, descriptor);
  }

  /**
   * Run `body`, then restore `Object.prototype.get`/`.set` to their exact
   * pre-test descriptors (or absence) no matter how it resolves, before any
   * later assertion or test observes the realm.
   */
  function withAccessorRestore<T>(body: () => T): T {
    const saved: Record<AccessorKey, PropertyDescriptor | undefined> = {
      get: Object.getOwnPropertyDescriptor(Object.prototype, 'get'),
      set: Object.getOwnPropertyDescriptor(Object.prototype, 'set'),
    };
    try {
      return body();
    } finally {
      for (const key of ['get', 'set'] as const) {
        const descriptor = saved[key];
        if (descriptor === undefined) {
          Reflect.deleteProperty(Object.prototype, key);
        } else {
          Object.defineProperty(Object.prototype, key, descriptor);
        }
      }
    }
  }

  /**
   * A repository whose own `repositoryId` getter installs the named accessor
   * keys on `Object.prototype` as a side effect, then returns a valid id so the
   * snapshot proceeds into the append paths. With `validId: false` it returns an
   * invalid id, forcing the `repository.repositoryId` invalidFields append to
   * run under the poison instead.
   */
  function repositoryThatPoisons(
    keys: readonly AccessorKey[],
    validId = true,
  ): Record<string, unknown> {
    const repository: Record<string, unknown> = { ...buildRepository() };
    delete repository.repositoryId;
    Object.defineProperty(repository, 'repositoryId', {
      enumerable: true,
      configurable: true,
      get() {
        for (const key of keys) {
          installAccessorPoison(key);
        }
        return validId ? REPO_A : '';
      },
    });
    return repository;
  }

  /** A snapshot with one valid pull request, so the list append is reached. */
  function nonEmptyListSnapshot(repository: object) {
    return buildSnapshot({
      repository: repository as never,
      pullRequests: [buildPullRequest()],
      evidence: [],
      findings: [],
      repairJobs: [],
    });
  }

  function expectRealmClean(): void {
    expect(Object.getOwnPropertyDescriptor(Object.prototype, 'get')).toBeUndefined();
    expect(Object.getOwnPropertyDescriptor(Object.prototype, 'set')).toBeUndefined();
  }

  /** Assert totality and returned list shape when a non-empty list is appended under poison. */
  function expectListAppendTotalUnderPoison(keys: readonly AccessorKey[]): void {
    const result = withAccessorRestore(() =>
      readCockpitSnapshot(nonEmptyListSnapshot(repositoryThatPoisons(keys))),
    );

    // The realm is clean again for every later assertion and test.
    expectRealmClean();

    // Totality: the non-empty-list append was reached under poison and did not throw.
    expect(result.invalidFields).toEqual([]);
    const snapshot = result.snapshot;
    expect(snapshot).not.toBeNull();
    if (snapshot === null) {
      return;
    }
    const list = snapshot.pullRequests;
    expect(Array.isArray(list)).toBe(true);
    expect(Object.isFrozen(list)).toBe(true);
    expect(list.length).toBe(1);
    expect(list[0]?.pullRequestId).toBe('42');
  }

  it('(1) returns normally when get is poisoned before a non-empty list append', () => {
    expectListAppendTotalUnderPoison(['get']);
  });

  it('(2) returns normally when set is poisoned before a non-empty list append', () => {
    expectListAppendTotalUnderPoison(['set']);
  });

  it('(3) returns normally when get and set are poisoned before a non-empty list append', () => {
    expectListAppendTotalUnderPoison(['get', 'set']);
  });

  it('(4) returns normally when poison precedes an invalidFields append', () => {
    // The repositoryId getter installs the poison and then returns an invalid id,
    // so `append(invalidFields, 'repository.repositoryId')` runs under the poison.
    const result = withAccessorRestore(() =>
      readCockpitSnapshot(nonEmptyListSnapshot(repositoryThatPoisons(['get', 'set'], false))),
    );
    expectRealmClean();
    expect(result.snapshot).toBeNull();
    expect(result.invalidFields).toContain('repository.repositoryId');
  });

  it('(5) preserves append descriptor semantics on appended list elements', () => {
    // A cleanly accepted snapshot: the appended element must be an own, enumerable
    // data property carrying the value. `writable`/`configurable` are `true` at
    // append time (as in the shared helper) and then sealed by the accepted
    // snapshot's mandatory freeze — the same lifecycle as before this repair.
    const result = readCockpitSnapshot(
      buildSnapshot({
        pullRequests: [buildPullRequest()],
        evidence: [],
        findings: [],
        repairJobs: [],
      }),
    );
    const list = result.snapshot?.pullRequests;
    expect(list).toBeDefined();
    if (!list) {
      return;
    }
    expect(Object.prototype.hasOwnProperty.call(list, 0)).toBe(true);
    const descriptor = Object.getOwnPropertyDescriptor(list, 0);
    expect(descriptor).toBeDefined();
    expect(descriptor?.enumerable).toBe(true);
    expect((descriptor?.value as { pullRequestId: string }).pullRequestId).toBe('42');
    // Sealed by the accepted-snapshot freeze.
    expect(descriptor?.writable).toBe(false);
    expect(descriptor?.configurable).toBe(false);
  });

  it('(6) returns real, indexable, iterable, mappable, frozen Cockpit lists', () => {
    const result = readCockpitSnapshot(
      buildSnapshot({
        pullRequests: [buildPullRequest(), buildPullRequest({ pullRequestId: '43' })],
        evidence: [],
        findings: [],
        repairJobs: [],
      }),
    );
    const list = result.snapshot?.pullRequests;
    expect(list).toBeDefined();
    if (!list) {
      return;
    }
    expect(Array.isArray(list)).toBe(true);
    expect(Object.isFrozen(list)).toBe(true);
    expect(list[0]?.pullRequestId).toBe('42');
    expect([...list].length).toBe(2);
    expect(list.map((pullRequest) => pullRequest.pullRequestId)).toEqual(['42', '43']);
  });

  it('(7) leaves clean, non-empty input behaviour unchanged', () => {
    const result = readCockpitSnapshot(buildSnapshot());
    expect(result.invalidFields).toEqual([]);
    expect(result.snapshot).not.toBeNull();
    expect(result.snapshot?.pullRequests.length).toBe(1);
  });
});

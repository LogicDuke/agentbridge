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

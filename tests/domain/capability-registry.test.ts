import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { INVOCATION_PURPOSES, type InvocationPurpose } from '../../src/domain/agent-invocation.js';
import {
  CAPABILITY_APPROVAL_STATE,
  CAPABILITY_APPROVAL_STATES,
  CAPABILITY_ELIGIBILITY_REASON,
  CAPABILITY_ELIGIBILITY_REASONS,
  CAPABILITY_REGISTRY_BOUNDS,
  evaluateCapabilityEligibility,
  type CapabilityEligibility,
  type CapabilityQuery,
  type CapabilityRegistryVersion,
} from '../../src/domain/capability-registry.js';

/**
 * Pure capability-registry evaluator.
 *
 * The invariant under test: no `(providerId, agentId)` pair is eligible for a
 * purpose unless one pinned registry version holds exactly one entry for that
 * exact pair, in state `APPROVED`, whose explicit canonical purpose set
 * contains exactly that purpose. Every other input, shape, or hostile trick
 * must produce a refusal, and no input at all may produce a throw.
 */

const MODULE_PATH = fileURLToPath(
  new URL('../../src/domain/capability-registry.ts', import.meta.url),
);
const MODULE_SOURCE = readFileSync(MODULE_PATH, 'utf8');

const REASON = CAPABILITY_ELIGIBILITY_REASON;
const STATE = CAPABILITY_APPROVAL_STATE;

const PROVIDER = 'provider-alpha';
const AGENT = 'agent-one';
const VERSION = 'registry-version-0001';
/** One character past `INVOCATION_BOUNDS.MAX_IDENTIFIER_LENGTH`. */
const OVERSIZED = 'x'.repeat(257);

/** Call the evaluator with deliberately hostile, off-contract input. */
function evaluate(registry: unknown, query: unknown): CapabilityEligibility {
  return evaluateCapabilityEligibility(
    registry as CapabilityRegistryVersion,
    query as CapabilityQuery,
  );
}

function approvedEntry(
  providerId: string,
  agentId: string,
  purposes: readonly unknown[],
): unknown {
  return { providerId, agentId, approvedPurposes: purposes, approvalState: STATE.APPROVED };
}

function versionOf(entries: readonly unknown[], registryVersion = VERSION): unknown {
  return { registryVersion, entries };
}

function queryOf(
  providerId: string,
  agentId: string,
  purpose: InvocationPurpose = 'review',
): unknown {
  return { providerId, agentId, purpose };
}

/** A registry with one APPROVED pair admitted for `review` only. */
function baselineRegistry(): unknown {
  return versionOf([approvedEntry(PROVIDER, AGENT, ['review'])]);
}

/** A handler whose every consulted trap throws. */
function hostileProxy(target: object): object {
  const trap = (): never => {
    throw new Error('hostile trap');
  };
  return new Proxy(target, {
    get: trap,
    has: trap,
    getOwnPropertyDescriptor: trap,
    ownKeys: trap,
  });
}

describe('happy path', () => {
  it('admits an exact pair whose approved purpose set contains the purpose', () => {
    const result = evaluate(baselineRegistry(), queryOf(PROVIDER, AGENT, 'review'));

    expect(result).toStrictEqual({
      eligible: true,
      reason: REASON.ELIGIBLE,
      registryVersion: VERSION,
      providerId: PROVIDER,
      agentId: AGENT,
      purpose: 'review',
    });
  });

  it('resolves the correct entry out of a multi-entry version', () => {
    const registry = versionOf([
      approvedEntry('provider-beta', 'agent-two', ['implement']),
      approvedEntry(PROVIDER, AGENT, ['review']),
      approvedEntry('provider-gamma', 'agent-three', ['audit']),
    ]);

    expect(evaluate(registry, queryOf('provider-beta', 'agent-two', 'implement')).reason).toBe(
      REASON.ELIGIBLE,
    );
    expect(evaluate(registry, queryOf(PROVIDER, AGENT, 'review')).reason).toBe(REASON.ELIGIBLE);
    expect(evaluate(registry, queryOf('provider-gamma', 'agent-three', 'audit')).reason).toBe(
      REASON.ELIGIBLE,
    );
    // Cross-pairing the same providers and agents admits nothing.
    expect(evaluate(registry, queryOf('provider-beta', AGENT, 'implement')).reason).toBe(
      REASON.PAIR_NOT_APPROVED,
    );
  });

  it('admits every purpose listed on a multi-purpose entry, and no other', () => {
    const registry = versionOf([approvedEntry(PROVIDER, AGENT, ['review', 'repair'])]);

    expect(evaluate(registry, queryOf(PROVIDER, AGENT, 'review')).reason).toBe(REASON.ELIGIBLE);
    expect(evaluate(registry, queryOf(PROVIDER, AGENT, 'repair')).reason).toBe(REASON.ELIGIBLE);
    expect(evaluate(registry, queryOf(PROVIDER, AGENT, 'implement')).reason).toBe(
      REASON.PURPOSE_NOT_APPROVED,
    );
    expect(evaluate(registry, queryOf(PROVIDER, AGENT, 'audit')).reason).toBe(
      REASON.PURPOSE_NOT_APPROVED,
    );
  });
});

describe('negative verdicts', () => {
  it('refuses a pair that has no entry', () => {
    expect(evaluate(baselineRegistry(), queryOf('provider-other', 'agent-other')).reason).toBe(
      REASON.PAIR_NOT_APPROVED,
    );
  });

  it('refuses the right provider with the wrong agent', () => {
    expect(evaluate(baselineRegistry(), queryOf(PROVIDER, 'agent-other')).reason).toBe(
      REASON.PAIR_NOT_APPROVED,
    );
  });

  it('refuses the right agent under the wrong provider', () => {
    expect(evaluate(baselineRegistry(), queryOf('provider-other', AGENT)).reason).toBe(
      REASON.PAIR_NOT_APPROVED,
    );
  });

  it('refuses a suspended pair', () => {
    const registry = versionOf([
      {
        providerId: PROVIDER,
        agentId: AGENT,
        approvedPurposes: ['review'],
        approvalState: STATE.SUSPENDED,
      },
    ]);

    expect(evaluate(registry, queryOf(PROVIDER, AGENT, 'review')).reason).toBe(
      REASON.PAIR_SUSPENDED,
    );
  });

  it('refuses a withdrawn pair', () => {
    const registry = versionOf([
      {
        providerId: PROVIDER,
        agentId: AGENT,
        approvedPurposes: ['review'],
        approvalState: STATE.WITHDRAWN,
      },
    ]);

    expect(evaluate(registry, queryOf(PROVIDER, AGENT, 'review')).reason).toBe(
      REASON.PAIR_WITHDRAWN,
    );
  });

  it('refuses an approved pair for a purpose outside its explicit set', () => {
    const result = evaluate(baselineRegistry(), queryOf(PROVIDER, AGENT, 'audit'));

    expect(result.reason).toBe(REASON.PURPOSE_NOT_APPROVED);
    expect(result.eligible).toBe(false);
    expect(result.purpose).toBe('audit');
  });

  it('reports pair state before purpose, so a suspended pair is never a purpose problem', () => {
    const registry = versionOf([
      {
        providerId: PROVIDER,
        agentId: AGENT,
        approvedPurposes: ['review', 'repair'],
        approvalState: STATE.SUSPENDED,
      },
    ]);

    // The purpose *is* listed; the suspension still decides.
    expect(evaluate(registry, queryOf(PROVIDER, AGENT, 'review')).reason).toBe(
      REASON.PAIR_SUSPENDED,
    );
    expect(evaluate(registry, queryOf(PROVIDER, AGENT, 'audit')).reason).toBe(
      REASON.PAIR_SUSPENDED,
    );
  });
});

describe('query validity', () => {
  it('refuses a non-object query while still echoing a readable registry version', () => {
    for (const query of [null, undefined, 42, 'query', true, Symbol('q'), Math.max]) {
      const result = evaluate(baselineRegistry(), query);
      expect(result.reason).toBe(REASON.QUERY_INVALID);
      expect(result.registryVersion).toBe(VERSION);
      expect(result.providerId).toBeNull();
      expect(result.agentId).toBeNull();
      expect(result.purpose).toBeNull();
    }
  });

  it('refuses an array query', () => {
    expect(evaluate(baselineRegistry(), [PROVIDER, AGENT, 'review']).reason).toBe(
      REASON.QUERY_INVALID,
    );
  });

  it('refuses a blank or missing providerId', () => {
    for (const providerId of ['', '   ', undefined]) {
      const result = evaluate(baselineRegistry(), {
        providerId,
        agentId: AGENT,
        purpose: 'review',
      });
      expect(result.reason).toBe(REASON.QUERY_INVALID);
      expect(result.providerId).toBeNull();
      expect(result.agentId).toBe(AGENT);
    }
  });

  it('refuses a blank or missing agentId', () => {
    for (const agentId of ['', '\t\n', undefined]) {
      const result = evaluate(baselineRegistry(), {
        providerId: PROVIDER,
        agentId,
        purpose: 'review',
      });
      expect(result.reason).toBe(REASON.QUERY_INVALID);
      expect(result.agentId).toBeNull();
    }
  });

  it('refuses non-string identifiers', () => {
    expect(
      evaluate(baselineRegistry(), { providerId: 7, agentId: AGENT, purpose: 'review' }).reason,
    ).toBe(REASON.QUERY_INVALID);
    expect(
      evaluate(baselineRegistry(), { providerId: PROVIDER, agentId: {}, purpose: 'review' }).reason,
    ).toBe(REASON.QUERY_INVALID);
  });

  it('rejects an oversized identifier without echoing a truncated prefix', () => {
    const result = evaluate(baselineRegistry(), queryOf(OVERSIZED, AGENT));

    expect(result.reason).toBe(REASON.QUERY_INVALID);
    expect(result.providerId).toBeNull();
    expect(JSON.stringify(result)).not.toContain('xxx');
  });

  it('refuses an unknown purpose or a case variant of a known one', () => {
    for (const purpose of ['REVIEW', 'Review', 'review ', 'deploy', '', undefined, 3]) {
      const result = evaluate(baselineRegistry(), {
        providerId: PROVIDER,
        agentId: AGENT,
        purpose,
      });
      expect(result.reason).toBe(REASON.QUERY_INVALID);
      expect(result.purpose).toBeNull();
    }
  });
});

describe('registry unreadable', () => {
  it('refuses a non-object registry and echoes nothing about it', () => {
    for (const registry of [null, undefined, 0, 'v1', false, Symbol('r'), Math.max]) {
      const result = evaluate(registry, queryOf(PROVIDER, AGENT));
      expect(result.reason).toBe(REASON.REGISTRY_UNREADABLE);
      expect(result.registryVersion).toBeNull();
      expect(result.providerId).toBeNull();
      expect(result.agentId).toBeNull();
      expect(result.purpose).toBeNull();
    }
  });

  it('refuses an array registry', () => {
    expect(evaluate([], queryOf(PROVIDER, AGENT)).reason).toBe(REASON.REGISTRY_UNREADABLE);
    expect(
      evaluate([approvedEntry(PROVIDER, AGENT, ['review'])], queryOf(PROVIDER, AGENT)).reason,
    ).toBe(REASON.REGISTRY_UNREADABLE);
  });

  it('refuses a missing, blank, non-string, or oversized registryVersion', () => {
    for (const registryVersion of [undefined, '', '  ', 1, {}, OVERSIZED]) {
      const result = evaluate({ registryVersion, entries: [] }, queryOf(PROVIDER, AGENT));
      expect(result.reason).toBe(REASON.REGISTRY_UNREADABLE);
      expect(result.registryVersion).toBeNull();
    }
  });

  it('refuses missing entries or entries that are not an array', () => {
    for (const entries of [undefined, null, {}, 'entries', 3, new Set()]) {
      expect(evaluate({ registryVersion: VERSION, entries }, queryOf(PROVIDER, AGENT)).reason).toBe(
        REASON.REGISTRY_UNREADABLE,
      );
    }
  });

  it('refuses without throwing when registryVersion or entries throws on read', () => {
    const throwingVersion = {
      get registryVersion(): string {
        throw new Error('hostile getter');
      },
      entries: [],
    };
    const throwingEntries = {
      registryVersion: VERSION,
      get entries(): readonly unknown[] {
        throw new Error('hostile getter');
      },
    };

    expect(() => evaluate(throwingVersion, queryOf(PROVIDER, AGENT))).not.toThrow();
    expect(evaluate(throwingVersion, queryOf(PROVIDER, AGENT)).reason).toBe(
      REASON.REGISTRY_UNREADABLE,
    );
    expect(evaluate(throwingEntries, queryOf(PROVIDER, AGENT)).reason).toBe(
      REASON.REGISTRY_UNREADABLE,
    );
  });

  it('refuses when the entries array lies about or throws on length', () => {
    const trapped = hostileProxy([]);
    expect(
      evaluate({ registryVersion: VERSION, entries: trapped }, queryOf(PROVIDER, AGENT)).reason,
    ).toBe(REASON.REGISTRY_UNREADABLE);
  });
});

describe('registry invalid', () => {
  function expectInvalid(entry: unknown): void {
    const result = evaluate(versionOf([entry]), queryOf(PROVIDER, AGENT));
    expect(result.reason).toBe(REASON.REGISTRY_INVALID);
    expect(result.registryVersion).toBe(VERSION);
  }

  it('refuses a malformed entry: non-object, null, array, or missing field', () => {
    for (const entry of [null, undefined, 'entry', 7, [], Math.max]) {
      expectInvalid(entry);
    }
    expectInvalid({ agentId: AGENT, approvedPurposes: ['review'], approvalState: STATE.APPROVED });
    expectInvalid({
      providerId: PROVIDER,
      approvedPurposes: ['review'],
      approvalState: STATE.APPROVED,
    });
    expectInvalid({ providerId: PROVIDER, agentId: AGENT, approvalState: STATE.APPROVED });
    expectInvalid({ providerId: PROVIDER, agentId: AGENT, approvedPurposes: ['review'] });
    expectInvalid({
      providerId: '',
      agentId: AGENT,
      approvedPurposes: ['review'],
      approvalState: STATE.APPROVED,
    });
    expectInvalid(approvedEntry(PROVIDER, OVERSIZED, ['review']));
  });

  it('refuses an unknown or case-variant approval state', () => {
    for (const approvalState of ['approved', 'Approved', 'PENDING', 'APPROVED ', 'active']) {
      expectInvalid({
        providerId: PROVIDER,
        agentId: AGENT,
        approvedPurposes: ['review'],
        approvalState,
      });
    }
  });

  it('refuses a non-string approval state', () => {
    for (const approvalState of [undefined, null, 1, {}, true]) {
      expectInvalid({
        providerId: PROVIDER,
        agentId: AGENT,
        approvedPurposes: ['review'],
        approvalState,
      });
    }
  });

  it('refuses an unknown purpose inside an entry purpose set', () => {
    expectInvalid(approvedEntry(PROVIDER, AGENT, ['review', 'deploy']));
    expectInvalid(approvedEntry(PROVIDER, AGENT, ['REVIEW']));
    expectInvalid(approvedEntry(PROVIDER, AGENT, [7]));
  });

  it('refuses a duplicate purpose in one entry', () => {
    expectInvalid(approvedEntry(PROVIDER, AGENT, ['review', 'review']));
  });

  it('refuses an empty purpose set regardless of approval state', () => {
    for (const approvalState of [STATE.APPROVED, STATE.SUSPENDED, STATE.WITHDRAWN]) {
      expectInvalid({ providerId: PROVIDER, agentId: AGENT, approvedPurposes: [], approvalState });
    }
  });

  it('refuses an approvedPurposes that is not an array', () => {
    for (const approvedPurposes of ['review', { 0: 'review', length: 1 }, null, 1]) {
      expectInvalid({
        providerId: PROVIDER,
        agentId: AGENT,
        approvedPurposes,
        approvalState: STATE.APPROVED,
      });
    }
  });

  it('refuses a purpose set that is not in canonical declaration order', () => {
    expect(INVOCATION_PURPOSES).toStrictEqual(['review', 'implement', 'repair', 'audit']);
    expectInvalid(approvedEntry(PROVIDER, AGENT, ['implement', 'review']));
    expectInvalid(approvedEntry(PROVIDER, AGENT, ['audit', 'review']));
    // The same members in canonical order are accepted.
    expect(
      evaluate(
        versionOf([approvedEntry(PROVIDER, AGENT, ['review', 'implement'])]),
        queryOf(PROVIDER, AGENT, 'implement'),
      ).reason,
    ).toBe(REASON.ELIGIBLE);
  });

  it('refuses a duplicated pair even when the query names an unrelated pair', () => {
    const registry = versionOf([
      approvedEntry(PROVIDER, AGENT, ['review']),
      approvedEntry(PROVIDER, AGENT, ['audit']),
      approvedEntry('provider-beta', 'agent-two', ['review']),
    ]);

    expect(evaluate(registry, queryOf('provider-beta', 'agent-two', 'review')).reason).toBe(
      REASON.REGISTRY_INVALID,
    );
  });

  it('keeps pair keys unambiguous across a separator planted in an identifier', () => {
    const registry = versionOf([
      approvedEntry('a|b', 'c', ['review']),
      approvedEntry('a', 'b|c', ['audit']),
    ]);

    // Both entries coexist: they are distinct pairs, not a duplicate.
    expect(evaluate(registry, queryOf('a|b', 'c', 'review')).reason).toBe(REASON.ELIGIBLE);
    expect(evaluate(registry, queryOf('a', 'b|c', 'audit')).reason).toBe(REASON.ELIGIBLE);
    // Neither admission answers for the other pair's purpose.
    expect(evaluate(registry, queryOf('a|b', 'c', 'audit')).reason).toBe(
      REASON.PURPOSE_NOT_APPROVED,
    );
    expect(evaluate(registry, queryOf('a', 'b|c', 'review')).reason).toBe(
      REASON.PURPOSE_NOT_APPROVED,
    );
  });

  it('echoes the registry version whenever identity was readable', () => {
    const result = evaluate(versionOf([null], 'v-readable'), queryOf(PROVIDER, AGENT));

    expect(result.reason).toBe(REASON.REGISTRY_INVALID);
    expect(result.registryVersion).toBe('v-readable');
  });
});

describe('valid but empty', () => {
  it('accepts an empty entry list and admits nothing', () => {
    const result = evaluate(versionOf([]), queryOf(PROVIDER, AGENT));

    expect(result.reason).toBe(REASON.PAIR_NOT_APPROVED);
    expect(result.registryVersion).toBe(VERSION);
  });

  it('accepts a version in which every entry is withdrawn', () => {
    const registry = versionOf([
      {
        providerId: PROVIDER,
        agentId: AGENT,
        approvedPurposes: ['review'],
        approvalState: STATE.WITHDRAWN,
      },
      {
        providerId: 'provider-beta',
        agentId: 'agent-two',
        approvedPurposes: ['audit'],
        approvalState: STATE.WITHDRAWN,
      },
    ]);

    expect(evaluate(registry, queryOf(PROVIDER, AGENT, 'review')).reason).toBe(
      REASON.PAIR_WITHDRAWN,
    );
  });
});

describe('totality against hostile input', () => {
  it('fails closed when an entry field throws on read', () => {
    for (const field of ['providerId', 'agentId', 'approvedPurposes', 'approvalState']) {
      const entry: Record<string, unknown> = {
        providerId: PROVIDER,
        agentId: AGENT,
        approvedPurposes: ['review'],
        approvalState: STATE.APPROVED,
      };
      Object.defineProperty(entry, field, {
        get(): never {
          throw new Error('hostile getter');
        },
        enumerable: true,
        configurable: true,
      });

      const registry = versionOf([entry]);
      expect(() => evaluate(registry, queryOf(PROVIDER, AGENT))).not.toThrow();
      expect(evaluate(registry, queryOf(PROVIDER, AGENT)).reason).toBe(REASON.REGISTRY_INVALID);
    }
  });

  it('fails closed against a Proxy whose traps throw', () => {
    const trappedRegistry = hostileProxy({});
    expect(() => evaluate(trappedRegistry, queryOf(PROVIDER, AGENT))).not.toThrow();
    expect(evaluate(trappedRegistry, queryOf(PROVIDER, AGENT)).reason).toBe(
      REASON.REGISTRY_UNREADABLE,
    );

    const trappedEntry = versionOf([hostileProxy({})]);
    expect(() => evaluate(trappedEntry, queryOf(PROVIDER, AGENT))).not.toThrow();
    expect(evaluate(trappedEntry, queryOf(PROVIDER, AGENT)).reason).toBe(REASON.REGISTRY_INVALID);

    const trappedPurposes = versionOf([
      {
        providerId: PROVIDER,
        agentId: AGENT,
        approvedPurposes: hostileProxy([]),
        approvalState: STATE.APPROVED,
      },
    ]);
    expect(() => evaluate(trappedPurposes, queryOf(PROVIDER, AGENT))).not.toThrow();
    expect(evaluate(trappedPurposes, queryOf(PROVIDER, AGENT)).reason).toBe(
      REASON.REGISTRY_INVALID,
    );

    const trappedQuery = hostileProxy({});
    expect(() => evaluate(baselineRegistry(), trappedQuery)).not.toThrow();
    expect(evaluate(baselineRegistry(), trappedQuery).reason).toBe(REASON.QUERY_INVALID);
  });

  it('ignores prototype-planted fields on registries, entries, and queries', () => {
    const plantedRegistry: unknown = Object.create({ registryVersion: VERSION, entries: [] });
    expect(evaluate(plantedRegistry, queryOf(PROVIDER, AGENT)).reason).toBe(
      REASON.REGISTRY_UNREADABLE,
    );

    const plantedEntry: unknown = Object.create({
      providerId: PROVIDER,
      agentId: AGENT,
      approvedPurposes: ['review'],
      approvalState: STATE.APPROVED,
    });
    expect(evaluate(versionOf([plantedEntry]), queryOf(PROVIDER, AGENT)).reason).toBe(
      REASON.REGISTRY_INVALID,
    );

    const plantedQuery: unknown = Object.create({
      providerId: PROVIDER,
      agentId: AGENT,
      purpose: 'review',
    });
    expect(evaluate(baselineRegistry(), plantedQuery).reason).toBe(REASON.QUERY_INVALID);
  });

  it('reads each entry field once, so an inconsistent getter cannot validate one pair and match another', () => {
    let reads = 0;
    const entry: Record<string, unknown> = {
      agentId: AGENT,
      approvedPurposes: ['review'],
      approvalState: STATE.APPROVED,
    };
    Object.defineProperty(entry, 'providerId', {
      get(): string {
        reads += 1;
        return reads === 1 ? 'provider-first' : 'provider-second';
      },
      enumerable: true,
      configurable: true,
    });
    const registry = versionOf([entry]);

    // Only the first read exists, so only 'provider-first' can ever match.
    expect(evaluate(registry, queryOf('provider-second', AGENT, 'review')).reason).toBe(
      REASON.PAIR_NOT_APPROVED,
    );
    reads = 0;
    expect(evaluate(registry, queryOf('provider-first', AGENT, 'review')).reason).toBe(
      REASON.ELIGIBLE,
    );
    expect(reads).toBe(1);
  });

  it('survives a cyclic registry and a cyclic entry', () => {
    const cyclic: Record<string, unknown> = { registryVersion: VERSION, entries: [] };
    cyclic['self'] = cyclic;
    expect(evaluate(cyclic, queryOf(PROVIDER, AGENT)).reason).toBe(REASON.PAIR_NOT_APPROVED);

    const cyclicEntry: Record<string, unknown> = {
      providerId: PROVIDER,
      agentId: AGENT,
      approvedPurposes: ['review'],
      approvalState: STATE.APPROVED,
    };
    cyclicEntry['self'] = cyclicEntry;
    expect(evaluate(versionOf([cyclicEntry]), queryOf(PROVIDER, AGENT)).reason).toBe(
      REASON.ELIGIBLE,
    );
  });

  /**
   * Run `body`, then put back every intrinsic a poisoning entry may have
   * replaced — on any path out, so a failing assertion cannot leak a poisoned
   * `Array.prototype.push` into the rest of the suite.
   */
  function restoringIntrinsics<T>(body: () => T): T {
    /* eslint-disable @typescript-eslint/unbound-method */
    const mapGet = Map.prototype.get;
    const mapHas = Map.prototype.has;
    const mapSet = Map.prototype.set;
    const arrayIncludes = Array.prototype.includes;
    const arrayIndexOf = Array.prototype.indexOf;
    const arrayFind = Array.prototype.find;
    const arrayPush = Array.prototype.push;
    /* eslint-enable @typescript-eslint/unbound-method */
    try {
      return body();
    } finally {
      Map.prototype.get = mapGet;
      Map.prototype.has = mapHas;
      Map.prototype.set = mapSet;
      Array.prototype.includes = arrayIncludes;
      Array.prototype.indexOf = arrayIndexOf;
      Array.prototype.find = arrayFind;
      Array.prototype.push = arrayPush;
    }
  }

  /**
   * An APPROVED entry that runs `effect` mid-evaluation.
   *
   * `approvalState` is the last field the evaluator reads, so the effect lands
   * after this entry is validated and before any pair lookup happens — exactly
   * the window in which a call-time-resolved prototype method is replaceable.
   */
  function poisoningEntry(providerId: string, agentId: string, effect: () => void): unknown {
    return {
      providerId,
      agentId,
      approvedPurposes: ['review'],
      get approvalState(): string {
        effect();
        return STATE.APPROVED;
      },
    };
  }

  /** A snapshot-shaped object a poisoned container could hand back. */
  const FABRICATED = {
    providerId: 'fabricated-provider',
    agentId: 'fabricated-agent',
    approvedPurposes: ['review', 'implement', 'repair', 'audit'],
    approvalState: STATE.APPROVED,
  };

  it('refuses a fabricated entry when an entry getter repoints Map.prototype.get', () => {
    const registry = versionOf([
      poisoningEntry('other-provider', 'other-agent', () => {
        Map.prototype.get = ((): unknown => FABRICATED) as typeof Map.prototype.get;
      }),
    ]);

    const result = restoringIntrinsics(() => evaluate(registry, queryOf(PROVIDER, AGENT)));
    expect(result.reason).toBe(REASON.PAIR_NOT_APPROVED);
    expect(result.eligible).toBe(false);
    expect(() =>
      restoringIntrinsics(() => evaluate(registry, queryOf(PROVIDER, AGENT))),
    ).not.toThrow();
  });

  it('refuses a duplicate pair when an entry getter repoints Map.prototype.has', () => {
    const registry = versionOf([
      poisoningEntry(PROVIDER, AGENT, () => {
        Map.prototype.has = ((): boolean => false) as typeof Map.prototype.has;
      }),
      approvedEntry(PROVIDER, AGENT, ['review']),
    ]);

    const result = restoringIntrinsics(() => evaluate(registry, queryOf(PROVIDER, AGENT)));
    expect(result.reason).toBe(REASON.REGISTRY_INVALID);
    expect(result.eligible).toBe(false);
    expect(() =>
      restoringIntrinsics(() => evaluate(registry, queryOf(PROVIDER, AGENT))),
    ).not.toThrow();
  });

  it('returns the control verdict under broad intrinsic poisoning', () => {
    const poison = (): void => {
      Map.prototype.get = ((): unknown => FABRICATED) as typeof Map.prototype.get;
      Map.prototype.has = ((): boolean => false) as typeof Map.prototype.has;
      Map.prototype.set = (function set(this: unknown): unknown {
        return this;
      }) as typeof Map.prototype.set;
      Array.prototype.includes = ((): boolean => true) as typeof Array.prototype.includes;
      Array.prototype.indexOf = ((): number => 0) as typeof Array.prototype.indexOf;
      Array.prototype.find = ((): unknown => FABRICATED) as typeof Array.prototype.find;
      Array.prototype.push = ((): number => 0) as typeof Array.prototype.push;
    };

    const cases: readonly (readonly [string, readonly unknown[]])[] = [
      ['admitted pair', [approvedEntry(PROVIDER, AGENT, ['review'])]],
      ['absent pair', [approvedEntry('other-provider', 'other-agent', ['review'])]],
      [
        'duplicate registry',
        [approvedEntry(PROVIDER, AGENT, ['review']), approvedEntry(PROVIDER, AGENT, ['audit'])],
      ],
    ];

    for (const [name, entries] of cases) {
      // Identical registries but for what the first entry's getter does, so any
      // difference in verdict is attributable to the poisoning alone.
      const build = (effect: () => void): unknown =>
        versionOf([poisoningEntry('poison-provider', 'poison-agent', effect), ...entries]);

      const control = evaluate(
        build(() => undefined),
        queryOf(PROVIDER, AGENT),
      );
      const poisoned = restoringIntrinsics(() => evaluate(build(poison), queryOf(PROVIDER, AGENT)));

      expect({ name, ...poisoned }).toStrictEqual({ name, ...control });
    }
  });

  it('reaches every declared reason', () => {
    const reached = new Set<string>([
      evaluate(null, queryOf(PROVIDER, AGENT)).reason,
      evaluate(versionOf([null]), queryOf(PROVIDER, AGENT)).reason,
      evaluate(baselineRegistry(), null).reason,
      evaluate(baselineRegistry(), queryOf('nope', 'nope')).reason,
      evaluate(
        versionOf([
          {
            providerId: PROVIDER,
            agentId: AGENT,
            approvedPurposes: ['review'],
            approvalState: STATE.SUSPENDED,
          },
        ]),
        queryOf(PROVIDER, AGENT),
      ).reason,
      evaluate(
        versionOf([
          {
            providerId: PROVIDER,
            agentId: AGENT,
            approvedPurposes: ['review'],
            approvalState: STATE.WITHDRAWN,
          },
        ]),
        queryOf(PROVIDER, AGENT),
      ).reason,
      evaluate(baselineRegistry(), queryOf(PROVIDER, AGENT, 'audit')).reason,
      evaluate(baselineRegistry(), queryOf(PROVIDER, AGENT, 'review')).reason,
    ]);

    expect([...reached].sort()).toStrictEqual([...CAPABILITY_ELIGIBILITY_REASONS].sort());
  });

  it('exposes exact frozen vocabularies', () => {
    expect(CAPABILITY_APPROVAL_STATE).toStrictEqual({
      APPROVED: 'APPROVED',
      SUSPENDED: 'SUSPENDED',
      WITHDRAWN: 'WITHDRAWN',
    });
    expect(CAPABILITY_APPROVAL_STATES).toStrictEqual(['APPROVED', 'SUSPENDED', 'WITHDRAWN']);
    expect(CAPABILITY_ELIGIBILITY_REASONS).toHaveLength(8);
    expect([...CAPABILITY_ELIGIBILITY_REASONS].sort()).toStrictEqual(
      Object.values(CAPABILITY_ELIGIBILITY_REASON).sort(),
    );
    expect(Object.isFrozen(CAPABILITY_APPROVAL_STATE)).toBe(true);
    expect(Object.isFrozen(CAPABILITY_APPROVAL_STATES)).toBe(true);
    expect(Object.isFrozen(CAPABILITY_ELIGIBILITY_REASON)).toBe(true);
    expect(Object.isFrozen(CAPABILITY_ELIGIBILITY_REASONS)).toBe(true);
  });

  it('returns a frozen, JSON-stable result whose eligible flag tracks the reason', () => {
    const results = [
      evaluate(null, null),
      evaluate(baselineRegistry(), null),
      evaluate(versionOf([null]), queryOf(PROVIDER, AGENT)),
      evaluate(baselineRegistry(), queryOf(PROVIDER, AGENT, 'audit')),
      evaluate(baselineRegistry(), queryOf(PROVIDER, AGENT, 'review')),
    ];

    for (const result of results) {
      expect(Object.isFrozen(result)).toBe(true);
      expect(result.eligible).toBe(result.reason === REASON.ELIGIBLE);
      expect(JSON.parse(JSON.stringify(result))).toStrictEqual({
        eligible: result.eligible,
        reason: result.reason,
        registryVersion: result.registryVersion,
        providerId: result.providerId,
        agentId: result.agentId,
        purpose: result.purpose,
      });
    }
  });
});

describe('entry-count bound', () => {
  /** `count` unique APPROVED entries, none of which is the queried pair. */
  function filler(count: number): unknown[] {
    const entries: unknown[] = [];
    for (let index = 0; index < count; index += 1) {
      entries.push(approvedEntry(`filler-provider-${String(index)}`, AGENT, ['review']));
    }
    return entries;
  }

  it('refuses an entries list that reports an enormous length, in constant time', () => {
    // A real array cannot lie about its length; a Proxy can, and can synthesise
    // a fresh valid entry per index. Walking it would never return.
    const entries = new Proxy([] as unknown[], {
      getOwnPropertyDescriptor: (_target, key) =>
        key === 'length'
          ? { value: 2 ** 31, writable: true, enumerable: false, configurable: false }
          : { value: undefined, writable: true, enumerable: true, configurable: true },
      get: (_target, key) =>
        key === 'length'
          ? 2 ** 31
          : approvedEntry(`synthetic-provider-${String(key)}`, AGENT, ['review']),
    });
    const registry = { registryVersion: VERSION, entries };

    const startedAt = Date.now();
    const result = evaluate(registry, queryOf(PROVIDER, AGENT));
    const elapsed = Date.now() - startedAt;

    expect(() => evaluate(registry, queryOf(PROVIDER, AGENT))).not.toThrow();
    expect(result.reason).toBe(REASON.REGISTRY_INVALID);
    expect(result.eligible).toBe(false);
    expect(result.registryVersion).toBe(VERSION);
    expect(elapsed).toBeLessThan(1_000);
  });

  it('evaluates a registry holding exactly MAX_ENTRIES entries', () => {
    const entries = filler(CAPABILITY_REGISTRY_BOUNDS.MAX_ENTRIES - 1);
    entries.push(approvedEntry(PROVIDER, AGENT, ['review']));
    expect(entries).toHaveLength(CAPABILITY_REGISTRY_BOUNDS.MAX_ENTRIES);

    expect(evaluate(versionOf(entries), queryOf(PROVIDER, AGENT)).reason).toBe(REASON.ELIGIBLE);
  });

  it('refuses a registry holding one entry more than MAX_ENTRIES', () => {
    const entries = filler(CAPABILITY_REGISTRY_BOUNDS.MAX_ENTRIES);
    entries.push(approvedEntry(PROVIDER, AGENT, ['review']));
    expect(entries).toHaveLength(CAPABILITY_REGISTRY_BOUNDS.MAX_ENTRIES + 1);

    const result = evaluate(versionOf(entries), queryOf(PROVIDER, AGENT));
    expect(result.reason).toBe(REASON.REGISTRY_INVALID);
    expect(result.eligible).toBe(false);
    // Identity was readable, so it is echoed: this is malformed content, not an
    // unreadable registry.
    expect(result.registryVersion).toBe(VERSION);
  });

  it('refuses an oversized registry before reading a single entry', () => {
    let touched = false;
    const entries: unknown[] = [
      {
        get providerId(): string {
          touched = true;
          return PROVIDER;
        },
        agentId: AGENT,
        approvedPurposes: ['review'],
        approvalState: STATE.APPROVED,
      },
      ...filler(CAPABILITY_REGISTRY_BOUNDS.MAX_ENTRIES),
    ];
    expect(entries).toHaveLength(CAPABILITY_REGISTRY_BOUNDS.MAX_ENTRIES + 1);

    expect(evaluate(versionOf(entries), queryOf(PROVIDER, AGENT)).reason).toBe(
      REASON.REGISTRY_INVALID,
    );
    expect(touched).toBe(false);
  });

  it('leaves an empty and an all-withdrawn version valid', () => {
    expect(evaluate(versionOf([]), queryOf(PROVIDER, AGENT)).reason).toBe(
      REASON.PAIR_NOT_APPROVED,
    );

    const withdrawn = versionOf([
      {
        providerId: PROVIDER,
        agentId: AGENT,
        approvedPurposes: ['review'],
        approvalState: STATE.WITHDRAWN,
      },
    ]);
    expect(evaluate(withdrawn, queryOf(PROVIDER, AGENT)).reason).toBe(REASON.PAIR_WITHDRAWN);
  });
});

describe('no mutation', () => {
  it('leaves the registry version and query untouched', () => {
    const registry = versionOf([
      approvedEntry(PROVIDER, AGENT, ['review', 'audit']),
      approvedEntry('provider-beta', 'agent-two', ['implement']),
    ]);
    const query = queryOf(PROVIDER, AGENT, 'review');
    const registryBefore = JSON.stringify(registry);
    const queryBefore = JSON.stringify(query);

    expect(evaluate(registry, query).reason).toBe(REASON.ELIGIBLE);

    expect(JSON.stringify(registry)).toBe(registryBefore);
    expect(JSON.stringify(query)).toBe(queryBefore);
  });

  it('evaluates deeply frozen inputs without throwing', () => {
    const purposes = Object.freeze(['review']);
    const entry = Object.freeze({
      providerId: PROVIDER,
      agentId: AGENT,
      approvedPurposes: purposes,
      approvalState: STATE.APPROVED,
    });
    const registry = Object.freeze({
      registryVersion: VERSION,
      entries: Object.freeze([entry]),
    });
    const query = Object.freeze({ providerId: PROVIDER, agentId: AGENT, purpose: 'review' });

    expect(() => evaluate(registry, query)).not.toThrow();
    expect(evaluate(registry, query).reason).toBe(REASON.ELIGIBLE);
  });
});

describe('structural prohibitions', () => {
  it('grants no provider-level, agent-level, or wildcard approval', () => {
    const registry = versionOf([
      approvedEntry(PROVIDER, '*', ['review']),
      approvedEntry('*', AGENT, ['review']),
    ]);

    expect(evaluate(registry, queryOf(PROVIDER, AGENT, 'review')).reason).toBe(
      REASON.PAIR_NOT_APPROVED,
    );
    expect(evaluate(registry, queryOf(PROVIDER, 'agent-other', 'review')).reason).toBe(
      REASON.PAIR_NOT_APPROVED,
    );
    expect(evaluate(registry, queryOf('provider-other', AGENT, 'review')).reason).toBe(
      REASON.PAIR_NOT_APPROVED,
    );
    // The wildcard string is only ever an exact identifier, never a pattern.
    expect(evaluate(registry, queryOf(PROVIDER, '*', 'review')).reason).toBe(REASON.ELIGIBLE);
  });

  it('treats registryVersion as an opaque label, resolving nothing', () => {
    for (const label of ['latest', 'default', 'HEAD', 'current']) {
      const result = evaluate(versionOf([], label), queryOf(PROVIDER, AGENT));
      expect(result.registryVersion).toBe(label);
      expect(result.reason).toBe(REASON.PAIR_NOT_APPROVED);
    }
  });

  it('echoes each version identity verbatim without cross-version resolution', () => {
    const entries = [approvedEntry(PROVIDER, AGENT, ['review'])];

    expect(evaluate(versionOf(entries, 'v-one'), queryOf(PROVIDER, AGENT)).registryVersion).toBe(
      'v-one',
    );
    expect(evaluate(versionOf(entries, 'v-two'), queryOf(PROVIDER, AGENT)).registryVersion).toBe(
      'v-two',
    );
    // Identical content under two identifiers yields identical verdicts: the
    // identifier is never verified against, or derived from, the content.
    expect(evaluate(versionOf(entries, 'v-one'), queryOf(PROVIDER, AGENT)).eligible).toBe(true);
    expect(evaluate(versionOf(entries, 'v-two'), queryOf(PROVIDER, AGENT)).eligible).toBe(true);
  });

  it('imports exactly one module and reaches nothing outward', () => {
    const imports = [...MODULE_SOURCE.matchAll(/from\s+'([^']+)'/g)].map((match) => match[1]);
    expect(imports).toStrictEqual(['./agent-invocation.js']);

    for (const forbidden of [
      /node:/,
      /\brequire\(/,
      /\bimport\(/,
      /child_process/,
      /\bfetch\(/,
      /\bDate\b/,
      /Math\.random/,
      /\bcrypto\b/,
      /process\.env/,
      /globalThis/,
      /\blet\s+\w+\s*=.*\n/y,
    ]) {
      expect(MODULE_SOURCE).not.toMatch(forbidden);
    }
  });

  it('returns no entry, purpose set, index, or count', () => {
    const result = evaluate(baselineRegistry(), queryOf(PROVIDER, AGENT, 'review'));

    expect(Object.keys(result).sort()).toStrictEqual([
      'agentId',
      'eligible',
      'providerId',
      'purpose',
      'reason',
      'registryVersion',
    ]);
  });
});

describe('echo discipline', () => {
  it('nulls registryVersion only when the registry was unreadable', () => {
    const unreadable = evaluate({ entries: [] }, queryOf(PROVIDER, AGENT));
    expect(unreadable.reason).toBe(REASON.REGISTRY_UNREADABLE);
    expect(unreadable.registryVersion).toBeNull();

    for (const query of [null, queryOf('nope', 'nope'), queryOf(PROVIDER, AGENT, 'audit')]) {
      const result = evaluate(baselineRegistry(), query);
      expect(result.reason).not.toBe(REASON.REGISTRY_UNREADABLE);
      expect(result.registryVersion).toBe(VERSION);
    }

    expect(evaluate(versionOf([null]), queryOf(PROVIDER, AGENT)).registryVersion).toBe(VERSION);
  });

  it('echoes null for each invalid query field and never a raw value', () => {
    const result = evaluate(baselineRegistry(), {
      providerId: OVERSIZED,
      agentId: { toString: (): string => AGENT },
      purpose: 'REVIEW',
    });

    expect(result.reason).toBe(REASON.QUERY_INVALID);
    expect(result.providerId).toBeNull();
    expect(result.agentId).toBeNull();
    expect(result.purpose).toBeNull();
  });

  it('keeps registry precedence over an equally invalid query', () => {
    expect(evaluate(null, null).reason).toBe(REASON.REGISTRY_UNREADABLE);
    expect(evaluate(versionOf([null]), null).reason).toBe(REASON.REGISTRY_INVALID);
  });
});

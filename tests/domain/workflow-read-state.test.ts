/**
 * Adversarial suite for the serialized-observation reader `readWorkflowState`.
 *
 * This reader reconstructs a trusted, detached, deeply-frozen `WorkflowState`
 * from untrusted, possibly-mutable serialized data (ordinary `JSON.parse`
 * output). It is distinct by trust purpose from the authoritative transition
 * path: it never re-admits a state to the durable ledger, so — unlike
 * `applyWorkflowEvent` — it does not require the hostile input to be frozen. It
 * must nonetheless copy every accepted value off the hostile object graph, read
 * each hostile field exactly once, invoke no coercion hook, and fail closed on
 * every structural or invariant violation.
 */

import { afterEach, describe, expect, it } from 'vitest';

import { readWorkflowState } from '../../src/domain/index.js';
import { WORKFLOW_BOUNDS } from '../../src/domain/workflow.js';

const HEAD = 'c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00';

/** A fresh, plain, mutable, valid serialized state: OPEN, one REQUESTED invocation. */
function validSerialized(): Record<string, unknown> {
  return {
    workflowId: 'wf-1',
    repositoryId: 'owner/repo',
    pullRequestId: 'pr-1',
    boundCommitSha: HEAD,
    revision: 0,
    sequence: 1,
    status: 'OPEN',
    closureReason: null,
    humanGateOpenedAtRevision: null,
    invocations: [
      {
        invocationId: 'inv-1',
        targetCommitSha: HEAD,
        purpose: 'review',
        providerId: 'claude',
        agentId: 'agent-1',
        requestedAtRevision: 0,
        requestedAtSequence: 1,
        state: 'REQUESTED',
        reportedStatus: null,
        reportedAtRevision: null,
        reportedAtSequence: null,
      },
    ],
    evidence: [],
    reviews: [],
  };
}

function everyFrozen(state: {
  readonly invocations: readonly unknown[];
  readonly evidence: readonly unknown[];
  readonly reviews: readonly unknown[];
}): boolean {
  if (!Object.isFrozen(state)) {
    return false;
  }
  for (const list of [state.invocations, state.evidence, state.reviews]) {
    if (!Object.isFrozen(list)) {
      return false;
    }
    for (const element of list) {
      if (typeof element === 'object' && element !== null && !Object.isFrozen(element)) {
        return false;
      }
    }
  }
  return true;
}

describe('readWorkflowState — acceptance and trusted-snapshot construction', () => {
  it('1. accepts mutable JSON.parse-shaped valid input', () => {
    const revived: unknown = JSON.parse(JSON.stringify(validSerialized()));
    const state = readWorkflowState(revived);
    expect(state).not.toBeNull();
    expect(state?.workflowId).toBe('wf-1');
    expect(state?.status).toBe('OPEN');
    expect(state?.invocations).toHaveLength(1);
    expect(state?.invocations[0]?.invocationId).toBe('inv-1');
  });

  it('2. returns a deeply frozen state', () => {
    const state = readWorkflowState(validSerialized());
    expect(state).not.toBeNull();
    expect(state && everyFrozen(state)).toBe(true);
  });

  it('3. returns a state detached from the hostile input graph', () => {
    const input = validSerialized();
    const state = readWorkflowState(input);
    expect(state).not.toBeNull();
    // The returned invocations array is not the input array.
    expect(state?.invocations).not.toBe(input.invocations);
    // No accepted record is one of the input's own element objects.
    const inputInvocations = input.invocations as readonly unknown[];
    expect(state?.invocations[0]).not.toBe(inputInvocations[0]);
  });

  it('4. mutating the original input after return cannot affect the trusted result', () => {
    const input = validSerialized();
    const state = readWorkflowState(input);
    expect(state).not.toBeNull();
    // Mutate every reachable part of the hostile input.
    const inputInvocations = input.invocations as Array<Record<string, unknown>>;
    input.workflowId = 'mutated';
    inputInvocations.push({ invocationId: 'inv-2' });
    const firstInvocation = inputInvocations[0];
    if (firstInvocation !== undefined) {
      firstInvocation.invocationId = 'mutated';
    }
    expect(state?.workflowId).toBe('wf-1');
    expect(state?.invocations).toHaveLength(1);
    expect(state?.invocations[0]?.invocationId).toBe('inv-1');
  });

  it('20. round-trips through JSON preserving value semantics', () => {
    const state = readWorkflowState(validSerialized());
    expect(state).not.toBeNull();
    const revived: unknown = JSON.parse(JSON.stringify(state));
    const again = readWorkflowState(revived);
    expect(again).toEqual(state);
  });
});

describe('readWorkflowState — hostile input fails closed', () => {
  it('5. rejects a throwing getter on a scalar field, without throwing', () => {
    const input = validSerialized();
    Object.defineProperty(input, 'workflowId', {
      get() {
        throw new Error('hostile');
      },
      enumerable: true,
      configurable: true,
    });
    expect(readWorkflowState(input)).toBeNull();
  });

  it('6. rejects a revoked Proxy (top-level and as a collection)', () => {
    const top = Proxy.revocable({}, {});
    top.revoke();
    expect(readWorkflowState(top.proxy)).toBeNull();

    const listProxy = Proxy.revocable([], {});
    listProxy.revoke();
    const input = validSerialized();
    input.invocations = listProxy.proxy;
    expect(readWorkflowState(input)).toBeNull();
  });

  it('7. rejects a sparse collection (a hole is absence, never a value)', () => {
    const input = validSerialized();
    const sparse: unknown[] = [];
    sparse.length = 1; // one hole, length 1, no own index 0
    input.invocations = sparse;
    expect(readWorkflowState(input)).toBeNull();
  });

  it('8. rejects an inherited element planted on Array.prototype', () => {
    const input = validSerialized();
    // A collection of length 1 whose index 0 is a hole (no own property): the
    // only '0' available is inherited.
    const arr: unknown[] = [];
    arr.length = 1;
    input.invocations = arr;
    Object.defineProperty(Array.prototype, '0', {
      value: { invocationId: 'inherited' },
      configurable: true,
      writable: true,
    });
    try {
      // Own-key cardinality (own keys are exactly ['length'], not index 0 plus
      // length) rejects; the inherited '0' never becomes an element.
      expect(readWorkflowState(input)).toBeNull();
    } finally {
      delete (Array.prototype as unknown as Record<string, unknown>)['0'];
    }
  });

  it('9. rejects a collection carrying a surplus own key', () => {
    const input = validSerialized();
    const arr = input.invocations as unknown[];
    (arr as unknown as Record<string, unknown>).extra = 'surplus';
    expect(readWorkflowState(input)).toBeNull();
  });

  it('10. rejects a collection carrying a symbol own key', () => {
    const input = validSerialized();
    const arr = input.invocations as unknown[];
    (arr as unknown as Record<symbol, unknown>)[Symbol('x')] = 'surplus';
    expect(readWorkflowState(input)).toBeNull();
  });

  it('11. rejects a length-lying Proxy that hides an index', () => {
    const backing = validSerialized().invocations as unknown[];
    // A Proxy that reports length 0 while an own index 0 exists.
    const lying = new Proxy(backing, {
      get(target, key, recv): unknown {
        if (key === 'length') {
          return 0;
        }
        return Reflect.get(target, key, recv);
      },
    });
    const input = validSerialized();
    input.invocations = lying;
    // Reported length 0 yields an empty collection; the own-key cardinality
    // (index 0 + length = 2 keys) contradicts length 0 and rejects.
    expect(readWorkflowState(input)).toBeNull();
  });

  it('12. rejects a non-frozen Proxy collection substituting a malformed element', () => {
    const good = (validSerialized().invocations as Array<Record<string, unknown>>)[0];
    const backing = [good];
    const substituting = new Proxy(backing, {
      get(target, key, recv): unknown {
        if (key === '0') {
          // Substitute a structurally invalid record for the real one.
          return { invocationId: 'inv-1' };
        }
        return Reflect.get(target, key, recv);
      },
    });
    const input = validSerialized();
    input.invocations = substituting;
    expect(readWorkflowState(input)).toBeNull();
  });

  it('13. enforces each collection bound', () => {
    const input = validSerialized();
    input.invocations = new Array(WORKFLOW_BOUNDS.MAX_TRACKED_INVOCATIONS + 1).fill({});
    expect(readWorkflowState(input)).toBeNull();
  });

  it('18. rejects an invalid humanGateOpenedAtRevision relationship', () => {
    const input = validSerialized();
    // OPEN must carry a null gate; a non-null gate contradicts the status.
    input.humanGateOpenedAtRevision = 0;
    expect(readWorkflowState(input)).toBeNull();
  });

  it('19. rejects a duplicate transition sequence stamp across records', () => {
    const input = validSerialized();
    const first = (input.invocations as Array<Record<string, unknown>>)[0];
    input.invocations = [
      first,
      {
        ...first,
        invocationId: 'inv-2',
        requestedAtSequence: 1, // duplicate stamp
      },
    ];
    expect(readWorkflowState(input)).toBeNull();
  });
});

describe('readWorkflowState — ambient-realm robustness', () => {
  it('14. a poisoned Object.prototype cannot supply or alter fields', () => {
    (Object.prototype as unknown as Record<string, unknown>).status = 'CLOSED';
    (Object.prototype as unknown as Record<string, unknown>).injected = 'x';
    try {
      // Own-only reads: an inherited status must not override the own OPEN.
      const state = readWorkflowState(validSerialized());
      expect(state?.status).toBe('OPEN');
      expect(Object.hasOwn(state as object, 'injected')).toBe(false);
    } finally {
      delete (Object.prototype as unknown as Record<string, unknown>).status;
      delete (Object.prototype as unknown as Record<string, unknown>).injected;
    }
  });

  it('15/16. poisoned Array.prototype.push / Object.prototype.toJSON cannot affect construction', () => {
    const originalPush = Array.prototype.push;
    const pushed: unknown[] = [];
    Array.prototype.push = function (...args: unknown[]): number {
      // Delegate to the captured original against a private sink — never call
      // the (now-poisoned) prototype method, which would recurse.
      originalPush.apply(pushed, args);
      return this.length;
    };
    (Object.prototype as unknown as Record<string, unknown>).toJSON = () => ({ hijacked: true });
    try {
      const state = readWorkflowState(validSerialized());
      // Construction succeeds and is correct, reading fields directly (not via
      // JSON, whose `toJSON` is poisoned exactly as it would be for any engine-
      // produced state — that exposure is the domain's, not this reader's).
      expect(state).not.toBeNull();
      expect(state?.workflowId).toBe('wf-1');
      expect(state?.invocations[0]?.invocationId).toBe('inv-1');
      // Construction used captured intrinsics / defineProperty, never push.
      expect(pushed).toHaveLength(0);
    } finally {
      Array.prototype.push = originalPush;
      delete (Object.prototype as unknown as Record<string, unknown>).toJSON;
    }
  });

  it('17. never invokes a value-coercion hook on a hostile scalar', () => {
    let coerced = false;
    const tripwire = {
      valueOf() {
        coerced = true;
        return 0;
      },
      toString() {
        coerced = true;
        return '0';
      },
      [Symbol.toPrimitive]() {
        coerced = true;
        return 0;
      },
    };
    const input = validSerialized();
    input.revision = tripwire; // a non-number where a number is required
    const state = readWorkflowState(input);
    expect(state).toBeNull(); // typeof check rejects without coercion
    expect(coerced).toBe(false);
  });
});

describe('readWorkflowState — PR74-F1 prototype-hook insulation of the observation graph', () => {
  const objectToJSON = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
  const arrayToJSON = Object.getOwnPropertyDescriptor(Array.prototype, 'toJSON');

  // Always restore, even if a test threw, so no poisoned global leaks to others.
  afterEach(() => {
    if (objectToJSON !== undefined) {
      Object.defineProperty(Object.prototype, 'toJSON', objectToJSON);
    } else {
      delete (Object.prototype as unknown as Record<string, unknown>).toJSON;
    }
    if (arrayToJSON !== undefined) {
      Object.defineProperty(Array.prototype, 'toJSON', arrayToJSON);
    } else {
      delete (Array.prototype as unknown as Record<string, unknown>).toJSON;
    }
  });

  /**
   * A valid serialized state whose own `workflowId` getter runs `install` the
   * first time it is read — i.e. **during** `readWorkflowState`, before the
   * observation graph is built — so the poison is genuinely live at construction
   * time, not merely installed afterwards.
   */
  function inputPoisoningDuringRead(install: () => void): Record<string, unknown> {
    const base = validSerialized();
    let installed = false;
    Object.defineProperty(base, 'workflowId', {
      get(): string {
        if (!installed) {
          installed = true;
          install();
        }
        return 'wf-1';
      },
      enumerable: true,
      configurable: true,
    });
    return base;
  }

  it('A. a hijacking Object.prototype.toJSON installed during the read cannot hijack serialization', () => {
    const input = inputPoisoningDuringRead(() => {
      (Object.prototype as unknown as Record<string, unknown>).toJSON = () => ({ HIJACKED: true });
    });
    const state = readWorkflowState(input);
    expect(state).not.toBeNull();
    // The poison is live now; serialize the accepted graph.
    const json = JSON.stringify(state);
    expect(json).not.toContain('HIJACKED');
    const parsed = JSON.parse(json) as { workflowId: string; invocations: { invocationId: string }[] };
    expect(parsed.workflowId).toBe('wf-1');
    expect(parsed.invocations[0]?.invocationId).toBe('inv-1');
  });

  it('B. a throwing Object.prototype.toJSON installed during the read cannot make serialization throw', () => {
    const input = inputPoisoningDuringRead(() => {
      (Object.prototype as unknown as Record<string, unknown>).toJSON = () => {
        throw new Error('hostile toJSON');
      };
    });
    const state = readWorkflowState(input);
    expect(state).not.toBeNull();
    expect(() => JSON.stringify(state)).not.toThrow();
    const parsed = JSON.parse(JSON.stringify(state)) as { workflowId: string };
    expect(parsed.workflowId).toBe('wf-1');
  });

  it('C. a hostile Array.prototype.toJSON is not executed by the returned lists', () => {
    const state = readWorkflowState(validSerialized());
    expect(state).not.toBeNull();
    let called = false;
    (Array.prototype as unknown as Record<string, unknown>).toJSON = (): string => {
      called = true;
      return 'HOSTILE_ARRAY';
    };
    const json = JSON.stringify(state);
    expect(called).toBe(false);
    expect(json).not.toContain('HOSTILE_ARRAY');
    // Lists still serialize as real JSON arrays.
    const parsed = JSON.parse(json) as { invocations: unknown };
    expect(Array.isArray(parsed.invocations)).toBe(true);
  });

  it('D. nested records do not execute an inherited Object.prototype.toJSON', () => {
    const state = readWorkflowState(validSerialized());
    expect(state).not.toBeNull();
    (Object.prototype as unknown as Record<string, unknown>).toJSON = () => ({ HIJACKED: true });
    const parsed = JSON.parse(JSON.stringify(state)) as {
      invocations: { invocationId?: string; HIJACKED?: boolean }[];
    };
    expect(parsed.invocations[0]?.invocationId).toBe('inv-1');
    expect(parsed.invocations[0]?.HIJACKED).toBeUndefined();
  });

  it('E. the protective list toJSON shadow is non-enumerable and absent from JSON output', () => {
    const state = readWorkflowState(validSerialized());
    expect(state).not.toBeNull();
    const list = state?.invocations ?? [];
    expect(Object.hasOwn(list, 'toJSON')).toBe(true);
    expect(Object.getOwnPropertyDescriptor(list, 'toJSON')?.enumerable).toBe(false);
    expect(JSON.stringify(state)).not.toContain('toJSON');
  });

  it('F. the returned observation graph is deeply frozen and prototype-detached', () => {
    const state = readWorkflowState(validSerialized());
    expect(state).not.toBeNull();
    expect(state !== null && everyFrozen(state)).toBe(true);
    // Records are detached from Object.prototype; no inherited toJSON to reach.
    expect(Object.getPrototypeOf(state)).toBeNull();
    expect(Object.getPrototypeOf(state?.invocations[0])).toBeNull();
  });

  it('G. value semantics are unchanged from a normal read (round trip is faithful)', () => {
    const state = readWorkflowState(validSerialized());
    expect(state).not.toBeNull();
    const revived: unknown = JSON.parse(JSON.stringify(state));
    expect(readWorkflowState(revived)).toEqual(state);
  });
});

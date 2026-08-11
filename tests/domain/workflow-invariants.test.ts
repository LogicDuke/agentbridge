/**
 * Security and structural invariants for the Autoflow state machine.
 *
 * These are the properties that must survive every future change: provider,
 * purpose, and reported status never influence legality; a claim never becomes
 * an observation; old-revision facts never advance the current revision; no
 * state implies merge, deploy, or write authority; hostile input fails closed;
 * and every transition is pure, deterministic, and immutable.
 */

import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  applyWorkflowEvent,
  evaluateEvidenceFreshness,
  INVOCATION_BOUNDS,
  openWorkflow,
  REVIEW_BOUNDS,
  TRANSITION_REJECTIONS,
  WORKFLOW_BOUNDS,
  WORKFLOW_EVENT_KINDS,
  WORKFLOW_STATUSES,
  type AdmittedEvidence,
  type TrackedInvocation,
  type WorkflowEvent,
  type WorkflowState,
} from '../../src/domain/index.js';
import {
  admitEvidence,
  admitReview,
  applyOrThrow,
  buildBinding,
  buildHumanDecisionVerdict,
  buildInvocation,
  buildReport,
  buildReview,
  buildVerdict,
  closeWorkflow,
  EVIDENCE_A,
  EVIDENCE_B,
  FORBIDDEN_STATE_KEYS,
  FORBIDDEN_STATE_VALUES,
  INVOCATION_A,
  INVOCATION_B,
  observeHead,
  openedWorkflow,
  openHumanGate,
  oversized,
  PROVIDER_LABELS,
  PURPOSES,
  REPO_A,
  REPORT_STATUSES,
  reportInvocation,
  requestInvocation,
  REVIEW_A,
  revokedProxy,
  SHA_A,
  SHA_B,
  SHA_C,
  withRawInvocationField,
  withRawReportField,
  withThrowingGetter,
  withUnstableGetter,
} from './workflow-fixtures.js';

/** A workflow with one invocation already requested at the bound commit. */
function requested(): WorkflowState {
  return applyOrThrow(openedWorkflow(), requestInvocation());
}

/** Every event kind as a valid instance, for sweeps that must cover all seven. */
function everyEvent(): readonly (readonly [string, WorkflowEvent])[] {
  return [
    [
      'INVOCATION_REQUESTED',
      requestInvocation(buildInvocation({ invocationId: INVOCATION_B })),
    ],
    ['INVOCATION_REPORTED', reportInvocation()],
    ['REVIEW_ADMITTED', admitReview()],
    ['EVIDENCE_ADMITTED', admitEvidence()],
    ['HEAD_OBSERVED', observeHead(SHA_B)],
    ['HUMAN_GATE_OPENED', openHumanGate()],
    ['CLOSE_REQUESTED', closeWorkflow()],
  ];
}

/**
 * Remove comments so a static scan inspects code rather than prose.
 *
 * The doc comments legitimately discuss clocks, processes, and Promises while
 * explaining why none of them appear in the code.
 */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
}

/**
 * Freeze a collection the way `freezeState` always does.
 *
 * Every list this layer emits is frozen, and emptiness/cardinality is only
 * provable for a non-extensible list, so a synthetic state must be frozen to be
 * a faithful stand-in for one the layer produced.
 */
function stored<T>(list: readonly T[]): readonly T[] {
  return Object.freeze([...list]);
}

/** Run `body` with one property replaced, restoring it whatever happens. */
function withPoisoned(target: object, key: PropertyKey, value: unknown, body: () => void): void {
  const original = Object.getOwnPropertyDescriptor(target, key);
  try {
    Object.defineProperty(target, key, {
      value,
      writable: true,
      enumerable: false,
      configurable: true,
    });
    body();
  } finally {
    if (original === undefined) {
      Reflect.deleteProperty(target, key);
    } else {
      Object.defineProperty(target, key, original);
    }
  }
}

describe('group H — provider, purpose, and reported status are inert', () => {
  /** Replace the three recorded label fields, so only they may differ. */
  function withoutLabels(state: WorkflowState): unknown {
    return {
      ...state,
      invocations: state.invocations.map((tracked) => ({
        ...tracked,
        purpose: 'X',
        providerId: 'X',
        agentId: 'X',
        reportedStatus: tracked.reportedStatus === null ? null : 'X',
      })),
    };
  }

  function run(providerId: string, purpose: string, status: string): WorkflowState {
    const invocation = buildInvocation({
      providerId,
      agentId: `${providerId}-agent`,
      purpose: purpose as never,
    });
    return applyOrThrow(
      applyOrThrow(openedWorkflow(), requestInvocation(invocation)),
      reportInvocation(buildReport({ providerId, purpose: purpose as never, reportedStatus: status as never })),
    );
  }

  const canonical = withoutLabels(run('codex', 'review', 'reported-complete'));

  const combinations: readonly (readonly [string, string, string])[] = PROVIDER_LABELS.flatMap(
    (providerId) =>
      PURPOSES.flatMap((purpose) =>
        REPORT_STATUSES.map((status) => [providerId, purpose, status] as const),
      ),
  );

  it('covers every provider, purpose, and status combination', () => {
    expect(combinations).toHaveLength(8 * 4 * 4);
  });

  it.each(combinations)(
    'provider %s, purpose %s, status %s produces an identical state',
    (providerId, purpose, status) => {
      expect(withoutLabels(run(providerId, purpose, status))).toEqual(canonical);
    },
  );

  it('records the labels verbatim without ever reading them', () => {
    const state = run('agentbridge-internal', 'repair', 'reported-failed');

    expect(state.invocations[0]?.providerId).toBe('agentbridge-internal');
    expect(state.invocations[0]?.purpose).toBe('repair');
    expect(state.invocations[0]?.reportedStatus).toBe('reported-failed');
    expect(state.status).toBe('OPEN');
  });

  it('grants a repair invocation nothing a review invocation lacks', () => {
    const repair = run('claude', 'repair', 'reported-complete');
    const review = run('claude', 'review', 'reported-complete');

    expect(Object.keys(repair)).toEqual(Object.keys(review));
    expect(withoutLabels(repair)).toEqual(withoutLabels(review));
  });

  it('does not let a privileged-sounding provider open or clear a gate', () => {
    const gated = applyOrThrow(openedWorkflow(), openHumanGate());
    const result = applyWorkflowEvent(
      gated,
      requestInvocation(buildInvocation({ providerId: 'root', agentId: 'admin' })),
    );

    expect(result.rejection).toBe('WORKFLOW_AWAITING_HUMAN');
  });
});

describe('group I — a claim never becomes an observation', () => {
  it('records no evidence for a complete report full of claims', () => {
    const claims = Array.from({ length: 64 }, (_value, index) => ({
      claimId: `c${String(index)}`,
      ordinal: index,
      invocationId: INVOCATION_A,
      repositoryId: REPO_A,
      artifactType: 'commit',
      reference: `ref-${String(index)}`,
      claimedCommitSha: SHA_A,
      truncated: false,
    }));
    const state = applyOrThrow(
      requested(),
      reportInvocation(withRawReportField('claims', claims)),
    );
    const serialized = JSON.stringify(state);

    expect(state.evidence).toEqual([]);
    expect(state.reviews).toEqual([]);
    expect(serialized).not.toContain('ref-0');
    expect(serialized).not.toContain('artifactType');
    expect(serialized).not.toContain('claimedCommitSha');
  });

  it('has no code path from a report into an admission list', () => {
    const source = readFileSync(
      new URL('../../src/domain/workflow-transitions.ts', import.meta.url),
      'utf8',
    );
    const reportHandler = source.slice(
      source.indexOf('function applyInvocationReported'),
      source.indexOf('function applyReviewAdmitted'),
    );

    expect(reportHandler.length).toBeGreaterThan(0);
    expect(reportHandler).not.toContain('snapshot.evidence');
    expect(reportHandler).not.toContain('snapshot.reviews');
    expect(reportHandler).not.toContain('AdmittedEvidence');
    expect(reportHandler).not.toContain('AdmittedReview');
  });

  it('refuses a claim supplied where any payload belongs', () => {
    const claim = {
      claimId: 'c0',
      ordinal: 0,
      invocationId: INVOCATION_A,
      repositoryId: REPO_A,
      artifactType: 'commit',
      reference: 'abc',
      claimedCommitSha: SHA_A,
      truncated: false,
    };
    const payloads: readonly WorkflowEvent[] = [
      { kind: 'INVOCATION_REQUESTED', invocation: claim } as never,
      { kind: 'INVOCATION_REPORTED', report: claim } as never,
      { kind: 'REVIEW_ADMITTED', review: claim } as never,
      { kind: 'EVIDENCE_ADMITTED', verdict: claim } as never,
    ];

    for (const event of payloads) {
      const result = applyWorkflowEvent(requested(), event);
      expect(result.outcome).toBe('REJECTED');
    }
  });
});

describe('group J — hostile input fails closed', () => {
  it.each(['workflowId', 'repositoryId', 'boundCommitSha', 'revision', 'sequence', 'status'])(
    'refuses a state whose %s getter throws',
    (field) => {
      const state = withThrowingGetter(openedWorkflow(), field);
      const result = applyWorkflowEvent(state, admitEvidence());

      expect(result.rejection).toBe('WORKFLOW_UNREADABLE');
      expect(result.state).toBe(state);
    },
  );

  it.each(['invocations', 'evidence', 'reviews'])(
    'refuses a state whose %s list getter throws',
    (field) => {
      const result = applyWorkflowEvent(withThrowingGetter(openedWorkflow(), field), admitEvidence());

      expect(result.rejection).toBe('WORKFLOW_UNREADABLE');
    },
  );

  it('refuses a state whose list element read throws', () => {
    const base = requested();
    const hostile: unknown[] = [];
    Object.defineProperty(hostile, 0, {
      get() {
        throw new Error('hostile element');
      },
      enumerable: true,
      configurable: true,
    });
    const state = { ...base, invocations: hostile } as unknown as WorkflowState;

    expect(applyWorkflowEvent(state, admitEvidence()).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it('refuses a revoked Proxy as state and as event', () => {
    const proxy = revokedProxy() as WorkflowState;

    expect(applyWorkflowEvent(proxy, admitEvidence()).rejection).toBe('WORKFLOW_UNREADABLE');
    expect(
      applyWorkflowEvent(openedWorkflow(), revokedProxy() as WorkflowEvent).rejection,
    ).toBe('EVENT_UNREADABLE');
  });

  it('refuses an event whose kind getter throws', () => {
    const event = withThrowingGetter(admitEvidence(), 'kind');

    expect(applyWorkflowEvent(openedWorkflow(), event).rejection).toBe('EVENT_KIND_UNKNOWN');
  });

  it.each(['invocation', 'report', 'review', 'verdict'])(
    'refuses an event whose %s payload getter throws',
    (slot) => {
      const kinds: Record<string, string> = {
        invocation: 'INVOCATION_REQUESTED',
        report: 'INVOCATION_REPORTED',
        review: 'REVIEW_ADMITTED',
        verdict: 'EVIDENCE_ADMITTED',
      };
      const event = withThrowingGetter(
        { kind: kinds[slot], [slot]: {} } as unknown as WorkflowEvent,
        slot,
      );

      expect(applyWorkflowEvent(requested(), event).rejection).toBe('EVENT_PAYLOAD_INVALID');
    },
  );

  it('cannot validate one value and store another through an unstable getter', () => {
    const invocation = withUnstableGetter(buildInvocation(), 'targetCommitSha', [SHA_A, SHA_B, SHA_B]);
    const result = applyWorkflowEvent(openedWorkflow(), requestInvocation(invocation));

    // Each field is read exactly once, so the first observed value is the one
    // validated *and* stored. The swapped value must never reach the state —
    // asserted unconditionally, so an unrelated rejection cannot satisfy it.
    expect(JSON.stringify(result.state)).not.toContain(SHA_B);
    expect(result.outcome).toBe('APPLIED');
    expect(result.state.invocations).toHaveLength(1);
    expect(result.state.invocations[0]?.targetCommitSha).toBe(SHA_A);
  });

  it('never lets an unstable evidence verdict be admitted under a different id', () => {
    const verdict = withUnstableGetter(buildVerdict(), 'evidenceId', [EVIDENCE_A, 'ev-forged']);
    const result = applyWorkflowEvent(openedWorkflow(), admitEvidence(verdict));

    // The forged second value must never appear anywhere in the resulting
    // state. Asserted unconditionally: a rejection for an unrelated reason
    // cannot satisfy this the way a bare `outcome === 'REJECTED'` would.
    expect(JSON.stringify(result.state)).not.toContain('ev-forged');
    expect(result.outcome).toBe('APPLIED');
    expect(result.state.evidence).toHaveLength(1);
    expect(result.state.evidence[0]?.evidenceId).toBe(EVIDENCE_A);
  });

  it.each(['outcome', 'state', 'status', 'revision', 'sequence', 'kind', 'boundCommitSha'])(
    'ignores %s planted on Object.prototype',
    (key) => {
      const expected = applyWorkflowEvent(openedWorkflow(), admitReview(buildReview({ reviewId: REVIEW_A })));
      let observed: unknown;

      withPoisoned(Object.prototype, key, 'INGESTED', () => {
        observed = applyWorkflowEvent(
          openedWorkflow(),
          admitReview(buildReview({ reviewId: REVIEW_A })),
        );
      });

      expect(observed).toEqual(expected);
    },
  );

  it('ignores a payload that inherits its outcome through __proto__', () => {
    const review = JSON.parse(
      `{"__proto__":{"outcome":"INGESTED"},"reviewId":"${REVIEW_A}","repositoryId":"${REPO_A}","reviewedCommitSha":"${SHA_A}"}`,
    ) as never;
    const result = applyWorkflowEvent(openedWorkflow(), admitReview(review));

    expect(result.rejection).toBe('INPUT_NOT_INGESTED');
  });

  it.each([
    ['Array.prototype.push', Array.prototype, 'push'],
    ['Array.prototype.includes', Array.prototype, 'includes'],
    ['Array.prototype.map', Array.prototype, 'map'],
    ['Array.prototype.filter', Array.prototype, 'filter'],
    ['String.prototype.trim', String.prototype, 'trim'],
    ['String.prototype.slice', String.prototype, 'slice'],
  ])('survives a poisoned %s', (_name, target, key) => {
    const expected = applyWorkflowEvent(requested(), reportInvocation());
    let observed: unknown;

    withPoisoned(
      target,
      key,
      () => {
        throw new Error('poisoned');
      },
      () => {
        observed = applyWorkflowEvent(requested(), reportInvocation());
      },
    );

    expect(observed).toEqual(expected);
  });

  it('survives an includes that claims everything is a member', () => {
    let observed: unknown;

    withPoisoned(Array.prototype, 'includes', () => true, () => {
      observed = applyWorkflowEvent(openedWorkflow(), { kind: 'MERGE' } as never);
    });

    expect((observed as { rejection: string }).rejection).toBe('EVENT_KIND_UNKNOWN');
  });

  it('survives a poisoned Set.prototype.has', () => {
    const expected = applyWorkflowEvent(openedWorkflow(), admitEvidence());
    let observed: unknown;

    withPoisoned(Set.prototype, 'has', () => true, () => {
      observed = applyWorkflowEvent(openedWorkflow(), admitEvidence());
    });

    expect(observed).toEqual(expected);
  });

  it('still freezes results when Object.freeze is replaced after module load', () => {
    let observed: WorkflowState | undefined;

    withPoisoned(Object, 'freeze', (value: unknown) => value, () => {
      observed = applyWorkflowEvent(openedWorkflow(), admitEvidence()).state;
    });

    expect(observed).toBeDefined();
    expect(Object.isFrozen(observed)).toBe(true);
    expect(Object.isFrozen(observed?.evidence)).toBe(true);
  });

  it('still reads own properties when Object.hasOwn is replaced after module load', () => {
    const expected = applyWorkflowEvent(openedWorkflow(), admitEvidence());
    let observed: unknown;

    withPoisoned(Object, 'hasOwn', () => false, () => {
      observed = applyWorkflowEvent(openedWorkflow(), admitEvidence());
    });

    expect(observed).toEqual(expected);
  });

  it('bypasses an inherited numeric index setter', () => {
    const expected = applyWorkflowEvent(openedWorkflow(), requestInvocation());
    let observed: unknown;

    const descriptor = Object.getOwnPropertyDescriptor(Array.prototype, 0);
    try {
      Object.defineProperty(Array.prototype, 0, {
        set() {
          throw new Error('inherited index setter');
        },
        get() {
          return undefined;
        },
        configurable: true,
      });
      observed = applyWorkflowEvent(openedWorkflow(), requestInvocation());
    } finally {
      if (descriptor === undefined) {
        Reflect.deleteProperty(Array.prototype, 0);
      } else {
        Object.defineProperty(Array.prototype, 0, descriptor);
      }
    }

    expect(observed).toEqual(expected);
  });

  it('refuses a self-inconsistent state rather than trusting it', () => {
    const base = openedWorkflow();
    const inconsistent: readonly WorkflowState[] = [
      { ...base, closureReason: 'CALLER_CLOSED' } as WorkflowState,
      { ...base, status: 'CLOSED', closureReason: null } as unknown as WorkflowState,
      { ...base, humanGateOpenedAtRevision: 0 } as WorkflowState,
      { ...base, status: 'AWAITING_HUMAN_DECISION' } as unknown as WorkflowState,
      { ...base, revision: 5, humanGateOpenedAtRevision: 2 } as WorkflowState,
      { ...base, revision: -1 } as WorkflowState,
      { ...base, sequence: 1.5 } as WorkflowState,
      { ...base, status: 'open' } as unknown as WorkflowState,
    ];

    for (const state of inconsistent) {
      expect(applyWorkflowEvent(state, admitEvidence()).rejection).toBe('WORKFLOW_UNREADABLE');
    }
  });

  it('refuses a state whose tracked invocation contradicts its own reported trio', () => {
    const base = requested();
    const tracked = base.invocations[0];
    expect(tracked).toBeDefined();

    const forged = {
      ...base,
      invocations: [{ ...(tracked as TrackedInvocation), reportedStatus: 'reported-complete' }],
    } as unknown as WorkflowState;

    expect(applyWorkflowEvent(forged, admitEvidence()).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it('refuses a state whose admission postdates the workflow itself', () => {
    const base = applyOrThrow(openedWorkflow(), admitEvidence());
    const admission = base.evidence[0];
    expect(admission).toBeDefined();

    const forged = {
      ...base,
      evidence: [{ ...(admission as AdmittedEvidence), admittedAtSequence: 99 }],
    } as unknown as WorkflowState;

    expect(applyWorkflowEvent(forged, admitReview()).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it.each(['invocations', 'evidence', 'reviews'] as const)(
    'rejects a prototype-planted numeric entry in %s without making it durable',
    (listName) => {
      const invocationState = requested();
      const evidenceState = applyOrThrow(openedWorkflow(), admitEvidence());
      const reviewState = applyOrThrow(openedWorkflow(), admitReview());
      const planted =
        listName === 'invocations'
          ? invocationState.invocations[0]
          : listName === 'evidence'
            ? evidenceState.evidence[0]
            : reviewState.reviews[0];
      expect(planted).toBeDefined();

      const sparse = new Array<unknown>(1);
      const forged = {
        ...openedWorkflow(),
        sequence: 1,
        [listName]: sparse,
      } as unknown as WorkflowState;
      const event =
        listName === 'invocations'
          ? reportInvocation()
          : requestInvocation(buildInvocation({ invocationId: INVOCATION_B }));

      withPoisoned(Array.prototype, 0, planted, () => {
        const result = applyWorkflowEvent(forged, event);
        expect(result.rejection).toBe('WORKFLOW_UNREADABLE');
        expect(result.state).toBe(forged);
        expect(Object.hasOwn(sparse, 0)).toBe(false);
      });
    },
  );

  it.each(['evidence', 'reviews'] as const)(
    'requires a current %s admission commit to match while retaining historical commits',
    (listName) => {
      const admitted =
        listName === 'evidence'
          ? applyOrThrow(openedWorkflow(), admitEvidence())
          : applyOrThrow(openedWorkflow(), admitReview());
      const admission = listName === 'evidence' ? admitted.evidence[0] : admitted.reviews[0];
      expect(admission).toBeDefined();

      const mismatched = {
        ...admitted,
        [listName]: stored([{ ...admission, admittedAtCommitSha: SHA_B }]),
      } as unknown as WorkflowState;
      const laterEvent =
        listName === 'evidence'
          ? admitEvidence(buildVerdict({ evidenceId: EVIDENCE_A }))
          : admitReview(buildReview({ reviewId: REVIEW_A }));
      expect(applyWorkflowEvent(mismatched, laterEvent).rejection).toBe(
        'WORKFLOW_UNREADABLE',
      );

      const matching = {
        ...admitted,
        [listName]: stored([{ ...admission, admittedAtCommitSha: SHA_A }]),
      } as unknown as WorkflowState;
      expect(
        applyWorkflowEvent(
          matching,
          requestInvocation(buildInvocation({ invocationId: INVOCATION_B })),
        ).outcome,
      ).toBe('APPLIED');

      const historical = applyOrThrow(admitted, observeHead(SHA_B));
      expect(
        applyWorkflowEvent(
          historical,
          requestInvocation(buildInvocation({
            invocationId: INVOCATION_B,
            targetCommitSha: SHA_B,
          })),
        ).outcome,
      ).toBe('APPLIED');
      expect(
        (listName === 'evidence' ? historical.evidence[0] : historical.reviews[0])
          ?.admittedAtCommitSha,
      ).toBe(SHA_A);
    },
  );

  /**
   * A tracked invocation stamped at the current revision must target the
   * current bound commit, symmetrically with the two admission collections.
   *
   * Every state this layer produces satisfies it by construction —
   * `INVOCATION_REQUESTED` requires `targetCommitSha === boundCommitSha`, and
   * `revision` only moves through `HEAD_OBSERVED`. A deserialized or forged
   * aggregate that violates it would let `INVOCATION_REPORTED` record a report
   * against a commit the workflow was never bound to at that revision, because
   * that comparison correctly uses the tracked invocation's own commit.
   */
  const forgedCurrentInvocation = (): WorkflowState => {
    const base = requested();
    const tracked = base.invocations[0];
    return {
      ...base,
      invocations: [{ ...tracked, targetCommitSha: SHA_C }],
    } as unknown as WorkflowState;
  };

  it('refuses a current-revision invocation that targets a foreign commit', () => {
    const forged = forgedCurrentInvocation();
    const tracked = forged.invocations[0];

    expect(tracked?.requestedAtRevision).toBe(forged.revision);
    expect(tracked?.targetCommitSha).not.toBe(forged.boundCommitSha);
    expect(applyWorkflowEvent(forged, admitEvidence()).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it('refuses that forged state for every event kind, failing closed each time', () => {
    const forged = forgedCurrentInvocation();

    for (const [name, event] of everyEvent()) {
      const result = applyWorkflowEvent(forged, event);

      expect(result.rejection, name).toBe('WORKFLOW_UNREADABLE');
      expect(result.outcome, name).toBe('REJECTED');
      expect(result.state, name).toBe(forged);
    }
    expect(applyWorkflowEvent(forged, { kind: 'NOPE' } as never).state).toBe(forged);
  });

  it('refuses a report bound to the forged foreign commit', () => {
    const forged = forgedCurrentInvocation();
    const result = applyWorkflowEvent(
      forged,
      reportInvocation(buildReport({ invocationId: INVOCATION_A, targetCommitSha: SHA_C })),
    );

    expect(result.rejection).toBe('WORKFLOW_UNREADABLE');
    expect(result.state).toBe(forged);
    expect(result.state.invocations[0]?.state).toBe('REQUESTED');
  });

  it('keeps a legitimate current-revision invocation valid', () => {
    const legitimate = requested();

    expect(legitimate.invocations[0]?.requestedAtRevision).toBe(legitimate.revision);
    expect(legitimate.invocations[0]?.targetCommitSha).toBe(legitimate.boundCommitSha);
    expect(applyWorkflowEvent(legitimate, reportInvocation()).outcome).toBe('APPLIED');
    expect(applyWorkflowEvent(legitimate, admitEvidence()).outcome).toBe('APPLIED');
  });

  it('lets a historical invocation keep its own commit after HEAD advances', () => {
    const moved = applyOrThrow(requested(), observeHead(SHA_B));
    const tracked = moved.invocations[0];

    // Not rewritten to the new bound commit, and still below the new revision.
    expect(tracked?.targetCommitSha).toBe(SHA_A);
    expect(tracked?.requestedAtRevision).toBe(0);
    expect(tracked?.state).toBe('REQUESTED');
    expect(moved.boundCommitSha).toBe(SHA_B);
    expect(moved.revision).toBe(1);

    // The aggregate stays readable, and the historical report still applies
    // against the invocation's own commit rather than the new HEAD.
    expect(applyWorkflowEvent(moved, reportInvocation()).outcome).toBe('APPLIED');
    expect(
      applyWorkflowEvent(
        moved,
        requestInvocation(
          buildInvocation({ invocationId: INVOCATION_B, targetCommitSha: SHA_B }),
        ),
      ).outcome,
    ).toBe('APPLIED');
    expect(applyOrThrow(moved, reportInvocation()).invocations[0]?.targetCommitSha).toBe(SHA_A);
  });

  it('binds all three collections to the current commit symmetrically', () => {
    const base = requested();
    const withAdmissions = applyOrThrow(applyOrThrow(base, admitEvidence()), admitReview());
    const tracked = withAdmissions.invocations[0];
    const evidence = withAdmissions.evidence[0];
    const review = withAdmissions.reviews[0];

    // The invariant holds for a legitimately built aggregate.
    expect(tracked?.targetCommitSha).toBe(withAdmissions.boundCommitSha);
    expect(evidence?.admittedAtCommitSha).toBe(withAdmissions.boundCommitSha);
    expect(review?.admittedAtCommitSha).toBe(withAdmissions.boundCommitSha);

    // Breaking it in any one collection makes the whole aggregate unreadable.
    const forgeries: readonly WorkflowState[] = [
      {
        ...withAdmissions,
        invocations: [{ ...tracked, targetCommitSha: SHA_C }],
      } as unknown as WorkflowState,
      {
        ...withAdmissions,
        evidence: [{ ...evidence, admittedAtCommitSha: SHA_C }],
      } as unknown as WorkflowState,
      {
        ...withAdmissions,
        reviews: [{ ...review, admittedAtCommitSha: SHA_C }],
      } as unknown as WorkflowState,
    ];

    for (const forged of forgeries) {
      const result = applyWorkflowEvent(forged, admitEvidence(buildVerdict({ evidenceId: 'ev-x' })));

      expect(result.rejection).toBe('WORKFLOW_UNREADABLE');
      expect(result.state).toBe(forged);
    }
  });

  /* ---- finding 1: a CURRENT verdict must carry a complete PR 004 shape ---- */

  it.each([
    ['an absent source', { source: undefined }],
    ['a null source', { source: null }],
    ['a bogus source', { source: 'not-a-source' }],
    ['a numeric source', { source: 7 }],
    ['a non-empty invalidFields', { invalidFields: ['commitSha'] }],
    ['a non-array invalidFields', { invalidFields: 'none' }],
    ['a null invalidFields', { invalidFields: null }],
    ['an absent invalidFields', { invalidFields: undefined }],
  ])('refuses a CURRENT human-decision verdict with %s', (_name, overrides) => {
    const gated = applyOrThrow(openedWorkflow(), openHumanGate());
    const result = applyWorkflowEvent(
      gated,
      admitEvidence(buildHumanDecisionVerdict(overrides as never)),
    );

    expect(result.rejection).toBe('EVIDENCE_NOT_CURRENT');
    expect(result.state).toBe(gated);
    expect(result.state.status).toBe('AWAITING_HUMAN_DECISION');
    expect(result.state.humanGateOpenedAtRevision).toBe(0);
  });

  it('refuses a CURRENT verdict whose invalidFields is prototype-backed or hostile', () => {
    const gated = applyOrThrow(openedWorkflow(), openHumanGate());
    const inherited = Object.create([]) as unknown[];
    const throwingLength = new Proxy([], {
      get(target, key): unknown {
        if (key === 'length') {
          throw new Error('hostile length');
        }
        return Reflect.get(target, key);
      },
    });
    const lyingLength = new Proxy([], {
      get(target, key): unknown {
        if (key === 'length') {
          return Number.MAX_SAFE_INTEGER;
        }
        return Reflect.get(target, key);
      },
    });

    for (const invalidFields of [inherited, throwingLength, lyingLength, revokedProxy()]) {
      const result = applyWorkflowEvent(
        gated,
        admitEvidence(buildHumanDecisionVerdict({ invalidFields } as never)),
      );

      expect(result.rejection).toBe('EVIDENCE_NOT_CURRENT');
      expect(result.state.status).toBe('AWAITING_HUMAN_DECISION');
    }
  });

  it('still admits a genuine PR 004 verdict and still clears the gate', () => {
    const gated = applyOrThrow(openedWorkflow(), openHumanGate());
    const genuine = evaluateEvidenceFreshness(
      {
        evidenceId: EVIDENCE_A,
        repositoryId: REPO_A,
        commitSha: SHA_A,
        kind: 'human-decision',
        source: 'human',
        reference: 'decision-1',
        observedAt: '2026-01-01T00:00:00.000Z',
      },
      { repositoryId: REPO_A, currentHeadSha: SHA_A },
    );

    expect(genuine.state).toBe('CURRENT');
    expect(genuine.source).toBe('human');
    expect(genuine.invalidFields).toEqual([]);

    const result = applyWorkflowEvent(gated, admitEvidence(genuine));

    expect(result.outcome).toBe('APPLIED');
    expect(result.state.status).toBe('OPEN');
    expect(result.state.humanGateOpenedAtRevision).toBeNull();
  });

  /* ---- finding 2: one revision maps to exactly one commit ---- */

  /** A workflow with an invocation, an evidence and a review all at revision 0. */
  function historicalAggregate(): WorkflowState {
    const populated = applyOrThrow(
      applyOrThrow(applyOrThrow(openedWorkflow(), requestInvocation()), admitEvidence()),
      admitReview(),
    );
    return applyOrThrow(populated, observeHead(SHA_B));
  }

  it.each([
    ['within invocations', (s: WorkflowState) => ({
      ...s,
      invocations: [
        { ...s.invocations[0], targetCommitSha: SHA_C },
        { ...s.invocations[0], invocationId: INVOCATION_B, targetCommitSha: SHA_A },
      ],
    })],
    ['within evidence', (s: WorkflowState) => ({
      ...s,
      evidence: [
        s.evidence[0],
        { ...s.evidence[0], evidenceId: 'ev-other', admittedAtCommitSha: SHA_C },
      ],
    })],
    ['within reviews', (s: WorkflowState) => ({
      ...s,
      reviews: [
        s.reviews[0],
        { ...s.reviews[0], reviewId: 'rv-other', admittedAtCommitSha: SHA_C },
      ],
    })],
    ['across invocations and evidence', (s: WorkflowState) => ({
      ...s,
      evidence: [{ ...s.evidence[0], admittedAtCommitSha: SHA_C }],
    })],
    ['across evidence and reviews', (s: WorkflowState) => ({
      ...s,
      reviews: [{ ...s.reviews[0], admittedAtCommitSha: SHA_C }],
    })],
  ])('refuses a revision bound to two commits %s', (_name, forge) => {
    const forged = forge(historicalAggregate()) as unknown as WorkflowState;

    for (const [, event] of everyEvent()) {
      const result = applyWorkflowEvent(forged, event);
      expect(result.rejection).toBe('WORKFLOW_UNREADABLE');
      expect(result.state).toBe(forged);
    }
  });

  it('accepts a legitimate multi-revision history and preserves its commits', () => {
    const historical = historicalAggregate();

    expect(historical.invocations[0]?.targetCommitSha).toBe(SHA_A);
    expect(historical.evidence[0]?.admittedAtCommitSha).toBe(SHA_A);
    expect(historical.reviews[0]?.admittedAtCommitSha).toBe(SHA_A);

    const next = applyOrThrow(
      historical,
      admitEvidence(buildVerdict({ evidenceId: 'ev-next', commitSha: SHA_B, targetHeadSha: SHA_B })),
    );

    // Revision 0 keeps commit A; revision 1 records commit B. Different
    // revisions may of course differ.
    expect(next.evidence[0]?.admittedAtCommitSha).toBe(SHA_A);
    expect(next.evidence[1]?.admittedAtCommitSha).toBe(SHA_B);
    expect(next.invocations[0]?.targetCommitSha).toBe(SHA_A);
  });

  it('accepts many entries sharing one revision and one commit', () => {
    const state = applyOrThrow(
      applyOrThrow(applyOrThrow(openedWorkflow(), requestInvocation()), admitEvidence()),
      admitReview(),
    );

    expect(applyWorkflowEvent(state, observeHead(SHA_B)).outcome).toBe('APPLIED');
  });

  /* ---- finding 3: revision may never exceed sequence ---- */

  it.each([
    [2, 0],
    [1, 0],
    [5, 4],
    [WORKFLOW_BOUNDS.MAX_REVISION, 0],
  ])('refuses a state with revision %i and sequence %i', (revision, sequence) => {
    const forged = { ...openedWorkflow(), revision, sequence } as WorkflowState;

    for (const [, event] of everyEvent()) {
      expect(applyWorkflowEvent(forged, event).rejection).toBe('WORKFLOW_UNREADABLE');
    }
  });

  it.each([
    [0, 0],
    [1, 1],
    [1, 5],
  ])('accepts an otherwise valid state with revision %i and sequence %i', (revision, sequence) => {
    const forged = { ...openedWorkflow(), revision, sequence } as WorkflowState;

    expect(applyWorkflowEvent(forged, admitEvidence(buildVerdict())).outcome).toBe('APPLIED');
  });

  it('leaves legitimate histories unaffected by the counter invariant', () => {
    let state = openedWorkflow();
    for (const event of [requestInvocation(), admitEvidence(), admitReview(), observeHead(SHA_B)]) {
      state = applyOrThrow(state, event);
      expect(state.revision).toBeLessThanOrEqual(state.sequence);
    }
  });

  /* ---- finding 4: duplicate admission identities in deserialized state ---- */

  it('refuses a duplicate evidence admission identity already in state', () => {
    const admitted = applyOrThrow(openedWorkflow(), admitEvidence());
    const entry = admitted.evidence[0];
    const forged = {
      ...admitted,
      sequence: 2,
      // A copied object with the same value identity — not the same reference.
      evidence: [entry, { ...entry, admittedAtSequence: 2 }],
    } as unknown as WorkflowState;

    for (const [, event] of everyEvent()) {
      expect(applyWorkflowEvent(forged, event).rejection).toBe('WORKFLOW_UNREADABLE');
    }
    expect(applyWorkflowEvent(forged, admitEvidence()).state).toBe(forged);
  });

  it('refuses a duplicate review admission identity already in state', () => {
    const admitted = applyOrThrow(openedWorkflow(), admitReview());
    const entry = admitted.reviews[0];
    const forged = {
      ...admitted,
      sequence: 2,
      reviews: [entry, { ...entry, admittedAtSequence: 2 }],
    } as unknown as WorkflowState;

    expect(applyWorkflowEvent(forged, admitEvidence()).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it('accepts distinct admission ids sharing one revision', () => {
    const state = applyOrThrow(
      applyOrThrow(openedWorkflow(), admitEvidence()),
      admitEvidence(buildVerdict({ evidenceId: EVIDENCE_B })),
    );

    expect(state.evidence).toHaveLength(2);
    expect(applyWorkflowEvent(state, admitReview()).outcome).toBe('APPLIED');
  });

  it('still allows the same admission id at a different revision', () => {
    const admitted = applyOrThrow(openedWorkflow(), admitEvidence());
    const moved = applyOrThrow(admitted, observeHead(SHA_B));
    const readmitted = applyOrThrow(
      moved,
      admitEvidence(buildVerdict({ commitSha: SHA_B, targetHeadSha: SHA_B })),
    );

    expect(readmitted.evidence).toHaveLength(2);
    expect(readmitted.evidence[0]?.admittedAtRevision).toBe(0);
    expect(readmitted.evidence[1]?.admittedAtRevision).toBe(1);
    expect(readmitted.evidence[0]?.evidenceId).toBe(readmitted.evidence[1]?.evidenceId);
  });

  /* ---- readList: observable cardinality must match own-index structure ---- */

  /**
   * A workflow carrying two entries in each collection, so an under-reported
   * length has something to hide.
   */
  function populatedAggregate(): WorkflowState {
    let state = applyOrThrow(openedWorkflow(), requestInvocation());
    state = applyOrThrow(
      state,
      requestInvocation(buildInvocation({ invocationId: INVOCATION_B })),
    );
    state = applyOrThrow(state, admitEvidence());
    state = applyOrThrow(state, admitEvidence(buildVerdict({ evidenceId: EVIDENCE_B })));
    state = applyOrThrow(state, admitReview());
    return applyOrThrow(state, admitReview(buildReview({ reviewId: 'rv-second' })));
  }

  const COLLECTIONS = ['invocations', 'evidence', 'reviews'] as const;

  /** Swap one collection for a hostile list and apply an unrelated event. */
  function withList(
    state: WorkflowState,
    collection: (typeof COLLECTIONS)[number],
    list: unknown,
  ): ReturnType<typeof applyWorkflowEvent> {
    const forged = { ...state, [collection]: list } as unknown as WorkflowState;
    return applyWorkflowEvent(forged, closeWorkflow());
  }

  it.each(COLLECTIONS)('refuses %s whose proxy under-reports its length', (collection) => {
    const state = populatedAggregate();
    const real = [...state[collection]];
    const under = new Proxy(real, {
      get: (target, key): unknown => (key === 'length' ? 1 : Reflect.get(target, key)),
    });

    expect(real).toHaveLength(2);
    expect(withList(state, collection, under).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it.each(COLLECTIONS)('refuses %s reporting length 0 over a populated list', (collection) => {
    const state = populatedAggregate();
    const zero = new Proxy([...state[collection]], {
      get: (target, key): unknown => (key === 'length' ? 0 : Reflect.get(target, key)),
    });

    expect(withList(state, collection, zero).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it.each(COLLECTIONS)('refuses %s with own indices beyond the reported length', (collection) => {
    const state = populatedAggregate();
    const real = [...state[collection], state[collection][0]];

    // A genuine Array cannot hold an own index past its own length — lowering
    // `length` makes the engine delete the surplus — so the only way to present
    // this shape is a Proxy that under-reports while the target keeps them.
    const truncated = [...real];
    truncated.length = 1;
    expect(Object.hasOwn(truncated, 1)).toBe(false);

    const hiding = new Proxy(real, {
      get: (target, key): unknown => (key === 'length' ? 1 : Reflect.get(target, key)),
    });

    expect(real).toHaveLength(3);
    expect(Object.hasOwn(hiding, 1)).toBe(true);
    expect(Object.hasOwn(hiding, 2)).toBe(true);
    expect(withList(state, collection, hiding).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it.each(COLLECTIONS)('refuses %s carrying a stray non-index own property', (collection) => {
    const state = populatedAggregate();
    const strayed = [...state[collection]] as unknown[] & { smuggled?: unknown };
    strayed.smuggled = state[collection][0];

    expect(withList(state, collection, strayed).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it.each(COLLECTIONS)('refuses %s that over-reports its length', (collection) => {
    const state = populatedAggregate();
    const over = new Proxy([...state[collection]], {
      get: (target, key): unknown => (key === 'length' ? 5 : Reflect.get(target, key)),
    });

    expect(withList(state, collection, over).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it.each(COLLECTIONS)('refuses %s with an unstable length', (collection) => {
    const state = populatedAggregate();
    let reads = 0;
    const unstable = new Proxy([...state[collection]], {
      get: (target, key): unknown => {
        if (key === 'length') {
          reads += 1;
          return reads === 1 ? 2 : 0;
        }
        return Reflect.get(target, key);
      },
    });
    const result = withList(state, collection, unstable);

    // Either the structure check catches the disagreement, or the first read
    // stands and every entry is kept — never a silent shortening.
    if (result.outcome === 'APPLIED') {
      expect(result.state[collection]).toHaveLength(2);
    } else {
      expect(result.rejection).toBe('WORKFLOW_UNREADABLE');
    }
  });

  it.each(COLLECTIONS)('refuses %s with a throwing length', (collection) => {
    const state = populatedAggregate();
    const throwing = new Proxy([...state[collection]], {
      get: (target, key): unknown => {
        if (key === 'length') {
          throw new Error('hostile length');
        }
        return Reflect.get(target, key);
      },
    });

    expect(withList(state, collection, throwing).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it.each(COLLECTIONS)('refuses %s that is a revoked proxy', (collection) => {
    expect(withList(populatedAggregate(), collection, revokedProxy()).rejection).toBe(
      'WORKFLOW_UNREADABLE',
    );
  });

  it.each(COLLECTIONS)('refuses %s that is sparse with an inherited numeric entry', (collection) => {
    const state = populatedAggregate();
    const planted = state[collection][0];
    const holed: unknown[] = [];
    holed.length = 2;
    let observed: string | null = null;

    withPoisoned(Array.prototype, 0, planted, () => {
      withPoisoned(Array.prototype, 1, planted, () => {
        const result = withList(state, collection, holed);
        observed = result.rejection;
        // The inherited value must never become a durable own entry.
        expect(Object.hasOwn(holed, 0)).toBe(false);
        expect(JSON.stringify(result.state[collection])).not.toBe('[]');
      });
    });

    expect(observed).toBe('WORKFLOW_UNREADABLE');
  });

  it.each(COLLECTIONS)('accepts %s as an ordinary dense list with an accurate length', (collection) => {
    const state = populatedAggregate();
    const dense = stored([...state[collection]]);
    const result = withList(state, collection, dense);

    expect(result.outcome).toBe('APPLIED');
    expect(result.state[collection]).toHaveLength(2);
  });

  it('accepts genuinely empty collections', () => {
    const empty = openedWorkflow();

    expect(empty.invocations).toEqual([]);
    expect(applyWorkflowEvent(empty, admitEvidence()).outcome).toBe('APPLIED');
    expect(
      applyWorkflowEvent(
        { ...empty, evidence: stored([]), reviews: stored([]) } as WorkflowState,
        admitReview(),
      ).outcome,
    ).toBe('APPLIED');
  });

  it('requires a JSON round-tripped aggregate to have its collections re-frozen', () => {
    const state = populatedAggregate();
    const restored = JSON.parse(JSON.stringify(state)) as WorkflowState;

    // `JSON.parse` yields extensible arrays, and an extensible list cannot be
    // proven complete under the hostile-runtime model, so it is refused rather
    // than partially trusted. A caller restoring persisted state re-freezes the
    // three collections — which is the shape this layer itself always emits.
    expect(Object.isFrozen(restored.invocations)).toBe(false);
    expect(applyWorkflowEvent(restored, closeWorkflow()).rejection).toBe('WORKFLOW_UNREADABLE');

    const refrozen = {
      ...restored,
      invocations: stored(restored.invocations),
      evidence: stored(restored.evidence),
      reviews: stored(restored.reviews),
    } as WorkflowState;

    expect(applyWorkflowEvent(refrozen, closeWorkflow()).outcome).toBe('APPLIED');
    expect(applyWorkflowEvent(refrozen, closeWorkflow()).state.invocations).toHaveLength(2);
  });

  it('keeps capacity and duplicate scans working after the cardinality check', () => {
    const state = populatedAggregate();

    // Duplicate detection still fires on a structurally sound list.
    const duplicated = {
      ...state,
      evidence: stored([state.evidence[0], { ...state.evidence[0], admittedAtSequence: 9 }]),
      sequence: 20,
    } as unknown as WorkflowState;
    expect(applyWorkflowEvent(duplicated, closeWorkflow()).rejection).toBe('WORKFLOW_UNREADABLE');

    // Capacity still rejects rather than truncating.
    const full = Array.from({ length: WORKFLOW_BOUNDS.MAX_ADMITTED_EVIDENCE }, (_v, index) => ({
      evidenceId: `ev-${String(index)}`,
      kind: 'ci-result' as const,
      admittedAtCommitSha: SHA_A,
      admittedAtRevision: 0,
      admittedAtSequence: index + 1,
    }));
    const saturated = {
      ...openedWorkflow(),
      sequence: WORKFLOW_BOUNDS.MAX_ADMITTED_EVIDENCE,
      evidence: stored(full),
    } as WorkflowState;

    expect(applyWorkflowEvent(saturated, admitEvidence()).rejection).toBe('CAPACITY_EXCEEDED');
  });

  /* ---- a hostile list view may never hide a real own record ---- */

  /**
   * A Proxy that lies *consistently* about length, ownKeys, and descriptors,
   * exposing only a prefix of a larger target. Every channel agrees, so no
   * amount of cross-checking can contradict it — which is why acceptance rests
   * on non-extensibility instead.
   */
  function hidingView(target: readonly unknown[], visible: number): unknown {
    const shown: string[] = [];
    for (let index = 0; index < visible; index += 1) {
      shown.push(String(index));
    }
    shown.push('length');
    return new Proxy(target, {
      get: (t, key): unknown => (key === 'length' ? visible : Reflect.get(t, key)),
      ownKeys: (): ArrayLike<string | symbol> => shown,
      getOwnPropertyDescriptor: (t, key): PropertyDescriptor | undefined => {
        if (key === 'length') {
          return { value: visible, writable: true, enumerable: false, configurable: false };
        }
        if (typeof key === 'string' && Number(key) < visible) {
          return Reflect.getOwnPropertyDescriptor(t, key);
        }
        return undefined;
      },
      has: (t, key): boolean =>
        typeof key === 'string' && Number(key) >= visible ? false : Reflect.has(t, key),
    });
  }

  it.each(COLLECTIONS)('refuses %s whose view hides a trailing own record', (collection) => {
    const state = populatedAggregate();
    const real = [...state[collection]];
    const result = withList(state, collection, hidingView(real, 1));

    expect(real).toHaveLength(2);
    expect(result.rejection).toBe('WORKFLOW_UNREADABLE');
    expect(result.outcome).toBe('REJECTED');
  });

  it.each(COLLECTIONS)('refuses %s whose view hides a middle own record', (collection) => {
    const state = populatedAggregate();
    const three = [...state[collection], state[collection][0]];
    const middle = new Proxy(three, {
      get: (t, key): unknown =>
        key === 'length' ? 2 : Reflect.get(t, key === '1' ? '2' : key),
      ownKeys: (): ArrayLike<string | symbol> => ['0', '1', 'length'],
      getOwnPropertyDescriptor: (t, key): PropertyDescriptor | undefined => {
        if (key === 'length') {
          return { value: 2, writable: true, enumerable: false, configurable: false };
        }
        if (key === '0' || key === '1') {
          return Reflect.getOwnPropertyDescriptor(t, '0');
        }
        return undefined;
      },
    });

    expect(withList(state, collection, middle).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it.each(COLLECTIONS)('refuses %s presented as an extensible list', (collection) => {
    const state = populatedAggregate();
    const extensible = [...state[collection]];

    expect(Object.isExtensible(extensible)).toBe(true);
    expect(withList(state, collection, extensible).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it.each(COLLECTIONS)('accepts %s as a frozen list of the same records', (collection) => {
    const state = populatedAggregate();
    const result = withList(state, collection, Object.freeze([...state[collection]]));

    expect(result.outcome).toBe('APPLIED');
    expect(result.state[collection]).toHaveLength(2);
  });

  it.each(COLLECTIONS)('refuses %s that is merely sealed, not frozen', (collection) => {
    const state = populatedAggregate();

    // A sealed array keeps its elements writable, and the `get` invariant binds
    // a Proxy only for a non-configurable *and non-writable* property — so a
    // sealed view can substitute a record while every other channel stays
    // compliant. Non-extensibility alone is therefore not sufficient.
    for (const weaken of [Object.seal, Object.preventExtensions]) {
      const weakened = weaken([...state[collection]]);

      expect(Object.isExtensible(weakened)).toBe(false);
      expect(Object.isFrozen(weakened)).toBe(false);
      expect(withList(state, collection, weakened).rejection).toBe('WORKFLOW_UNREADABLE');
    }
  });

  it('refuses a sealed view that substitutes a record for a real entry', () => {
    const state = populatedAggregate();
    const real = [...state.invocations];
    const decoy = { ...real[0], invocationId: 'i-substituted', providerId: 'attacker' };
    const substituting = new Proxy(Object.seal([...real]), {
      get: (target, key): unknown => (key === '0' ? decoy : Reflect.get(target, key)),
    });
    const result = withList(state, 'invocations', substituting);

    expect(result.rejection).toBe('WORKFLOW_UNREADABLE');
    expect(result.outcome).toBe('REJECTED');

    // The real entry is never displaced, and the decoy never becomes durable.
    const ids = state.invocations.map((tracked) => tracked.invocationId);
    expect(ids).toContain(INVOCATION_A);
    expect(ids).not.toContain('i-substituted');
  });

  it('cannot have an element substituted once the list is frozen', () => {
    const state = populatedAggregate();
    const real = [...state.invocations];
    const decoy = { ...real[0], invocationId: 'i-substituted' };
    const overFrozen = new Proxy(Object.freeze([...real]), {
      get: (target, key): unknown => (key === '0' ? decoy : Reflect.get(target, key)),
    });

    // The engine itself refuses the lie for a non-writable, non-configurable
    // element, so the substitution cannot even be observed.
    expect(() => overFrozen[0]).toThrow(TypeError);
    expect(withList(state, 'invocations', overFrozen).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it.each(COLLECTIONS)('refuses %s whose ownKeys trap throws', (collection) => {
    const state = populatedAggregate();
    const throwing = new Proxy(Object.freeze([...state[collection]]), {
      ownKeys: (): never => {
        throw new Error('hostile ownKeys');
      },
    });

    expect(withList(state, collection, throwing).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it.each(COLLECTIONS)('refuses %s whose key view is unstable', (collection) => {
    const state = populatedAggregate();
    let reads = 0;
    const unstable = new Proxy([...state[collection]], {
      ownKeys: (t): ArrayLike<string | symbol> => {
        reads += 1;
        return reads === 1 ? ['0', 'length'] : Reflect.ownKeys(t);
      },
    });

    expect(withList(state, collection, unstable).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it('loses no record through a later legitimate transition', () => {
    const state = populatedAggregate();
    const hidden = withList(state, 'invocations', hidingView([...state.invocations], 1));

    expect(hidden.rejection).toBe('WORKFLOW_UNREADABLE');

    // The genuine aggregate still carries both records after further work.
    const advanced = applyOrThrow(state, observeHead(SHA_B));

    expect(advanced.invocations).toHaveLength(2);
    expect(advanced.evidence).toHaveLength(2);
    expect(advanced.reviews).toHaveLength(2);
    expect(Object.isFrozen(advanced.invocations)).toBe(true);
  });

  /* ---- a stamped record may not precede the transition that created it ---- */

  /**
   * Reaching revision R costs R applied `HEAD_OBSERVED` transitions, each
   * consuming a distinct sequence slot, so the R-th advance sat at slot >= R
   * and a record stamped at revision R was created by a later transition still:
   *
   *     recordedSequence > recordedRevision
   *
   * The bound is tight — open, one HEAD advance at slot 1, then a request at
   * slot 2 legitimately stamps revision 1 with sequence 2.
   */
  function stampedState(overrides: Record<string, unknown>): WorkflowState {
    return {
      ...openedWorkflow(),
      boundCommitSha: SHA_B,
      ...overrides,
    } as unknown as WorkflowState;
  }

  function trackedAt(revision: number, sequence: number): unknown {
    return {
      invocationId: INVOCATION_A,
      targetCommitSha: SHA_B,
      purpose: 'review',
      providerId: 'codex',
      agentId: 'agent-1',
      requestedAtRevision: revision,
      requestedAtSequence: sequence,
      state: 'REQUESTED',
      reportedStatus: null,
      reportedAtRevision: null,
      reportedAtSequence: null,
    };
  }

  const admittedAt = (revision: number, sequence: number): unknown => ({
    evidenceId: EVIDENCE_A,
    kind: 'ci-result',
    admittedAtCommitSha: SHA_B,
    admittedAtRevision: revision,
    admittedAtSequence: sequence,
  });

  const reviewedAt = (revision: number, sequence: number): unknown => ({
    reviewId: REVIEW_A,
    admittedAtCommitSha: SHA_B,
    admittedAtRevision: revision,
    admittedAtSequence: sequence,
  });

  it.each([
    ['an invocation', (r: number, q: number) => ({ invocations: stored([trackedAt(r, q)]) })],
    ['an evidence admission', (r: number, q: number) => ({ evidence: stored([admittedAt(r, q)]) })],
    ['a review admission', (r: number, q: number) => ({ reviews: stored([reviewedAt(r, q)]) })],
  ])('refuses %s stamped at revision 1 with sequence 1', (_name, build) => {
    const forged = stampedState({ revision: 1, sequence: 2, ...build(1, 1) });

    expect(applyWorkflowEvent(forged, closeWorkflow()).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it.each([
    ['an invocation', (r: number, q: number) => ({ invocations: stored([trackedAt(r, q)]) })],
    ['an evidence admission', (r: number, q: number) => ({ evidence: stored([admittedAt(r, q)]) })],
    ['a review admission', (r: number, q: number) => ({ reviews: stored([reviewedAt(r, q)]) })],
  ])('accepts %s stamped at revision 1 with sequence 2', (_name, build) => {
    const legal = stampedState({ revision: 1, sequence: 2, ...build(1, 2) });

    expect(applyWorkflowEvent(legal, closeWorkflow()).outcome).toBe('APPLIED');
  });

  it.each([
    ['an invocation', (r: number, q: number) => ({ invocations: stored([trackedAt(r, q)]) })],
    ['an evidence admission', (r: number, q: number) => ({ evidence: stored([admittedAt(r, q)]) })],
    ['a review admission', (r: number, q: number) => ({ reviews: stored([reviewedAt(r, q)]) })],
  ])('accepts %s stamped at revision 0 with sequence 1', (_name, build) => {
    // Bound to SHA_B so the revision-0 entries match their own commit binding.
    const legal = stampedState({ sequence: 1, ...build(0, 1) });

    expect(applyWorkflowEvent(legal, closeWorkflow()).outcome).toBe('APPLIED');
  });

  it.each([
    [3, 2],
    [3, 3],
    [5, 1],
    [2, 2],
  ])('refuses a record stamped at revision %i with sequence %i', (revision, sequence) => {
    const forged = stampedState({
      revision,
      sequence: revision + 2,
      evidence: stored([admittedAt(revision, sequence)]),
    });

    expect(applyWorkflowEvent(forged, closeWorkflow()).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it('refuses a report stamp that precedes its own revision', () => {
    // The request sits at revision 0 / sequence 1 so the report at sequence 2
    // clears the pre-existing `reportedAtSequence > requestedAtSequence` rule.
    // The only rule it breaks is `reportedAtSequence > reportedAtRevision`.
    const request = trackedAt(0, 1) as Record<string, unknown>;
    const reported = {
      ...request,
      state: 'REPORTED',
      reportedStatus: 'reported-complete',
      reportedAtRevision: 2,
      reportedAtSequence: 2,
    };

    expect(reported.reportedAtSequence).toBeGreaterThan(request.requestedAtSequence as number);
    expect(reported.reportedAtRevision).toBeGreaterThanOrEqual(
      request.requestedAtRevision as number,
    );

    const forged = stampedState({ revision: 2, sequence: 6, invocations: stored([reported]) });

    expect(applyWorkflowEvent(forged, closeWorkflow()).rejection).toBe('WORKFLOW_UNREADABLE');

    // Moving only the report stamp past its own revision makes it legal again.
    const legal = stampedState({
      revision: 2,
      sequence: 6,
      invocations: stored([{ ...reported, reportedAtSequence: 3 }]),
    });

    expect(applyWorkflowEvent(legal, closeWorkflow()).outcome).toBe('APPLIED');
  });

  it('accepts a report whose stamps follow both its request and its revision', () => {
    const legal = stampedState({
      revision: 2,
      sequence: 6,
      invocations: stored([
        {
          ...(trackedAt(2, 3) as Record<string, unknown>),
          state: 'REPORTED',
          reportedStatus: 'reported-complete',
          reportedAtRevision: 2,
          reportedAtSequence: 4,
        },
      ]),
    });

    expect(applyWorkflowEvent(legal, closeWorkflow()).outcome).toBe('APPLIED');
  });

  it('keeps a real multi-HEAD history valid and its stamps ahead of their revisions', () => {
    let state = applyOrThrow(openedWorkflow(), requestInvocation());
    state = applyOrThrow(state, observeHead(SHA_B));
    state = applyOrThrow(
      state,
      requestInvocation(buildInvocation({ invocationId: INVOCATION_B, targetCommitSha: SHA_B })),
    );
    state = applyOrThrow(
      state,
      admitEvidence(buildVerdict({ commitSha: SHA_B, targetHeadSha: SHA_B })),
    );
    state = applyOrThrow(state, observeHead(SHA_C));
    state = applyOrThrow(
      state,
      admitReview(buildReview({ reviewId: 'rv-late', reviewedCommitSha: SHA_C })),
    );

    for (const tracked of state.invocations) {
      expect(tracked.requestedAtSequence).toBeGreaterThan(tracked.requestedAtRevision);
    }
    for (const admission of [...state.evidence, ...state.reviews]) {
      expect(admission.admittedAtSequence).toBeGreaterThan(admission.admittedAtRevision);
    }
    expect(state.revision).toBe(2);
    expect(applyWorkflowEvent(state, closeWorkflow()).outcome).toBe('APPLIED');
  });

  it('still enforces global stamp uniqueness alongside the revision relation', () => {
    const forged = stampedState({
      revision: 1,
      sequence: 4,
      evidence: stored([admittedAt(1, 3)]),
      reviews: stored([reviewedAt(1, 3)]),
    });

    expect(applyWorkflowEvent(forged, closeWorkflow()).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  /* ---- P1: emptiness of invalidFields must be provable, not reported ---- */

  /** A gated workflow plus a forged human-decision verdict carrying `invalidFields`. */
  function gateAttack(invalidFields: unknown): {
    readonly state: WorkflowState;
    readonly result: ReturnType<typeof applyWorkflowEvent>;
  } {
    const state = applyOrThrow(openedWorkflow(), openHumanGate());
    return {
      state,
      result: applyWorkflowEvent(
        state,
        admitEvidence(buildHumanDecisionVerdict({ invalidFields } as never)),
      ),
    };
  }

  it('refuses a list proxy reporting length 0 over a populated target', () => {
    const lying = new Proxy(['commitSha'], {
      get: (target, key): unknown => (key === 'length' ? 0 : Reflect.get(target, key)),
    });
    const { state, result } = gateAttack(lying);

    expect(result.rejection).toBe('EVIDENCE_NOT_CURRENT');
    expect(result.invalidFields).toEqual(['verdict.invalidFields']);
    expect(result.state).toBe(state);
    expect(result.state.status).toBe('AWAITING_HUMAN_DECISION');
  });

  it.each([
    [
      'a length lie over three elements',
      (): unknown =>
        new Proxy(['a', 'b', 'c'], {
          get: (target, key): unknown => (key === 'length' ? 0 : Reflect.get(target, key)),
        }),
    ],
    [
      'a length lie larger than the target',
      (): unknown =>
        new Proxy([], {
          get: (target, key): unknown => (key === 'length' ? 5 : Reflect.get(target, key)),
        }),
    ],
    [
      'an unstable length',
      (): unknown => {
        let reads = 0;
        return new Proxy(['x'], {
          get: (target, key): unknown => {
            if (key === 'length') {
              reads += 1;
              return reads === 1 ? 0 : 9;
            }
            return Reflect.get(target, key);
          },
        });
      },
    ],
    [
      'a throwing length',
      (): unknown =>
        new Proxy(['x'], {
          get: (target, key): unknown => {
            if (key === 'length') {
              throw new Error('hostile length');
            }
            return Reflect.get(target, key);
          },
        }),
    ],
    [
      'an ownKeys trap hiding the element',
      (): unknown =>
        new Proxy(['x'], {
          get: (target, key): unknown => (key === 'length' ? 0 : Reflect.get(target, key)),
          ownKeys: (): ArrayLike<string | symbol> => ['length'],
          getOwnPropertyDescriptor: (target, key): PropertyDescriptor | undefined =>
            key === 'length'
              ? { value: 0, writable: true, enumerable: false, configurable: false }
              : undefined,
        }),
    ],
    ['an ordinary non-empty list', (): unknown => ['commitSha']],
    [
      'a sparse single-hole list',
      (): unknown => {
        const holed: unknown[] = [];
        holed.length = 1;
        return holed;
      },
    ],
    ['an object inheriting from an array', (): unknown => Object.create([]) as unknown],
    ['an array-like plain object', (): unknown => ({ length: 0 })],
    ['a revoked proxy', (): unknown => revokedProxy()],
    ['an extensible empty array', (): unknown => []],
  ])('refuses a CURRENT verdict whose invalidFields is %s', (_name, build) => {
    const { state, result } = gateAttack(build());

    expect(result.rejection).toBe('EVIDENCE_NOT_CURRENT');
    expect(result.state).toBe(state);
    expect(result.state.status).toBe('AWAITING_HUMAN_DECISION');
    expect(result.state.evidence).toEqual([]);
  });

  it('accepts a frozen empty list, exactly as PR 004 emits it', () => {
    const { result } = gateAttack(Object.freeze([]));

    expect(result.outcome).toBe('APPLIED');
    expect(result.state.status).toBe('OPEN');
  });

  it('accepts the genuine list a real PR 004 verdict carries', () => {
    const genuine = evaluateEvidenceFreshness(
      {
        evidenceId: EVIDENCE_A,
        repositoryId: REPO_A,
        commitSha: SHA_A,
        kind: 'human-decision',
        source: 'human',
        reference: 'd1',
        observedAt: '2026-01-01T00:00:00.000Z',
      },
      { repositoryId: REPO_A, currentHeadSha: SHA_A },
    );
    const gated = applyOrThrow(openedWorkflow(), openHumanGate());

    expect(Object.isFrozen(genuine.invalidFields)).toBe(true);
    expect(applyWorkflowEvent(gated, admitEvidence(genuine)).state.status).toBe('OPEN');
  });

  /* ---- P2: every retained transition sequence stamp is unique ---- */

  /** A workflow carrying one of every sequence-stamped record. */
  function stampedAggregate(): WorkflowState {
    let state = applyOrThrow(openedWorkflow(), requestInvocation());
    state = applyOrThrow(state, admitEvidence());
    state = applyOrThrow(state, admitReview());
    return applyOrThrow(state, reportInvocation());
  }

  it('stamps each applied transition with a distinct sequence', () => {
    const state = stampedAggregate();

    expect(state.sequence).toBe(4);
    expect(state.invocations[0]?.requestedAtSequence).toBe(1);
    expect(state.evidence[0]?.admittedAtSequence).toBe(2);
    expect(state.reviews[0]?.admittedAtSequence).toBe(3);
    expect(state.invocations[0]?.reportedAtSequence).toBe(4);
  });

  it.each([
    [
      'evidence reusing the request stamp',
      (s: WorkflowState) => ({ ...s, evidence: stored([{ ...s.evidence[0], admittedAtSequence: 1 }]) }),
    ],
    [
      'review reusing the request stamp',
      (s: WorkflowState) => ({ ...s, reviews: stored([{ ...s.reviews[0], admittedAtSequence: 1 }]) }),
    ],
    [
      'review reusing the evidence stamp',
      (s: WorkflowState) => ({ ...s, reviews: stored([{ ...s.reviews[0], admittedAtSequence: 2 }]) }),
    ],
    [
      'report reusing the evidence stamp',
      (s: WorkflowState) => ({
        ...s,
        invocations: stored([{ ...s.invocations[0], reportedAtSequence: 2 }]),
      }),
    ],
    [
      'report reusing the review stamp',
      (s: WorkflowState) => ({
        ...s,
        invocations: stored([{ ...s.invocations[0], reportedAtSequence: 3 }]),
      }),
    ],
    [
      'two evidence admissions sharing a stamp',
      (s: WorkflowState) => ({
        ...s,
        evidence: stored([s.evidence[0], { ...s.evidence[0], evidenceId: EVIDENCE_B }]),
      }),
    ],
    [
      'two reviews sharing a stamp',
      (s: WorkflowState) => ({
        ...s,
        reviews: stored([s.reviews[0], { ...s.reviews[0], reviewId: 'rv-other' }]),
      }),
    ],
  ])('refuses a state where %s', (_name, forge) => {
    const forged = forge(stampedAggregate()) as unknown as WorkflowState;

    for (const [, event] of everyEvent()) {
      const result = applyWorkflowEvent(forged, event);
      expect(result.rejection).toBe('WORKFLOW_UNREADABLE');
      expect(result.state).toBe(forged);
    }
  });

  it('refuses two invocations sharing a request stamp', () => {
    const base = stampedAggregate();
    const tracked = base.invocations[0];
    const forged = {
      ...base,
      invocations: stored([
        tracked,
        {
          ...tracked,
          invocationId: INVOCATION_B,
          state: 'REQUESTED',
          reportedStatus: null,
          reportedAtRevision: null,
          reportedAtSequence: null,
        },
      ]),
    } as unknown as WorkflowState;

    expect(applyWorkflowEvent(forged, admitEvidence()).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it('accepts a legitimate history whose stamps are all distinct', () => {
    const state = stampedAggregate();
    const moved = applyOrThrow(state, observeHead(SHA_B));

    // HEAD_OBSERVED advances the sequence while stamping nothing, so the gap it
    // leaves must not be mistaken for a violation.
    expect(moved.sequence).toBe(5);
    expect(moved.invocations[0]?.requestedAtSequence).toBe(1);
    expect(moved.evidence[0]?.admittedAtSequence).toBe(2);
    expect(
      applyWorkflowEvent(
        moved,
        admitEvidence(
          buildVerdict({ evidenceId: EVIDENCE_B, commitSha: SHA_B, targetHeadSha: SHA_B }),
        ),
      ).outcome,
    ).toBe('APPLIED');
  });

  it('keeps historical stamps intact across a HEAD advance', () => {
    const moved = applyOrThrow(stampedAggregate(), observeHead(SHA_B));
    const later = applyOrThrow(
      moved,
      admitEvidence(
        buildVerdict({ evidenceId: EVIDENCE_B, commitSha: SHA_B, targetHeadSha: SHA_B }),
      ),
    );

    expect(later.evidence[0]?.admittedAtSequence).toBe(2);
    expect(later.evidence[1]?.admittedAtSequence).toBe(6);
    expect(later.invocations[0]?.requestedAtSequence).toBe(1);
    expect(later.invocations[0]?.reportedAtSequence).toBe(4);
  });

  it('cannot have duplicate detection bypassed through a hostile prototype', () => {
    const admitted = applyOrThrow(openedWorkflow(), admitEvidence());
    const entry = admitted.evidence[0];
    const forged = {
      ...admitted,
      sequence: 2,
      evidence: [entry, { ...entry, admittedAtSequence: 2 }],
    } as unknown as WorkflowState;
    let observed: unknown;

    withPoisoned(Array.prototype, 'includes', () => false, () => {
      withPoisoned(Array.prototype, 'indexOf', () => -1, () => {
        observed = applyWorkflowEvent(forged, admitReview()).rejection;
      });
    });

    expect(observed).toBe('WORKFLOW_UNREADABLE');
  });
});

describe('group K — bounds', () => {
  it('pins the identifier bound to PR 005 and PR 006', () => {
    expect(WORKFLOW_BOUNDS.MAX_IDENTIFIER_LENGTH).toBe(REVIEW_BOUNDS.MAX_IDENTIFIER_LENGTH);
    expect(WORKFLOW_BOUNDS.MAX_IDENTIFIER_LENGTH).toBe(INVOCATION_BOUNDS.MAX_IDENTIFIER_LENGTH);
  });

  it('carries a maximum-length identifier through unchanged', () => {
    const maxId = oversized(WORKFLOW_BOUNDS.MAX_IDENTIFIER_LENGTH);
    const state = applyOrThrow(
      openedWorkflow(),
      requestInvocation(buildInvocation({ invocationId: maxId })),
    );

    expect(state.invocations[0]?.invocationId).toBe(maxId);
  });

  it.each([
    ['invocationId', 'invocation.invocationId'],
    ['repositoryId', 'invocation.repositoryId'],
    ['targetCommitSha', 'invocation.targetCommitSha'],
    ['providerId', 'invocation.providerId'],
    ['agentId', 'invocation.agentId'],
    ['requestedAt', 'invocation.requestedAt'],
  ])('rejects an oversized %s', (field, path) => {
    const result = applyWorkflowEvent(
      openedWorkflow(),
      requestInvocation(withRawInvocationField(field, oversized(257))),
    );

    expect(result.rejection).toBe('EVENT_PAYLOAD_INVALID');
    expect(result.invalidFields).toContain(path);
  });

  it('refuses a new invocation once the tracked bound is reached', () => {
    let state = openedWorkflow();
    for (let index = 0; index < WORKFLOW_BOUNDS.MAX_TRACKED_INVOCATIONS; index += 1) {
      state = applyOrThrow(
        state,
        requestInvocation(buildInvocation({ invocationId: `inv-${String(index)}` })),
      );
    }
    const result = applyWorkflowEvent(
      state,
      requestInvocation(buildInvocation({ invocationId: 'inv-overflow' })),
    );

    expect(state.invocations).toHaveLength(WORKFLOW_BOUNDS.MAX_TRACKED_INVOCATIONS);
    expect(result.rejection).toBe('CAPACITY_EXCEEDED');
    expect(result.state).toBe(state);
  });

  /** A synthetic but structurally valid state with `count` evidence admissions. */
  function withEvidenceAdmissions(count: number): WorkflowState {
    const evidence = Array.from({ length: count }, (_value, index) => ({
      evidenceId: `ev-${String(index)}`,
      kind: 'ci-result' as const,
      admittedAtCommitSha: SHA_A,
      admittedAtRevision: 0,
      admittedAtSequence: index + 1,
    }));
    return { ...openedWorkflow(), sequence: count, evidence: stored(evidence) } as WorkflowState;
  }

  it('refuses a new admission once the evidence bound is reached', () => {
    const state = withEvidenceAdmissions(WORKFLOW_BOUNDS.MAX_ADMITTED_EVIDENCE);
    const result = applyWorkflowEvent(state, admitEvidence());

    expect(result.rejection).toBe('CAPACITY_EXCEEDED');
    expect(result.state).toBe(state);
  });

  it('still admits one below the evidence bound', () => {
    const state = withEvidenceAdmissions(WORKFLOW_BOUNDS.MAX_ADMITTED_EVIDENCE - 1);

    expect(applyWorkflowEvent(state, admitEvidence()).outcome).toBe('APPLIED');
  });

  it('refuses a state whose list exceeds its own bound', () => {
    const state = withEvidenceAdmissions(WORKFLOW_BOUNDS.MAX_ADMITTED_EVIDENCE + 1);

    expect(applyWorkflowEvent(state, admitReview()).rejection).toBe('WORKFLOW_UNREADABLE');
  });

  it('refuses a new admission once the review bound is reached', () => {
    const reviews = Array.from({ length: WORKFLOW_BOUNDS.MAX_ADMITTED_REVIEWS }, (_v, index) => ({
      reviewId: `rev-${String(index)}`,
      admittedAtCommitSha: SHA_A,
      admittedAtRevision: 0,
      admittedAtSequence: index + 1,
    }));
    const state = {
      ...openedWorkflow(),
      sequence: WORKFLOW_BOUNDS.MAX_ADMITTED_REVIEWS,
      reviews: stored(reviews),
    } as WorkflowState;

    expect(applyWorkflowEvent(state, admitReview()).rejection).toBe('CAPACITY_EXCEEDED');
  });

  it('refuses to advance past the sequence bound', () => {
    const state = { ...openedWorkflow(), sequence: WORKFLOW_BOUNDS.MAX_SEQUENCE } as WorkflowState;

    for (const [, event] of everyEvent()) {
      const result = applyWorkflowEvent(state, event);
      expect(result.outcome).toBe('REJECTED');
      expect(result.state).toBe(state);
    }
  });

  it('refuses to advance past the revision bound', () => {
    // `sequence` must be at least `revision`: every revision advance is itself
    // an applied transition, so a state at the revision bound has advanced the
    // sequence at least as far.
    const state = {
      ...openedWorkflow(),
      revision: WORKFLOW_BOUNDS.MAX_REVISION,
      sequence: WORKFLOW_BOUNDS.MAX_REVISION,
    } as WorkflowState;

    expect(applyWorkflowEvent(state, observeHead(SHA_B)).rejection).toBe('CAPACITY_EXCEEDED');
  });
});

describe('group L — purity, immutability, and determinism', () => {
  it('returns the identical state reference for every rejection', () => {
    const states: readonly WorkflowState[] = [
      requested(),
      applyOrThrow(requested(), openHumanGate()),
      applyOrThrow(requested(), closeWorkflow()),
    ];

    for (const state of states) {
      for (const [, event] of everyEvent()) {
        const result = applyWorkflowEvent(state, event);
        if (result.outcome === 'REJECTED') {
          expect(result.state).toBe(state);
        }
      }
      expect(applyWorkflowEvent(state, { kind: 'NOPE' } as never).state).toBe(state);
    }
  });

  it('never mutates the state or the event', () => {
    for (const [, event] of everyEvent()) {
      const state = requested();
      const stateBefore = JSON.stringify(state);
      const eventBefore = JSON.stringify(event);

      applyWorkflowEvent(state, event);

      expect(JSON.stringify(state)).toBe(stateBefore);
      expect(JSON.stringify(event)).toBe(eventBefore);
    }
  });

  it('produces an identical result when applied twice to the same state', () => {
    for (const [, event] of everyEvent()) {
      const state = requested();

      expect(applyWorkflowEvent(state, event)).toEqual(applyWorkflowEvent(state, event));
    }
  });

  it('round-trips through JSON unchanged', () => {
    let state = requested();
    state = applyOrThrow(state, reportInvocation());
    state = applyOrThrow(state, admitEvidence());
    state = applyOrThrow(state, admitReview());
    state = applyOrThrow(state, observeHead(SHA_B));

    expect(JSON.parse(JSON.stringify(state))).toEqual(state);
  });

  it('deeply freezes every applied state', () => {
    const state = applyOrThrow(
      applyOrThrow(applyOrThrow(requested(), reportInvocation()), admitEvidence()),
      admitReview(),
    );

    expect(Object.isFrozen(state)).toBe(true);
    expect(Object.isFrozen(state.invocations)).toBe(true);
    expect(Object.isFrozen(state.evidence)).toBe(true);
    expect(Object.isFrozen(state.reviews)).toBe(true);
    expect(Object.isFrozen(state.invocations[0])).toBe(true);
    expect(Object.isFrozen(state.evidence[0])).toBe(true);
    expect(Object.isFrozen(state.reviews[0])).toBe(true);
  });

  it('freezes the transition result and its invalid-field list', () => {
    const result = applyWorkflowEvent(openedWorkflow(), observeHead(SHA_A));

    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.invalidFields)).toBe(true);
  });

  it('drops any extra property a caller attached to a state', () => {
    const smuggled = { ...openedWorkflow(), mayMerge: true } as unknown as WorkflowState;
    const result = applyWorkflowEvent(smuggled, admitEvidence());

    expect(result.outcome).toBe('APPLIED');
    expect(Object.keys(result.state)).not.toContain('mayMerge');
  });

  it('keeps humanGateOpenedAtRevision null or equal to revision at every step', () => {
    const steps: readonly WorkflowEvent[] = [
      requestInvocation(),
      openHumanGate(),
      reportInvocation(),
      observeHead(SHA_B),
      openHumanGate(SHA_B),
      admitEvidence(buildHumanDecisionVerdict({ targetHeadSha: SHA_B, commitSha: SHA_B })),
      admitReview(buildReview({ reviewedCommitSha: SHA_B })),
      openHumanGate(SHA_B),
      closeWorkflow('HUMAN_DECISION_RECORDED'),
    ];
    let state = openedWorkflow();

    for (const event of steps) {
      state = applyOrThrow(state, event);
      expect(
        state.humanGateOpenedAtRevision === null ||
          state.humanGateOpenedAtRevision === state.revision,
      ).toBe(true);
    }

    expect(state.status).toBe('CLOSED');
  });

  it('advances the sequence by exactly one per applied transition', () => {
    let state = openedWorkflow();
    let expected = 0;

    for (const event of [
      requestInvocation(),
      reportInvocation(),
      admitEvidence(),
      admitReview(),
      observeHead(SHA_B),
      openHumanGate(SHA_B),
      closeWorkflow(),
    ]) {
      state = applyOrThrow(state, event);
      expected += 1;
      expect(state.sequence).toBe(expected);
    }
  });

  it('reads no clock, randomness, environment, or host API', () => {
    for (const file of ['workflow.ts', 'workflow-transitions.ts']) {
      const source = stripComments(
        readFileSync(new URL(`../../src/domain/${file}`, import.meta.url), 'utf8'),
      );

      for (const forbidden of [
        'Date',
        'Math.random',
        'process',
        'globalThis',
        'require(',
        'node:',
        'async ',
        'await ',
        'Promise',
        'setTimeout',
        'crypto',
        'randomUUID',
      ]) {
        expect(source).not.toContain(forbidden);
      }
    }
  });

  it('returns synchronously, never a thenable', () => {
    const result: unknown = applyWorkflowEvent(openedWorkflow(), admitEvidence());

    expect(result).not.toHaveProperty('then');
    expect(openWorkflow(buildBinding())).not.toHaveProperty('then');
  });
});

describe('group M — forbidden vocabulary', () => {
  /** Every event payload, with every banned field name planted on it. */
  function planted<T extends object>(base: T): T {
    const target = { ...base } as Record<string, unknown>;
    for (const key of FORBIDDEN_STATE_KEYS) {
      target[key] = true;
    }
    for (const value of FORBIDDEN_STATE_VALUES) {
      target[`planted_${value}`] = value;
    }
    return target as T;
  }

  it('never places a banned key in a serialized state', () => {
    let state = openedWorkflow();
    state = applyOrThrow(state, requestInvocation(planted(buildInvocation())));
    state = applyOrThrow(state, reportInvocation(planted(buildReport())));
    state = applyOrThrow(state, admitEvidence(planted(buildVerdict())));
    state = applyOrThrow(state, admitReview(planted(buildReview())));

    const keys = new Set<string>();
    JSON.parse(JSON.stringify(state), function collect(this: unknown, key: string, value: unknown) {
      if (key !== '') {
        keys.add(key);
      }
      return value;
    });

    for (const banned of FORBIDDEN_STATE_KEYS) {
      expect(keys.has(banned)).toBe(false);
    }
  });

  it('never places a policy or freshness value in a serialized state', () => {
    let state = openedWorkflow();
    state = applyOrThrow(state, requestInvocation(planted(buildInvocation())));
    state = applyOrThrow(state, admitEvidence(planted(buildVerdict())));
    const serialized = JSON.stringify(state);

    for (const banned of FORBIDDEN_STATE_VALUES) {
      expect(serialized).not.toContain(banned);
    }
  });

  it('exposes no boolean field anywhere in a state', () => {
    const state = applyOrThrow(
      applyOrThrow(requested(), reportInvocation()),
      admitEvidence(),
    );
    const booleans: string[] = [];

    JSON.parse(JSON.stringify(state), function collect(this: unknown, key: string, value: unknown) {
      if (typeof value === 'boolean') {
        booleans.push(key);
      }
      return value;
    });

    expect(booleans).toEqual([]);
  });

  it('declares no status, event, or rejection name that implies authority', () => {
    const names = [...WORKFLOW_STATUSES, ...WORKFLOW_EVENT_KINDS, ...TRANSITION_REJECTIONS];

    for (const name of names) {
      expect(name).not.toMatch(/MERGE|DEPLOY|APPROV|AUTHORIZ|ALLOW|DENY|WRITE|MUTAT/i);
    }
  });

  it('keeps the rejection vocabulary complete and in declaration order', () => {
    expect(TRANSITION_REJECTIONS).toEqual([
      'WORKFLOW_UNREADABLE',
      'EVENT_UNREADABLE',
      'EVENT_KIND_UNKNOWN',
      'EVENT_PAYLOAD_INVALID',
      'WORKFLOW_CLOSED',
      'WORKFLOW_AWAITING_HUMAN',
      'HUMAN_GATE_ALREADY_OPEN',
      'BINDING_MISMATCH',
      'INPUT_NOT_INGESTED',
      'EVIDENCE_NOT_CURRENT',
      'DUPLICATE_INVOCATION_ID',
      'UNKNOWN_INVOCATION',
      'INVOCATION_ALREADY_REPORTED',
      'DUPLICATE_ADMISSION',
      'HEAD_UNCHANGED',
      'CAPACITY_EXCEEDED',
    ]);
  });

  it('keeps the status and event vocabularies minimal', () => {
    expect(WORKFLOW_STATUSES).toEqual(['OPEN', 'AWAITING_HUMAN_DECISION', 'CLOSED']);
    expect(WORKFLOW_EVENT_KINDS).toEqual([
      'INVOCATION_REQUESTED',
      'INVOCATION_REPORTED',
      'REVIEW_ADMITTED',
      'EVIDENCE_ADMITTED',
      'HEAD_OBSERVED',
      'HUMAN_GATE_OPENED',
      'CLOSE_REQUESTED',
    ]);
  });

  it('exports no projection, recommendation, or next-action API', async () => {
    const domain: Record<string, unknown> = await import('../../src/domain/index.js');

    for (const name of Object.keys(domain)) {
      expect(name).not.toMatch(/^(legalEventKinds|nextAction|recommend|select|route|plan)/);
    }
  });
});

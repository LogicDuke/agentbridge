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

    if (result.outcome === 'APPLIED') {
      expect(result.state.invocations[0]?.targetCommitSha).toBe(SHA_A);
    } else {
      expect(result.rejection).toBe('BINDING_MISMATCH');
    }
  });

  it('never lets an unstable evidence verdict be admitted under a different id', () => {
    const verdict = withUnstableGetter(buildVerdict(), 'evidenceId', [EVIDENCE_A, 'ev-forged']);
    const result = applyWorkflowEvent(openedWorkflow(), admitEvidence(verdict));

    if (result.outcome === 'APPLIED') {
      expect(result.state.evidence[0]?.evidenceId).toBe(EVIDENCE_A);
    } else {
      expect(result.outcome).toBe('REJECTED');
    }
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
        [listName]: [{ ...admission, admittedAtCommitSha: SHA_B }],
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
        [listName]: [{ ...admission, admittedAtCommitSha: SHA_A }],
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
    return { ...openedWorkflow(), sequence: count, evidence } as WorkflowState;
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
      reviews,
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
    const state = {
      ...openedWorkflow(),
      revision: WORKFLOW_BOUNDS.MAX_REVISION,
      sequence: 1,
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

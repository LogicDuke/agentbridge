import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { projectCockpitAutoflow } from '../../src/cockpit/autoflow-projection.js';
import type { WorkflowState } from '../../src/domain/index.js';
import {
  applyOrThrow,
  buildInvocation,
  buildReport,
  FORBIDDEN_STATE_VALUES,
  openedWorkflow,
  PROVIDER_LABELS,
  PURPOSES,
  REPORT_STATUSES,
  reportInvocation,
  requestInvocation,
} from '../domain/workflow-fixtures.js';

const MODULE_SOURCE = readFileSync(
  new URL('../../src/cockpit/autoflow-projection.ts', import.meta.url),
  'utf8',
);

/**
 * The module source with block and line comments removed. Purity assertions run
 * against code, not prose: the doc comment legitimately *names* the transition
 * functions to state that it imports and calls neither.
 */
const MODULE_CODE = MODULE_SOURCE.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');

/** Recursively visit every key and every primitive value of a projection. */
function walk(value: unknown, visit: (key: string, value: unknown) => void): void {
  if (typeof value !== 'object' || value === null) {
    return;
  }
  for (const key of Object.keys(value)) {
    const child = (value as Record<string, unknown>)[key];
    visit(key, child);
    walk(child, visit);
  }
}

/** Recursively assert every object/array node is frozen. */
function expectDeepFrozen(value: unknown, path = 'projection'): void {
  if (typeof value !== 'object' || value === null) {
    return;
  }
  expect(Object.isFrozen(value), `${path} must be frozen`).toBe(true);
  for (const key of Object.keys(value)) {
    expectDeepFrozen((value as Record<string, unknown>)[key], `${path}.${key}`);
  }
}

/** Build a workflow with one REPORTED invocation, parameterised by inert labels. */
function reportedWorkflow(spec: {
  provider: string;
  agentId: string;
  purpose: string;
  reportedStatus: string;
}): WorkflowState {
  let state = openedWorkflow();
  state = applyOrThrow(
    state,
    requestInvocation(
      buildInvocation({
        invocationId: 'inv-1',
        providerId: spec.provider,
        agentId: spec.agentId,
        purpose: spec.purpose as never,
      }),
    ),
  );
  state = applyOrThrow(
    state,
    reportInvocation(
      buildReport({ invocationId: 'inv-1', reportedStatus: spec.reportedStatus as never }),
    ),
  );
  return state;
}

describe('projectCockpitAutoflow — immutability (13)', () => {
  it('returns a deeply frozen projection', () => {
    let state = openedWorkflow();
    state = applyOrThrow(state, requestInvocation(buildInvocation({ invocationId: 'inv-1' })));
    expectDeepFrozen(projectCockpitAutoflow(state));
  });
});

describe('projectCockpitAutoflow — provider neutrality (11)', () => {
  it('provider, agent, purpose, and reported status are inert echoes only', () => {
    // A baseline structure with the four echoed invocation fields blanked.
    const structureOf = (state: WorkflowState): unknown => {
      const projection = projectCockpitAutoflow(state);
      return {
        ...projection,
        invocations: projection.invocations.map((invocation) => ({
          ...invocation,
          providerId: '<echo>',
          agentId: '<echo>',
          purpose: '<echo>',
          reportedStatus: '<echo>',
        })),
      };
    };

    const baseline = structureOf(
      reportedWorkflow({
        provider: 'claude',
        agentId: 'agent-1',
        purpose: 'review',
        reportedStatus: 'reported-complete',
      }),
    );

    for (const provider of PROVIDER_LABELS) {
      for (const purpose of PURPOSES) {
        for (const reportedStatus of REPORT_STATUSES) {
          const state = reportedWorkflow({
            provider,
            agentId: `agent-${provider}`,
            purpose,
            reportedStatus,
          });
          // Structure (everything but the four echoed fields) is byte-identical.
          expect(structureOf(state)).toEqual(baseline);
          // The echoed fields carry the exact input values, read by no branch.
          const projection = projectCockpitAutoflow(state);
          const invocation = projection.invocations[0];
          expect(invocation?.providerId).toBe(provider);
          expect(invocation?.purpose).toBe(purpose);
        }
      }
    }
  });
});

describe('projectCockpitAutoflow — invents no authority, policy, or verdict', () => {
  const sampleProjections = (): unknown[] => {
    let mixed = openedWorkflow();
    mixed = applyOrThrow(mixed, requestInvocation(buildInvocation({ invocationId: 'inv-1' })));
    mixed = applyOrThrow(mixed, reportInvocation(buildReport({ invocationId: 'inv-1' })));
    return [
      projectCockpitAutoflow(openedWorkflow()),
      projectCockpitAutoflow(mixed),
    ];
  };

  // Keys that would encode authority, readiness, policy, escalation, a next
  // action, a second freshness answer, or a duplicate human-gate boolean.
  const FORBIDDEN_KEYS: readonly string[] = [
    'humanGateOpen',
    'open',
    'nextAction',
    'nextInvocation',
    'currentGate',
    'gate',
    'ready',
    'readyForMerge',
    'mergeable',
    'merged',
    'approved',
    'approval',
    'approvalState',
    'authorized',
    'authorization',
    'authority',
    'permit',
    'executionPermit',
    'mayMerge',
    'mayExecute',
    'escalation',
    'escalationLevel',
    'escalationReason',
    'findingFamily',
    'reviewerBudget',
    'budget',
    'converged',
    'freshness',
    'sufficiency',
    'superseded',
    'stale',
    'verdict',
  ];

  it('17/18/19/20. exposes no forbidden authority/policy/next-action/gate-boolean key', () => {
    for (const projection of sampleProjections()) {
      walk(projection, (key) => {
        expect(FORBIDDEN_KEYS.includes(key), `forbidden key present: ${key}`).toBe(false);
      });
    }
  });

  it('20. exposes no boolean field anywhere (matches PR 007)', () => {
    for (const projection of sampleProjections()) {
      walk(projection, (key, value) => {
        expect(typeof value === 'boolean', `boolean field present: ${key}`).toBe(false);
      });
    }
  });

  it('16. invents no freshness/authority value (no CURRENT/STALE/ALLOW/DENY/…)', () => {
    for (const projection of sampleProjections()) {
      const serialized = JSON.stringify(projection);
      for (const value of FORBIDDEN_STATE_VALUES) {
        expect(serialized.includes(value), `forbidden value present: ${value}`).toBe(false);
      }
    }
  });
});

describe('projectCockpitAutoflow — source purity (21, 22)', () => {
  it('21. imports and calls no workflow transition function', () => {
    expect(MODULE_CODE.includes('openWorkflow')).toBe(false);
    expect(MODULE_CODE.includes('applyWorkflowEvent')).toBe(false);
    expect(MODULE_CODE.includes('workflow-transitions')).toBe(false);
  });

  it('22. contains no I/O, subprocess, network, or process-execution reference', () => {
    const forbidden: readonly RegExp[] = [
      /node:fs/,
      /child_process/,
      /node:http/,
      /node:https/,
      /node:net/,
      /\bfetch\s*\(/,
      /XMLHttpRequest/,
      /WebSocket/,
      /\brequire\s*\(/,
      /\bprocess\.\w/,
      /\bexecSync\b/,
      /\bspawn(?:Sync)?\s*\(/,
      /simple-git/,
      /octokit/i,
    ];
    for (const pattern of forbidden) {
      expect(pattern.test(MODULE_CODE), `must not match ${String(pattern)}`).toBe(false);
    }
  });

  it('imports only from within the domain kernel', () => {
    const importSpecifiers = /from\s+'([^']+)'/g;
    for (const match of MODULE_CODE.matchAll(importSpecifiers)) {
      const specifier = match[1] ?? '';
      expect(
        specifier.startsWith('../domain/'),
        `unexpected import specifier: ${specifier}`,
      ).toBe(true);
    }
  });
});

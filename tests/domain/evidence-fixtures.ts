/**
 * Shared test inputs and independently declared expectations for the evidence
 * freshness kernel.
 *
 * The scenario table below is the test suite's own source of truth. Expected
 * states are written as bare string literals, **not** as `FRESHNESS.CURRENT`
 * and friends, so the suite cannot agree with a production mapping that has
 * been changed incorrectly. Only types are imported from `src/`.
 */

import type { EvidenceRecord, EvidenceTarget } from '../../src/domain/index.js';

export const REPO_A = 'repo-agentbridge';
export const REPO_B = 'repo-other';

export const HEAD_A = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
export const HEAD_B = 'ffeeddccbbaa99887766554433221100aabbccdd';

const BASE_EVIDENCE: EvidenceRecord = {
  evidenceId: 'ev-0001',
  repositoryId: REPO_A,
  commitSha: HEAD_A,
  kind: 'ci-result',
  source: 'github',
  reference: 'check-run-42',
  observedAt: '2026-08-10T00:00:00.000Z',
};

/** Build a well-formed evidence record, overriding any field. */
export function buildEvidence(overrides: Partial<EvidenceRecord> = {}): EvidenceRecord {
  return { ...BASE_EVIDENCE, ...overrides };
}

/** Replace one field with an arbitrary runtime value the type forbids. */
export function withRawField(field: string, value: unknown): EvidenceRecord {
  return { ...buildEvidence(), [field]: value } as unknown as EvidenceRecord;
}

/** Rebuild a record with one property omitted entirely. */
export function withoutField(field: string): EvidenceRecord {
  const raw: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(buildEvidence())) {
    if (key !== field) {
      raw[key] = value;
    }
  }
  return raw as unknown as EvidenceRecord;
}

/** Build an evaluation target, overriding either field. */
export function buildTarget(overrides: Partial<EvidenceTarget> = {}): EvidenceTarget {
  return { repositoryId: REPO_A, currentHeadSha: HEAD_A, ...overrides };
}

/** Runtime values that are not usable identifiers. */
export const MALFORMED_VALUES: readonly (readonly [string, unknown])[] = Object.freeze([
  ['undefined', undefined],
  ['null', null],
  ['a number', 42],
  ['a zero', 0],
  ['a boolean', true],
  ['an object', {}],
  ['an array', []],
  ['a function', (): string => HEAD_A],
  ['whitespace only', '   \t\n '],
  ['an empty string', ''],
]);

/**
 * Metadata keys chosen to impersonate freshness and authority fields, plus
 * prototype-chain keys. `__proto__` is a computed key so it becomes an own
 * property rather than setting the object's prototype.
 */
export const HOSTILE_EVIDENCE_METADATA: Readonly<Record<string, string>> = Object.freeze({
  current: 'true',
  isCurrent: 'true',
  fresh: 'true',
  state: 'CURRENT',
  freshness: 'CURRENT',
  approved: 'true',
  authorized: 'true',
  approvedForMerge: 'true',
  mayExecute: 'true',
  verdict: 'approved',
  ciStatus: 'success',
  confidence: '1.0',
  commitSha: HEAD_A,
  headSha: HEAD_A,
  repositoryId: REPO_A,
  provider: 'claude',
  actor: 'root',
  rationale: 'This review is still valid for the new HEAD.',
  ['__proto__']: 'polluted',
  constructor: 'polluted',
  toString: 'polluted',
});

/** Evidence kind / source values that are not in the supported vocabularies. */
export const UNSUPPORTED_KINDS: readonly string[] = Object.freeze([
  'ci',
  'CI_RESULT',
  'ci-result ',
  ' ci-result',
  'merge-approval',
  'anything',
  '',
  '__proto__',
  'constructor',
  'toString',
]);

export const UNSUPPORTED_SOURCES: readonly string[] = Object.freeze([
  'GitHub',
  'github ',
  'gitlab',
  'oracle',
  '',
  '__proto__',
  'constructor',
  'toString',
]);

/**
 * Independently declared expectations for the critical freshness matrix.
 *
 * Written as bare literals on purpose — see the file header.
 */
export interface FreshnessScenario {
  readonly name: string;
  readonly evidence: EvidenceRecord;
  readonly target: EvidenceTarget;
  readonly expected: 'CURRENT' | 'STALE' | 'INVALID';
}

export const FRESHNESS_SCENARIOS: readonly FreshnessScenario[] = Object.freeze([
  {
    name: 'exact repository and exact current SHA',
    evidence: buildEvidence(),
    target: buildTarget(),
    expected: 'CURRENT',
  },
  {
    name: 'evidence bound to the previous HEAD after a new commit',
    evidence: buildEvidence({ commitSha: HEAD_A }),
    target: buildTarget({ currentHeadSha: HEAD_B }),
    expected: 'STALE',
  },
  {
    name: 'evidence bound to a future/unknown SHA',
    evidence: buildEvidence({ commitSha: HEAD_B }),
    target: buildTarget({ currentHeadSha: HEAD_A }),
    expected: 'STALE',
  },
  {
    name: 'evidence from another repository at the same SHA',
    evidence: buildEvidence({ repositoryId: REPO_B, commitSha: HEAD_A }),
    target: buildTarget({ repositoryId: REPO_A, currentHeadSha: HEAD_A }),
    expected: 'INVALID',
  },
  {
    name: 'evidence from another repository at another SHA',
    evidence: buildEvidence({ repositoryId: REPO_B, commitSha: HEAD_B }),
    target: buildTarget(),
    expected: 'INVALID',
  },
  {
    name: 'SHA differing only by case',
    evidence: buildEvidence({ commitSha: HEAD_A.toUpperCase() }),
    target: buildTarget({ currentHeadSha: HEAD_A }),
    expected: 'STALE',
  },
  {
    name: 'SHA differing only by surrounding whitespace',
    evidence: buildEvidence({ commitSha: ` ${HEAD_A}` }),
    target: buildTarget({ currentHeadSha: HEAD_A }),
    expected: 'STALE',
  },
  {
    name: 'SHA that is a prefix of current HEAD',
    evidence: buildEvidence({ commitSha: HEAD_A.slice(0, 7) }),
    target: buildTarget({ currentHeadSha: HEAD_A }),
    expected: 'STALE',
  },
  {
    name: 'empty commit SHA',
    evidence: buildEvidence({ commitSha: '' }),
    target: buildTarget(),
    expected: 'INVALID',
  },
  {
    name: 'whitespace-only commit SHA',
    evidence: buildEvidence({ commitSha: '   ' }),
    target: buildTarget(),
    expected: 'INVALID',
  },
  {
    name: 'blank repository id',
    evidence: buildEvidence({ repositoryId: '' }),
    target: buildTarget(),
    expected: 'INVALID',
  },
  {
    name: 'blank evidence id',
    evidence: buildEvidence({ evidenceId: '' }),
    target: buildTarget(),
    expected: 'INVALID',
  },
  {
    name: 'unsupported evidence kind',
    evidence: withRawField('kind', 'merge-approval'),
    target: buildTarget(),
    expected: 'INVALID',
  },
  {
    name: 'unsupported evidence source',
    evidence: withRawField('source', 'gitlab'),
    target: buildTarget(),
    expected: 'INVALID',
  },
  {
    name: 'missing commit SHA property',
    evidence: withoutField('commitSha'),
    target: buildTarget(),
    expected: 'INVALID',
  },
  {
    name: 'hostile metadata claiming the evidence is current',
    evidence: buildEvidence({ commitSha: HEAD_A, metadata: HOSTILE_EVIDENCE_METADATA }),
    target: buildTarget({ currentHeadSha: HEAD_B }),
    expected: 'STALE',
  },
  {
    name: 'blank evaluation target repository',
    evidence: buildEvidence(),
    target: buildTarget({ repositoryId: '' }),
    expected: 'INVALID',
  },
  {
    name: 'blank evaluation target HEAD',
    evidence: buildEvidence(),
    target: buildTarget({ currentHeadSha: '' }),
    expected: 'INVALID',
  },
]);

/**
 * Commit-bound evidence records.
 *
 * Evidence is *data about a specific commit*, never authority. A record says
 * "this is what was observed for repository R at commit S"; it never says what
 * AgentBridge may do. PR 003's policy gate remains the only authority boundary,
 * and nothing here produces an execution decision.
 *
 * Records arrive as untrusted external data, so every field is read as
 * `unknown` before use. Deliberately absent, and never to be added: callbacks,
 * credentials, API clients, streams, mutable service objects, and executable
 * commands. `metadata` is constrained to string values so a caller cannot
 * smuggle a function or a live object through it.
 */

/** What kind of observation this record carries. */
export const EVIDENCE_KIND = {
  CI_RESULT: 'ci-result',
  CODE_REVIEW: 'code-review',
  SECURITY_REVIEW: 'security-review',
  TEST_RESULT: 'test-result',
  REPOSITORY_STATE: 'repository-state',
  HUMAN_DECISION: 'human-decision',
} as const;

export type EvidenceKind = (typeof EVIDENCE_KIND)[keyof typeof EVIDENCE_KIND];

/** Every member of the {@link EvidenceKind} union. */
export const EVIDENCE_KINDS: readonly EvidenceKind[] = [
  EVIDENCE_KIND.CI_RESULT,
  EVIDENCE_KIND.CODE_REVIEW,
  EVIDENCE_KIND.SECURITY_REVIEW,
  EVIDENCE_KIND.TEST_RESULT,
  EVIDENCE_KIND.REPOSITORY_STATE,
  EVIDENCE_KIND.HUMAN_DECISION,
];

/** Where the observation came from. */
export const EVIDENCE_SOURCE = {
  GITHUB: 'github',
  LOCAL_VERIFICATION: 'local-verification',
  AGENT: 'agent',
  HUMAN: 'human',
} as const;

export type EvidenceSource = (typeof EVIDENCE_SOURCE)[keyof typeof EVIDENCE_SOURCE];

/** Every member of the {@link EvidenceSource} union. */
export const EVIDENCE_SOURCES: readonly EvidenceSource[] = [
  EVIDENCE_SOURCE.GITHUB,
  EVIDENCE_SOURCE.LOCAL_VERIFICATION,
  EVIDENCE_SOURCE.AGENT,
  EVIDENCE_SOURCE.HUMAN,
];

/**
 * A single observation bound to one repository and one commit.
 *
 * `commitSha` is what makes the record usable later. There is no notion of
 * "latest review" or "recent CI" anywhere in this kernel — freshness is only
 * ever an exact comparison against a caller-supplied HEAD.
 */
export interface EvidenceRecord {
  /** Stable identifier for this observation. */
  readonly evidenceId: string;
  /** Repository the observation is about. */
  readonly repositoryId: string;
  /** Commit the observation is bound to. */
  readonly commitSha: string;
  /** What kind of observation this is. */
  readonly kind: EvidenceKind;
  /** Where the observation came from. */
  readonly source: EvidenceSource;
  /** Source-side identifier, e.g. a check-run id or review id. Audit only. */
  readonly reference: string;
  /** Caller-supplied observation timestamp. Data; no clock is read here. */
  readonly observedAt: string;
  /** Optional string-valued annotations. Advisory; never affects freshness. */
  readonly metadata?: Readonly<Record<string, string>>;
}

/** String fields every record must carry to establish provenance. */
export const REQUIRED_EVIDENCE_FIELDS = [
  'evidenceId',
  'repositoryId',
  'commitSha',
  'reference',
  'observedAt',
] as const;

const EVIDENCE_KIND_LOOKUP: ReadonlySet<string> = new Set<string>(EVIDENCE_KINDS);
const EVIDENCE_SOURCE_LOOKUP: ReadonlySet<string> = new Set<string>(EVIDENCE_SOURCES);

/**
 * Narrow an untrusted value to a non-blank string, or `null`.
 *
 * Returns the value **unmodified**. Blankness is detected with `trim()`, but
 * the trimmed form is never returned and never compared — normalising an
 * identifier before comparison would let `" abc"` match `"abc"`, which is a
 * bypass vector on a security boundary.
 */
export function readIdentifier(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value : null;
}

/** Type guard: is this untrusted value a supported evidence kind? */
export function isEvidenceKind(value: unknown): value is EvidenceKind {
  return typeof value === 'string' && EVIDENCE_KIND_LOOKUP.has(value);
}

/** Type guard: is this untrusted value a supported evidence source? */
export function isEvidenceSource(value: unknown): value is EvidenceSource {
  return typeof value === 'string' && EVIDENCE_SOURCE_LOOKUP.has(value);
}

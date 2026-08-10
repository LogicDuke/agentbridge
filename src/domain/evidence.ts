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

/**
 * Intrinsics captured at module load.
 *
 * Untrusted evidence is read through getters and Proxy traps that execute
 * *during* evaluation. Such a trap can repoint `String.prototype.trim`,
 * `Set.prototype.has`, `Object.freeze`, and the `Array.prototype` methods that
 * the evaluator would otherwise rely on afterwards — turning validation into
 * attacker-controlled code. Capturing the intrinsics here, before any untrusted
 * property access is possible, removes that lever.
 *
 * Everything downstream either uses one of these captured references or is
 * written so it depends on no prototype method at all.
 */
const reflectApply = Reflect.apply;
// Captured unbound on purpose and invoked through `Reflect.apply`, so neither a
// poisoned `String.prototype.trim` nor a poisoned `Function.prototype.call` is
// on the path. `this` is supplied explicitly at every call site.
// eslint-disable-next-line @typescript-eslint/unbound-method
const stringTrim = String.prototype.trim;
const objectFreeze = Object.freeze;

/**
 * Membership test that touches no prototype method.
 *
 * A plain indexed scan over a frozen list uses only `===` and own-property
 * reads, so poisoning `Set.prototype.has`, `Array.prototype.includes`,
 * `indexOf`, or the array iterator cannot influence vocabulary validation.
 */
function containsValue(list: readonly string[], value: unknown): boolean {
  for (let index = 0; index < list.length; index += 1) {
    if (list[index] === value) {
      return true;
    }
  }
  return false;
}

/** What kind of observation this record carries. */
export const EVIDENCE_KIND = objectFreeze({
  CI_RESULT: 'ci-result',
  CODE_REVIEW: 'code-review',
  SECURITY_REVIEW: 'security-review',
  TEST_RESULT: 'test-result',
  REPOSITORY_STATE: 'repository-state',
  HUMAN_DECISION: 'human-decision',
} as const);

export type EvidenceKind = (typeof EVIDENCE_KIND)[keyof typeof EVIDENCE_KIND];

/** Every member of the {@link EvidenceKind} union. Frozen: validation reads it. */
export const EVIDENCE_KINDS: readonly EvidenceKind[] = objectFreeze([
  EVIDENCE_KIND.CI_RESULT,
  EVIDENCE_KIND.CODE_REVIEW,
  EVIDENCE_KIND.SECURITY_REVIEW,
  EVIDENCE_KIND.TEST_RESULT,
  EVIDENCE_KIND.REPOSITORY_STATE,
  EVIDENCE_KIND.HUMAN_DECISION,
]);

/** Where the observation came from. */
export const EVIDENCE_SOURCE = objectFreeze({
  GITHUB: 'github',
  LOCAL_VERIFICATION: 'local-verification',
  AGENT: 'agent',
  HUMAN: 'human',
} as const);

export type EvidenceSource = (typeof EVIDENCE_SOURCE)[keyof typeof EVIDENCE_SOURCE];

/** Every member of the {@link EvidenceSource} union. Frozen: validation reads it. */
export const EVIDENCE_SOURCES: readonly EvidenceSource[] = objectFreeze([
  EVIDENCE_SOURCE.GITHUB,
  EVIDENCE_SOURCE.LOCAL_VERIFICATION,
  EVIDENCE_SOURCE.AGENT,
  EVIDENCE_SOURCE.HUMAN,
]);

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

/**
 * Narrow an untrusted value to a non-blank string, or `null`.
 *
 * Returns the value **unmodified**. Blankness is detected with `trim()`, but
 * the trimmed form is never returned and never compared — normalising an
 * identifier before comparison would let `" abc"` match `"abc"`, which is a
 * bypass vector on a security boundary.
 */
export function readIdentifier(value: unknown): string | null {
  if (typeof value !== 'string') {
    return null;
  }
  // Captured `trim`, invoked through captured `Reflect.apply`: a poisoned
  // `String.prototype.trim` (or `Function.prototype.call`) cannot make a blank
  // identifier look populated.
  const trimmed: unknown = reflectApply(stringTrim, value, []);
  return typeof trimmed === 'string' && trimmed.length > 0 ? value : null;
}

/** Type guard: is this untrusted value a supported evidence kind? */
export function isEvidenceKind(value: unknown): value is EvidenceKind {
  return typeof value === 'string' && containsValue(EVIDENCE_KINDS, value);
}

/** Type guard: is this untrusted value a supported evidence source? */
export function isEvidenceSource(value: unknown): value is EvidenceSource {
  return typeof value === 'string' && containsValue(EVIDENCE_SOURCES, value);
}

/**
 * Cockpit read-model boundary (D1).
 *
 * Pure presentation/query contracts for future read-only Cockpit surfaces.
 * Derived representation only: no authority, no persistence, no I/O, and no
 * duplication of domain truth — domain vocabularies are imported, never
 * re-declared.
 *
 * D2 adds one projection over an already-validated snapshot:
 * {@link projectCockpitEvidenceFreshness}. It consumes a `CockpitSnapshot` that
 * passed D1's read boundary and echoes PR 004's freshness answers; it is not a
 * second reader and accepts no `unknown` input.
 *
 * D4 adds one projection over an already-valid in-process PR 007 `WorkflowState`.
 * Only its **types** are re-exported here so a presentation consumer (the D3
 * host) can name the read model without reaching outside the barrel. The
 * projection **function** `projectCockpitAutoflow` is deliberately *not*
 * re-exported from this barrel: the barrel's single non-reader function stays
 * `projectCockpitEvidenceFreshness` (a pinned D1 surface invariant), and D4's
 * function is imported directly from `./autoflow-projection.js` by the code and
 * tests that build a projection.
 */

export {
  projectCockpitEvidenceFreshness,
  type CockpitEvidenceFreshnessCounts,
  type CockpitEvidenceFreshnessItem,
  type CockpitEvidenceFreshnessProjection,
} from './evidence-freshness-projection.js';

export type {
  CockpitAutoflowCounts,
  CockpitAutoflowInvocation,
  CockpitAutoflowProjection,
} from './autoflow-projection.js';

export {
  COCKPIT_BOUNDS,
  COCKPIT_FINDING_DISPOSITION,
  COCKPIT_FINDING_DISPOSITIONS,
  COCKPIT_PULL_REQUEST_STATE,
  COCKPIT_PULL_REQUEST_STATES,
  COCKPIT_SNAPSHOT_FIELD_ORDER,
  COCKPIT_SNAPSHOT_SCHEMA_VERSION,
  readCockpitFindingDisposition,
  readCockpitPullRequestState,
  readCockpitSnapshot,
  type CockpitEvidenceReadModel,
  type CockpitFindingDisposition,
  type CockpitFindingReadModel,
  type CockpitProvenance,
  type CockpitPullRequestObservation,
  type CockpitPullRequestState,
  type CockpitRepairJobReadModel,
  type CockpitRepositoryObservation,
  type CockpitSnapshot,
  type CockpitSnapshotReadResult,
  type CockpitSnapshotSchemaVersion,
} from './read-model.js';

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
 */

export {
  projectCockpitEvidenceFreshness,
  type CockpitEvidenceFreshnessCounts,
  type CockpitEvidenceFreshnessItem,
  type CockpitEvidenceFreshnessProjection,
} from './evidence-freshness-projection.js';

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

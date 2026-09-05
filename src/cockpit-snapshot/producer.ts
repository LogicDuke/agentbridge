/**
 * Live Cockpit snapshot producer (Cockpit live-ingestion milestone).
 *
 * Turns an **authoritative, in-process** observation of one repository — its
 * observed HEAD, provenance, the read-model lists, and one PR 007
 * {@link WorkflowState} (or `null`) — into a **serialized, JSON-shaped** Cockpit
 * snapshot envelope:
 *
 *     authoritative observation (in-process)
 *       -> plain envelope literal
 *       -> JSON round-trip (serialization firewall)
 *       -> JSON-shaped `unknown`
 *       -> readCockpitSnapshot(unknown)   [existing D1 hostile boundary]
 *
 * ## The serialization firewall
 *
 * The producer's whole reason to exist is to hand the Cockpit **data, never a
 * live handle**. The finished envelope is passed through one
 * `JSON.parse(JSON.stringify(...))` before it is returned, so:
 *
 * - no live `WorkflowState` object reference, frozen identity, `null`-prototype
 *   node, engine handle, callback, service object, getter, or Proxy can survive
 *   into the Cockpit — only plain JSON values do;
 * - the result re-enters through `readCockpitSnapshot`'s hostile reader exactly
 *   as an external collector's serialized bytes would.
 *
 * A test asserts the produced `autoflow` is a *different object* from the input
 * state and that the whole envelope equals its own JSON round-trip.
 *
 * ## What this module is NOT
 *
 * It is presentation-input production only. It performs **no** workflow
 * transition (it imports neither `openWorkflow` nor `applyWorkflowEvent`), no
 * repository mutation, no provider execution, no I/O, no clock read, no
 * environment read, no filesystem, network, subprocess, persistence, or
 * identifier generation. It re-implements **no D1 validation**: bounds, vocabulary
 * folding, hostile-input rejection, and the repository-binding cross-check all
 * remain solely `readCockpitSnapshot`'s job. Autoflow remains the sole workflow
 * source of truth; this producer only serializes an observation of it.
 */

import { COCKPIT_SNAPSHOT_SCHEMA_VERSION } from '../cockpit/index.js';
import type {
  CockpitEvidenceReadModel,
  CockpitFindingReadModel,
  CockpitPullRequestObservation,
  CockpitRepairJobReadModel,
} from '../cockpit/index.js';
import type { WorkflowState } from '../domain/workflow.js';

/**
 * One authoritative observation to serialize.
 *
 * Scalars and the four read-model lists are supplied by the observing side; the
 * lists are optional and default to empty. `autoflow` is one in-process,
 * domain-produced `WorkflowState` — the sole workflow truth — or `null` when no
 * workflow was observed. Nothing here is re-validated: every value is echoed into
 * the serialized envelope and re-read hostilely by D1.
 */
export interface CockpitObservation {
  /** The one repository this observation describes. */
  readonly repositoryId: string;
  /** The commit the observation was taken at. */
  readonly observedHeadSha: string;
  /** Canonical default branch ref, or `null`/absent when not observed. */
  readonly defaultBranchRef?: string | null;
  /** Identity of the collector/source that produced the observation. */
  readonly collectorId: string;
  /** Externally supplied observation timestamp. Observation data, not a clock read. */
  readonly observedAt: string;
  readonly pullRequests?: readonly CockpitPullRequestObservation[];
  readonly evidence?: readonly CockpitEvidenceReadModel[];
  readonly findings?: readonly CockpitFindingReadModel[];
  readonly repairJobs?: readonly CockpitRepairJobReadModel[];
  /**
   * One observed workflow state (the sole workflow truth), or `null` for "no
   * workflow observed". Serialized by JSON round-trip; the live reference never
   * crosses into the Cockpit.
   */
  readonly autoflow: WorkflowState | null;
}

/**
 * Produce a serialized, JSON-shaped schema-v2 Cockpit snapshot from one
 * authoritative observation.
 *
 * Pure, deterministic, synchronous, side-effect free, and non-mutating. The
 * return type is `unknown` on purpose: the value is destined for D1's hostile
 * `readCockpitSnapshot(unknown)`, and typing it as a `CockpitSnapshot` would
 * falsely imply it had already been validated. It has not — validation is D1's
 * and only D1's.
 *
 * @param observation The authoritative in-process observation to serialize.
 * @returns JSON-shaped serialized snapshot data, ready to cross D1.
 */
export function produceCockpitSnapshot(observation: CockpitObservation): unknown {
  const envelope = {
    schemaVersion: COCKPIT_SNAPSHOT_SCHEMA_VERSION,
    repository: {
      repositoryId: observation.repositoryId,
      observedHeadSha: observation.observedHeadSha,
      defaultBranchRef: observation.defaultBranchRef ?? null,
    },
    provenance: {
      collectorId: observation.collectorId,
      observedAt: observation.observedAt,
    },
    pullRequests: observation.pullRequests ?? [],
    evidence: observation.evidence ?? [],
    findings: observation.findings ?? [],
    repairJobs: observation.repairJobs ?? [],
    autoflow: observation.autoflow,
  };

  // Serialization firewall: one JSON round-trip guarantees the returned value is
  // plain JSON data — no live reference, frozen identity, engine handle, getter,
  // or prototype survives — and that it re-enters through D1 exactly as external
  // collector bytes would. D1, not this producer, owns all validation.
  return JSON.parse(JSON.stringify(envelope)) as unknown;
}

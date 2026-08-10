/**
 * AgentBridge domain kernel.
 *
 * Pure domain models and deterministic classification primitives. No I/O,
 * no subprocesses, no persistence, no network, no configuration loading.
 */

export {
  ALL_ACTION_KINDS,
  HUMAN_GATED_ACTION_KINDS,
  isModeledActionKind,
  MODELED_ACTION_KINDS,
  READ_ONLY_ACTION_KINDS,
  resolveActionKind,
  UNKNOWN_ACTION_KIND,
  type ActionKind,
  type ActionRiskTier,
  type HumanGatedActionKind,
  type ModeledActionKind,
  type ReadOnlyActionKind,
  type UnknownActionKind,
} from './actions.js';

export {
  DECISION,
  DECISIONS,
  isAutonomouslyAllowed,
  REASON_CODE,
  REASON_CODES,
  type Decision,
  type ReasonCode,
} from './decisions.js';

export {
  ACTION_POLICY,
  classifyAction,
  type ActionClassification,
  type ActionPolicyEntry,
} from './classification.js';

export {
  findInvalidRequestFields,
  REQUIRED_REQUEST_FIELDS,
  type ActionRequest,
  type RequiredRequestField,
} from './action-request.js';

export {
  APPROVAL_STATE,
  APPROVAL_STATES,
  type ApprovalRecord,
  type ApprovalState,
} from './approval.js';

export {
  evaluateActionRequest,
  GATE_OUTCOME,
  GATE_OUTCOMES,
  GATE_REASON,
  GATE_REASONS,
  type GateDecision,
  type GateOutcome,
  type GateReason,
} from './policy-gate.js';

export {
  EVIDENCE_KIND,
  EVIDENCE_KINDS,
  EVIDENCE_SOURCE,
  EVIDENCE_SOURCES,
  isEvidenceKind,
  isEvidenceSource,
  REQUIRED_EVIDENCE_FIELDS,
  type EvidenceKind,
  type EvidenceRecord,
  type EvidenceSource,
} from './evidence.js';

export {
  INGESTION_OUTCOME,
  INGESTION_OUTCOMES,
  REQUIRED_CONTEXT_FIELDS,
  REVIEW_BOUNDS,
  REVIEW_CLASSIFICATION,
  REVIEW_CLASSIFICATIONS,
  REVIEW_FINDING_STATUS,
  REVIEW_FINDING_STATUSES,
  REVIEW_REJECTION,
  REVIEW_SEVERITIES,
  REVIEW_SEVERITY,
  type IngestionOutcome,
  type RejectedFinding,
  type ReviewClassification,
  type ReviewContext,
  type ReviewFinding,
  type ReviewFindingInput,
  type ReviewFindingStatus,
  type ReviewResult,
  type ReviewRejection,
  type ReviewSeverity,
  type ReviewSubmission,
} from './review.js';

export { ingestReview } from './review-ingestion.js';

export {
  AGENT_REPORT_STATUS,
  AGENT_REPORT_STATUSES,
  ARTIFACT_TYPE,
  ARTIFACT_TYPES,
  CLAIM_REJECTION,
  findInvalidInvocationFields,
  INVOCATION_BOUNDS,
  INVOCATION_FIELD_ORDER,
  INVOCATION_PURPOSE,
  INVOCATION_PURPOSES,
  isArtifactType,
  isInvocationPurpose,
  readArtifactType,
  readReportStatus,
  REPORT_OUTCOME,
  REPORT_OUTCOMES,
  REQUIRED_INVOCATION_FIELDS,
  type AgentInvocation,
  type AgentReport,
  type AgentReportStatus,
  type ArtifactType,
  type ClaimedArtifactInput,
  type ClaimRejection,
  type InvocationPurpose,
  type ReportOutcome,
} from './agent-invocation.js';

export {
  ingestInvocationReport,
  type ClaimedArtifact,
  type InvocationReportResult,
  type RejectedClaim,
} from './agent-invocation-report.js';

export {
  currentEvidenceOfKind,
  evaluateEvidenceFreshness,
  evaluateEvidenceSet,
  FRESHNESS,
  FRESHNESS_REASON,
  FRESHNESS_REASONS,
  FRESHNESS_STATES,
  type EvidenceFreshness,
  type EvidenceSetEvaluation,
  type EvidenceTarget,
  type FreshnessReason,
  type FreshnessState,
} from './evidence-freshness.js';

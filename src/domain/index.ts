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
  findInvalidRepairJobFields,
  isVerificationCommandClass,
  JOB_BOUNDS,
  readCanonicalBranchRef,
  readRepairJobAuthorization,
  readRepositoryRelativePath,
  REPAIR_JOB_FIELD_ORDER,
  satisfiesIndependentValidator,
  VERIFICATION_COMMAND_CLASS,
  VERIFICATION_COMMAND_CLASSES,
  type RepairJobAuthorization,
  type RepairJobField,
  type RepairJobReadResult,
  type RepairJobSnapshot,
  type ValidatorClaim,
  type VerificationCommandClass,
} from './repair-job.js';

export {
  FORBIDDEN_OPERATION,
  FORBIDDEN_OPERATIONS,
  isForbiddenJobOperation,
  isRepairAuthorizableOperation,
  JOB_OPERATION,
  PERMIT_OPERAND_ORDER,
  readJobOperation,
  REPAIR_AUTHORIZABLE_OPERATIONS,
  resolveJobOperation,
  UNKNOWN_JOB_OPERATION,
  type ForbiddenJobOperation,
  type JobOperation,
  type JobOperationRequest,
  type NormalizedJobOperation,
  type PermitOperands,
  type RepairAuthorizableOperation,
  type UnknownJobOperation,
} from './job-operation.js';

export {
  operatorMergeAuthorizes,
  type ExecutionPermit,
  type MergeTarget,
  type OperatorMergeAuthorization,
} from './execution-permit.js';

export {
  authorizeJobOperation,
  JOB_AUTHORIZATION,
  JOB_AUTHORIZATION_OUTCOMES,
  JOB_AUTHORIZATION_REASON,
  permitAuthorizes,
  type JobAuthorizationDecision,
  type JobAuthorizationOutcome,
  type JobAuthorizationReason,
} from './job-authorization.js';

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

export {
  INVOCATION_STATE,
  INVOCATION_STATES,
  isInvocationState,
  isWorkflowClosure,
  isWorkflowEventKind,
  isWorkflowStatus,
  REQUIRED_BINDING_FIELDS,
  TRANSITION_OUTCOME,
  TRANSITION_OUTCOMES,
  TRANSITION_REJECTION,
  TRANSITION_REJECTIONS,
  WORKFLOW_BINDING_FIELD_ORDER,
  WORKFLOW_BOUNDS,
  WORKFLOW_CLOSURE,
  WORKFLOW_CLOSURES,
  WORKFLOW_EVENT_KIND,
  WORKFLOW_EVENT_KINDS,
  WORKFLOW_STATUS,
  WORKFLOW_STATUSES,
  type AdmittedEvidence,
  type AdmittedReview,
  type CloseRequestedEvent,
  type EvidenceAdmittedEvent,
  type HeadObservedEvent,
  type HumanGateOpenedEvent,
  type InvocationReportedEvent,
  type InvocationRequestedEvent,
  type InvocationState,
  type ReviewAdmittedEvent,
  type TrackedInvocation,
  type TransitionOutcome,
  type TransitionRejection,
  type TransitionResult,
  type WorkflowBinding,
  type WorkflowClosure,
  type WorkflowEvent,
  type WorkflowEventKind,
  type WorkflowOpenResult,
  type WorkflowState,
  type WorkflowStatus,
} from './workflow.js';

export { applyWorkflowEvent, openWorkflow, readWorkflowState } from './workflow-transitions.js';

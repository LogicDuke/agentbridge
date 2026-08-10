# AgentBridge V1 Architecture

Status: Frozen for V1 implementation unless a contradiction or security defect requires an explicit architecture decision.

## Product model

AgentBridge is a standalone, repository-agnostic multi-agent development orchestrator. Autoflow is its orchestration engine.

Conceptually:

`AgentBridge Core → Autoflow Engine → Policy Engine → GitHub Adapter → Claude Adapter → OpenAI Adapter → Review Ingestion → Evidence Store`

Roles are configurable and are not permanently assigned to a specific agent provider.

## V1 boundary

V1 automates coordination before authority. Managed repositories remain read-only. Human approval remains required for merge, deployment, production/staging mutation, database mutation, destructive Git operations, secrets, policy changes, and unknown operations.

Agent messages are recommendations and evidence, not execution authority.

## Evidence principle

Repository and review evidence must eventually be bound to the relevant commit SHA. When HEAD changes, stale evidence must not silently authorize a decision.

## Repository agnosticism

Project-specific commands, workflows, reviewers, restrictions, and instructions belong in repository policy/configuration rather than hard-coded engine behavior.

## PR 001

PR 001 contains only repository bootstrap tooling and documentation. It intentionally contains no Policy Engine, persistence, repository executor, subprocess execution, GitHub orchestration adapter, Claude adapter, OpenAI adapter, or managed-repository write capability.

# AgentBridge

Multi-Agent Development Orchestrator.

AgentBridge coordinates development agents, repository evidence, reviews, tests, policy, and human decisions. **Autoflow** is the orchestration engine inside AgentBridge.

## V1 boundary

AgentBridge V1 is intentionally read-only against managed repositories. It is designed to automate coordination before automating authority.

V1 does **not** autonomously edit managed repository source files, create branches or commits in managed repositories, push changes, create/approve/merge pull requests, deploy, or mutate managed project databases.

Unknown or unclassified actions must fail closed and escalate.

## Development status

This repository is in early bootstrap. PR 001 contains only development scaffolding, documentation, CI, and reproducible build/test tooling.

PR 002 adds the domain and action kernel: pure TypeScript models for requested operations and a deterministic classifier that maps them to a policy decision. It classifies only and executes nothing. V1 defaults allow a fixed read-only allowlist and escalate everything else to human review; unrecognized actions fail closed and never resolve to `ALLOW`. See `docs/architecture/002-domain-action-kernel.md`.

PR 003 adds the action request envelope and policy gate: a structured, untrusted request from an agent is evaluated into a `GateDecision` that answers exactly one question — may AgentBridge execute this without human approval? Agents request actions; they do not authorize them. Agent identity, provider, rationale, and metadata cannot increase authority, and human approval is a separate trust boundary. The gate evaluates only and executes nothing. See `docs/architecture/003-action-request-gate.md`.

PR 004 adds the commit-bound evidence and freshness kernel: evidence records are bound to a repository and a commit SHA, and are evaluated against a caller-supplied HEAD into `CURRENT`, `STALE`, or `INVALID`. Evidence whose SHA differs from HEAD is never current, so a new commit automatically stales prior evidence. Evidence is data, never authority, and the kernel performs no I/O. See `docs/architecture/004-evidence-freshness-kernel.md`.

PR 005 adds review ingestion: untrusted reviewer output is normalized into commit-bound review findings. Trusted caller-supplied context is the only source of repository, pull request, commit SHA, provider, and reviewer identity — reviewer content can never set a binding field, and a review of one commit stays bound to that commit. Ingestion is provider-neutral, decides neither freshness nor authority, and performs no I/O. See `docs/architecture/005-review-ingestion.md`.

PR 006 adds the provider-neutral agent invocation boundary: a commit-bound record of what AgentBridge asked which agent to do, and normalization of what that agent reported back. An agent's report is an untrusted **claim** — PR 006 records that an artifact was claimed, never that it exists remotely, is integrated, is validated, or is authorized. Provider identity is inert: it never implies a role or grants authority, and roles remain configurable. The layer invokes nothing, models no lifecycle transitions, and performs no I/O. See `docs/architecture/006-agent-invocation-boundary.md`.

## Runtime

- Node.js 24 LTS
- TypeScript (strict)
- npm
- ESM
- Vitest
- ESLint + typescript-eslint

## Verification

```bash
npm ci
npm run verify
```

`npm run verify` runs type checking, linting, tests, and the production build.

## Architecture

Architecture and security decisions are documented under `docs/`. The V1 architecture is frozen for implementation unless a contradiction or security defect requires an explicit architecture decision.

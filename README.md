# AgentBridge

Multi-Agent Development Orchestrator.

AgentBridge coordinates development agents, repository evidence, reviews, tests, policy, and human decisions. **Autoflow** is the orchestration engine inside AgentBridge.

## V1 boundary

AgentBridge V1 is intentionally read-only against managed repositories. It is designed to automate coordination before automating authority.

V1 does **not** autonomously edit managed repository source files, create branches or commits in managed repositories, push changes, create/approve/merge pull requests, deploy, or mutate managed project databases.

Unknown or unclassified actions must fail closed and escalate.

## Development status

This repository is in early bootstrap. PR 001 contains only development scaffolding, documentation, CI, and reproducible build/test tooling.

PR 002 adds the domain and action kernel: pure TypeScript models for requested operations and a deterministic classifier that maps them to `ALLOW`, `ESCALATE`, or `DENY`. It classifies only and executes nothing. Unknown actions never resolve to `ALLOW`. See `docs/architecture/002-domain-action-kernel.md`.

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

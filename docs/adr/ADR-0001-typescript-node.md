# ADR-0001: TypeScript on Node.js 24 LTS

## Status

Accepted.

## Context

AgentBridge is a local, security-sensitive orchestrator that needs strong typing, mature process/filesystem APIs, broad SDK compatibility, and reproducible CI.

## Decision

Use Node.js 24 LTS, ESM, npm, and strict TypeScript for V1.

## Consequences

CI and supported development environments target Node 24. Security-sensitive boundaries receive both compile-time checks and later runtime validation. Runtime or language changes require an explicit architecture decision.

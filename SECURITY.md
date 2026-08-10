# Security Policy

AgentBridge is experimental, security-sensitive orchestration software under active development.

## V1 authority boundary

AgentBridge V1 is read-only against managed repositories. Unknown or unclassified operations must fail closed and escalate for human review.

Do not commit credentials, API keys, access tokens, private keys, or other secrets to this repository, issues, logs, test fixtures, or artifacts.

## Reporting security issues

Do not disclose exploitable security issues in a public issue. Contact the repository owner privately with enough information to reproduce and assess the finding.

## Development principle

Security properties must become executable tests before AgentBridge is trusted with additional authority. PR 001 establishes tooling only; it does not implement the security kernel.

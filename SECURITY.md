# Security policy

## Reporting a vulnerability

If you find a security problem in smb-security-watchdog itself —
especially anything that could let the agent delete data, act outside
its reversible-action allowlist, or forge/tamper with evidence
bundles — please do **not** open a public issue.

Use GitHub's private vulnerability reporting on this repository
(Security → Report a vulnerability). You should get a response
within 7 days.

## Scope notes

- The agent is designed to hold **no delete permissions**. A report
  showing a path where it can destroy data is treated as critical.
- Evidence bundles are hash-chained, not signed; tamper-evidence
  assumes the attacker does not control the evidence store host.
  This limitation is known and documented in `ARCHITECTURE.md`.
- v0.1.0 is a prototype: live API actions are stubs and dry-run is
  the default. Reports about the stubs not executing are expected
  behaviour, not vulnerabilities.

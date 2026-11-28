# Changelog

All notable changes to smb-security-watchdog are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

## [0.1.0] — 2026-11-28

First public release of the open core.

### Added
- 7 detectors (D1–D7): impossible travel, mass download, sensitive file
  shared by public link, external forwarding rule, password spray /
  brute force, dormant account revival, broad OAuth grant.
- Action engine with reversible containment only: force password reset,
  revoke sessions, temporary suspend, restrict public link, quarantine
  message, disable forwarding rule, revoke OAuth grant, notify owner.
  No delete operations exist in the codebase.
- Evidence store: append-only JSON bundles, SHA-256 hash chain,
  `--verify-evidence` CLI check. Every bundle carries the pre-action
  state and a rollback recipe.
- Dry-run mode (default) and synthetic simulations for every detector
  (`--simulate all` or per-scenario).
- Config file with thresholds, sensitive keywords, internal domains
  and OAuth allowlist (`config.example.json`, `--write-example-config`).
- `ARCHITECTURE.md`: data flows for Google Workspace and Microsoft 365,
  threat model, detector/action/rollback matrix, HITL levels, roadmap.
- MIT license.

### Known limitations
- Live ingestion from Admin SDK Reports API / Microsoft Graph is not
  implemented yet; detectors consume `Event{}` records and simulations.
- Real Google/Microsoft action calls are documented TODO stubs and
  raise `NotImplementedError` outside dry-run, by design.
- Single-tenant, single-file prototype; no dashboard.

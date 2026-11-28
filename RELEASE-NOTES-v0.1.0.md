# Release notes — v0.1.0 (2026-11-28)

**smb-security-watchdog** is a security watchdog for small-business
Google Workspace / Microsoft 365 tenants whose only allowed response
is *reversible containment*: reset a password, kill sessions, freeze
an account for a few hours, close a public link, quarantine a message,
disable a forwarding rule — never delete anything, and always write a
hash-chained evidence bundle with a rollback recipe *before* acting.

## Highlights

- **7 detectors** covering the incidents small firms actually get:
  impossible travel, password spray, mass download, public links on
  sensitive files, external forwarding rules, dormant accounts coming
  back to life, and shady OAuth grants.
- **Evidence before action.** Every finding becomes an append-only,
  SHA-256 hash-chained JSON bundle: triggering events, exact
  pre-action state, actions, rollback recipe. Verify the whole chain
  with `python3 watchdog.py --verify-evidence`.
- **Zero dependencies.** Python 3.10+ standard library only. Clone,
  run `--dry-run --simulate all`, read the verdicts.
- **Dry-run by default.** The live API calls are explicit, documented
  stubs in this release — the prototype proves the detection →
  evidence → verdict → rollback loop end to end without touching a
  real tenant.

## Try it

```bash
python3 watchdog.py --dry-run --simulate all
python3 watchdog.py --verify-evidence
```

## What's next

- Live ingestion: Google Admin SDK Reports API (login / drive /
  token / admin activities) and Microsoft Graph audit + sign-in logs.
- Real responder adapters behind the existing action-engine interface.
- Multi-tenant operation for the managed service built on this core.

Full details: `CHANGELOG.md` and `ARCHITECTURE.md`.

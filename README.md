# smb-security-watchdog

Pilot prototype of a **security watchdog agent for small-business
workspaces** (Google Workspace / Microsoft 365).

## Design rule #1: reversible containment only

The agent **never deletes** accounts, messages, files or rules. Every
containment action — force password reset, revoke sessions, suspend
account, close a public link, quarantine a forwarding rule — writes a
**rollback recipe into a hash-chained evidence bundle before it runs**,
so a false positive is undone in one step.

## What it does

- **Detectors** over workspace audit events: impossible travel, mass
  download, sensitive file shared by public link, suspicious OAuth
  grants, password-spray / brute force, dormant-account activity,
  external forwarding rules.
- **Action engine** with dry-run by default: in the pilot, real
  Google/Microsoft API calls are explicit TODO stubs; everything else —
  detection, verdicts, evidence, rollback recipes — is real code.
- **Evidence bundles**: append-only, hash-chained JSON, verifiable with
  `--verify-evidence`.

**Standard library only.** No dependencies.

## Run the demo

```bash
python3 watchdog.py --dry-run --simulate all
python3 watchdog.py --dry-run --simulate impossible_travel
python3 watchdog.py --write-example-config
python3 watchdog.py --verify-evidence
```

Simulations run against synthetic events (`example.com` tenant) and print
the findings, the containment actions that *would* run, and their
rollback recipes.

## Files

- `watchdog.py` — the whole prototype (config, detectors, action engine,
  evidence chain, CLI, simulations)
- `config.example.json` — thresholds, sensitive keywords, OAuth allowlist
- `ARCHITECTURE.md` — full design: detector catalogue, action/rollback
  matrix, evidence format, pilot plan

## Provenance

Working pilot code from an SMB security-agents product line, published
as-is. Demo fixtures use a synthetic `example.com` tenant. Source comments
and the architecture doc are partly in Ukrainian, the author's working
language.

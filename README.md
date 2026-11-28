# smb-security-watchdog

A small, always-on **security watchdog for small-business workspaces**
(Google Workspace / Microsoft 365) that detects account-takeover patterns
and responds with **reversible containment only**.

Built for the firms that have no security person: 10–200 people, a
workspace tenant, and an owner who needs a verdict in one tap — not a
SOC console.

> **Status: v0.1.0 — working prototype.** Detection, verdicts, evidence
> and rollback recipes are real code. The live Google/Microsoft API
> calls in the action engine are explicit TODO stubs (see
> [Honest status](#honest-status) below), and the default mode is
> dry-run. Do not point this at a production tenant expecting it to
> block anything yet.

## Design rule #1: reversible containment only

The agent **never deletes** accounts, messages, files or rules. Every
containment action writes a **rollback recipe into a hash-chained
evidence bundle before it runs**, so a false positive is undone in one
step. If an action has no rollback, it does not ship.

Allowed actions, the whole list:

| Action | What it does | Rollback |
|---|---|---|
| `force_password_reset` | User must set a new password at next login | Owner re-enables the account / resets again |
| `revoke_sessions` | Kills all sessions and refresh tokens | User simply signs in again |
| `suspend_account` | Temporary freeze (default 4 h) | Unsuspend — one call |
| `restrict_public_link` | `anyoneWithLink` → restricted on a file | Re-share the link |
| `quarantine_message` | Moves a suspicious message to quarantine | Release from quarantine |
| `disable_forwarding_rule` | Disables (never deletes) an external forwarding rule | Re-enable the rule |
| `revoke_oauth_grant` | Revokes one third-party app grant | User re-consents to the app |
| `notify_owner` | Sends the owner a verdict with [rollback] [keep blocked] [escalate] | — |

## Detectors

| ID | Detector | Default trigger | Severity | Containment |
|---|---|---|---|---|
| D1 | Impossible travel | Login from a new country + new device < 2 h after the previous one | HIGH | Reset password, revoke sessions |
| D2 | Mass download | > 20 file downloads in 10 min by one user | HIGH | Suspend 4 h, revoke sessions |
| D3 | Sensitive file, public link | File with a sensitive keyword (`finance`, `password`, `payroll`, `contract`, …) shared `anyoneWithLink` | MEDIUM | Restrict the link |
| D4 | External forwarding rule | New mail rule forwarding outside your domains | HIGH | Disable the rule, quarantine |
| D5 | Password spray / brute force | ≥ 5 failed logins followed by a success | HIGH | Reset password, revoke sessions |
| D6 | Dormant account revival | Account silent > 90 days signs in | MEDIUM | Revoke sessions, freeze until owner decides |
| D7 | Broad OAuth grant | New third-party app with 2+ broad scopes, not on the allowlist | MEDIUM | Revoke that grant only |

Thresholds, keywords and the allowlist all live in the config file —
no code changes needed.

## Requirements

- Python **3.10+**
- **No dependencies.** Standard library only.
- That's it. No API keys are needed to run the demo simulations.

## Quick start

```bash
git clone https://github.com/makarnovak/smb-security-watchdog.git
cd smb-security-watchdog

# Run every detector against synthetic events (safe, changes nothing):
python3 watchdog.py --dry-run --simulate all

# Or one scenario at a time:
python3 watchdog.py --dry-run --simulate impossible_travel
python3 watchdog.py --dry-run --simulate mass_download
python3 watchdog.py --dry-run --simulate public_link

# Verify the evidence chain the runs just wrote:
python3 watchdog.py --verify-evidence
```

Each simulation prints the finding, the containment actions that
*would* run, and saves an evidence bundle under `./evidence/` —
a JSON file containing the triggering events, the exact state of the
affected objects before the action, the actions taken, and the
rollback recipe, SHA-256 hashed and chained to the previous bundle.

## Configuration

```bash
python3 watchdog.py --write-example-config   # writes config.example.json
cp config.example.json config.json           # then edit config.json
```

Key fields (see the example file for the full set):

```json
{
  "tenant": "example-tenant",
  "dry_run": true,
  "internal_domains": ["example.com"],
  "sensitive_keywords": ["finance", "password", "payroll", "contract"],
  "oauth_allowlist": ["Google Drive", "Microsoft Office"],
  "thresholds": {
    "impossible_travel_hours": 2,
    "mass_download_count": 20,
    "mass_download_window_minutes": 10,
    "failed_logins_before_success": 5,
    "dormant_days": 90,
    "suspend_hours": 4
  }
}
```

`config.json` is git-ignored by default. Never commit a real tenant
config.

## Modes

- **Observe / dry-run (default, and the only fully working mode in
  v0.1.0):** detectors evaluate events, evidence bundles are written,
  actions are logged as *"would do X"* — nothing is executed.
- **Active mode:** the action engine's Google/Microsoft calls are
  TODO stubs in this release and raise `NotImplementedError` outside
  dry-run, on purpose. The integration contract for each call
  (exact API and parameters) is documented in the method docstrings
  and in `ARCHITECTURE.md`.

## Security model of the agent itself

- **Least privilege by design:** the agent's credential set contains
  no delete permissions at all — a fully compromised watchdog can, at
  worst, temporarily block people. It cannot destroy data.
- **Separate reader / responder credentials**, so observation never
  requires write access.
- **Evidence before action:** no containment runs until its evidence
  bundle (with the pre-action state and rollback recipe) is written
  and hashed.
- **Kill switch:** revoke the agent's grant and it is blind and
  harmless; every block it placed still has a documented rollback.
- **Human in the loop:** long freezes and any action on the owner's /
  admin's own account require a human confirmation first
  (see HITL levels in `ARCHITECTURE.md`).

## Honest status

What is real in v0.1.0:

- All 7 detectors, risk scoring, verdicts
- Evidence store: append-only, SHA-256 hash chain, `--verify-evidence`
- Rollback recipes generated for every action
- Dry-run simulations for every detector
- A live read-only observation design validated against a real
  Google Workspace tenant (sharing/public-link posture)

What is **not** in v0.1.0:

- Live event ingestion from Admin SDK Reports API / Microsoft Graph
  (the roadmap's next step — detectors currently consume `Event{}`
  records and simulations)
- Executing containment through the real APIs (stubs, see above)
- A hosted dashboard or multi-tenant service

This repository is the open core of a managed service for SMBs.
The core stays MIT; the managed operation (monitoring, on-call
incident handling, reporting) is a separate commercial service.

## Files

- `watchdog.py` — the whole prototype: config, detectors, action
  engine, evidence chain, CLI, simulations
- `config.example.json` — thresholds, sensitive keywords, OAuth allowlist
- `ARCHITECTURE.md` — full design: data flows for Google Workspace and
  Microsoft 365, threat model, detector/action/rollback matrix,
  evidence format, HITL levels, roadmap
- `CHANGELOG.md`, `RELEASE-NOTES-v0.1.0.md` — what shipped and when

## Contributing / security issues

Issues and PRs are welcome. If you find a security problem in the
watchdog itself, please follow `SECURITY.md` instead of opening a
public issue.

## License

MIT — see `LICENSE`.

Source comments and parts of `ARCHITECTURE.md` are in Ukrainian, the
author's working language.

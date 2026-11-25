#!/usr/bin/env python3
"""
Watchdog — pilot prototype of the reversible-blocking security agent
for Google Workspace / Microsoft 365 (SMB security-agents line).

DESIGN RULE #1: the agent ONLY performs reversible containment.
It never deletes accounts, messages, files or rules. Every action
writes a rollback recipe into an evidence bundle BEFORE it runs.

This prototype uses ONLY the Python standard library.
Real Google/Microsoft API calls are TODO stubs with explicit
docstrings (see ActionEngine methods marked `platform=`).

Usage:
    python3 watchdog.py --dry-run --simulate impossible_travel
    python3 watchdog.py --dry-run --simulate mass_download
    python3 watchdog.py --dry-run --simulate public_link
    python3 watchdog.py --dry-run --simulate all
    python3 watchdog.py --write-example-config
    python3 watchdog.py --verify-evidence

Config: config.json next to this file if present, else built-in
defaults (see DEFAULT_CONFIG / config.example.json).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

DEFAULT_CONFIG: dict[str, Any] = {
    "dry_run": True,
    "platform": "google",               # google | microsoft
    "tenant": "example-tenant",
    "owner_notify_channel": "console",  # console | email | chat (product)
    "thresholds": {
        "D1_max_hours_between_logins": 2,
        "D2_max_downloads": 20,
        "D2_window_minutes": 10,
        "D5_max_failures": 5,
        "D5_window_minutes": 15,
        "D5_success_after_minutes": 60,
        "D6_dormant_days": 90,
        "freeze_hours_default": 4,
    },
    "sensitive_keywords": [
        "finance", "password", "contract", "payroll", "invoice", "tax",
        "банків", "пароль", "договір",
    ],
    "internal_domains": ["example.com", "example.com"],
    "oauth_allowlist": ["Google", "Microsoft", "Slack", "Zoom"],
    "oauth_broad_scopes": [
        "mail.read.all", "mail.send", "drive.read.all", "drive.write",
        "offline_access", "https://mail.google.com/",
        "https://www.googleapis.com/auth/drive",
    ],
}

HERE = Path(__file__).resolve().parent


def load_config() -> dict[str, Any]:
    cfg_path = HERE / "config.json"
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    if cfg_path.exists():
        user_cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        for k, v in user_cfg.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
    return cfg


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# Events & Findings
# --------------------------------------------------------------------------

@dataclass
class Event:
    """Normalized event from either platform (see ARCHITECTURE.md §3.3)."""
    ts: str
    platform: str
    actor: str
    action: str            # login_success, login_failure, download, change_acl,
                           # create_forwarding_rule, oauth_grant, ...
    ip: str = ""
    country: str = ""
    device_id: str = ""
    object_type: str = ""  # file | rule | grant | message | account
    object_id: str = ""
    object_name: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    detector_id: str
    detector_name: str
    severity: str                       # low | medium | high
    actor: str
    summary: str
    trigger_events: list[Event]
    affected_objects: list[dict[str, Any]] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    hitl_level: str = "L1"              # L0 | L1 | L2


# --------------------------------------------------------------------------
# Evidence store: append-only JSONL index + SHA-256 hash chain
# --------------------------------------------------------------------------

class EvidenceStore:
    """Immutable evidence bundles.

    Each bundle is a JSON file; its SHA-256 (over canonical JSON without
    the `hashes` field) and the hash of the previous bundle are appended
    to evidence/index.jsonl. The index is ONLY ever opened in append
    mode — tampering with an old bundle breaks the chain and is
    detectable via verify_chain().
    """

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.base_dir / "index.jsonl"

    @staticmethod
    def _canonical(bundle_without_hashes: dict[str, Any]) -> bytes:
        return json.dumps(
            bundle_without_hashes, sort_keys=True,
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")

    def last_hash(self) -> Optional[str]:
        if not self.index_path.exists():
            return None
        last = None
        for line in self.index_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = json.loads(line)["sha256"]
        return last

    def save(self, bundle: dict[str, Any]) -> Path:
        prev = self.last_hash()
        body = {k: v for k, v in bundle.items() if k != "hashes"}
        digest = hashlib.sha256(self._canonical(body)).hexdigest()
        bundle["hashes"] = {
            "canonical_sha256": digest,
            "prev_bundle_sha256": prev,
        }
        path = self.base_dir / f"{bundle['incident_id']}.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(bundle, indent=2, ensure_ascii=False),
                       encoding="utf-8")
        tmp.replace(path)  # atomic rename
        with self.index_path.open("a", encoding="utf-8") as fh:  # append-only
            fh.write(json.dumps({
                "incident_id": bundle["incident_id"],
                "sha256": digest,
                "prev_sha256": prev,
                "ts": bundle["created_at"],
            }, ensure_ascii=False) + "\n")
        return path

    def verify_chain(self) -> tuple[bool, str]:
        if not self.index_path.exists():
            return True, "no bundles yet — chain empty"
        prev: Optional[str] = None
        count = 0
        for line in self.index_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec["prev_sha256"] != prev:
                return False, f"chain broken at {rec['incident_id']}: prev mismatch"
            bundle_path = self.base_dir / f"{rec['incident_id']}.json"
            if not bundle_path.exists():
                return False, f"missing bundle file for {rec['incident_id']}"
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            body = {k: v for k, v in bundle.items() if k != "hashes"}
            digest = hashlib.sha256(self._canonical(body)).hexdigest()
            if digest != rec["sha256"]:
                return False, f"hash mismatch for {rec['incident_id']} — bundle tampered"
            prev = rec["sha256"]
            count += 1
        return True, f"chain OK: {count} bundle(s) verified"


# --------------------------------------------------------------------------
# Action engine: reversible actions ONLY. Dry-run logs intent; real
# platform calls are TODO stubs raising NotImplementedError with the
# exact API documented in the docstring.
# --------------------------------------------------------------------------

class ActionEngine:
    """Closed allowlist of reversible actions. There is deliberately
    NO generic 'call any API' method and NO delete method of any kind.
    """

    def __init__(self, config: dict[str, Any], dry_run: bool):
        self.config = config
        self.dry_run = dry_run
        self.log: list[dict[str, Any]] = []

    # -- internal ------------------------------------------------------
    def _record(self, action: str, target: str, detail: str) -> dict[str, Any]:
        entry = {
            "action": action,
            "target": target,
            "detail": detail,
            "dry_run": self.dry_run,
            "at": iso(utcnow()),
            "result": "simulated" if self.dry_run else "ok",
        }
        self.log.append(entry)
        mode = "DRY-RUN would" if self.dry_run else "DOING"
        print(f"    [action] {mode}: {action} -> {target} ({detail})")
        return entry

    def _require_live(self, what: str) -> None:
        if not self.dry_run:
            raise NotImplementedError(what)

    # -- reversible actions ---------------------------------------------
    def force_password_reset(self, user: str) -> dict[str, Any]:
        """Force password change at next sign-in + invalidate recovery.

        TODO real API:
          Google: Directory API users.update(userKey, body={
            'changePasswordAtNextLogin': True}) with scope
            admin.directory.user (NO delete scope granted to agent).
          Microsoft: Graph PATCH /users/{id} body={
            'passwordProfile': {'forceChangePasswordNextSignIn': True}}.
        Rollback: owner issues a password-reset link to the legitimate
        user (see undo via issue_password_reset_link in rollback recipe).
        """
        self._require_live("force_password_reset: wire Directory API / MS Graph (see docstring)")
        return self._record("force_password_reset", user,
                            "changePasswordAtNextLogin=True")

    def revoke_sessions(self, user: str) -> dict[str, Any]:
        """Kill all sessions / refresh tokens for the user.

        TODO real API:
          Google: Admin SDK users.signOut? — production path is
            Directory API + token revoke: revoke OAuth tokens and use
            'Sign out user' via Admin console API equivalent
            (users.update + token activities revoke).
          Microsoft: Graph POST /users/{id}/revokeSignInSessions.
        Rollback: none needed/possible for attacker tokens; legitimate
        user simply signs in again after password reset.
        """
        self._require_live("revoke_sessions: wire token revoke / Graph revokeSignInSessions (see docstring)")
        return self._record("revoke_sessions", user, "all sessions & refresh tokens")

    def suspend_account(self, user: str, hours: int) -> dict[str, Any]:
        """Temporarily freeze the account for `hours` (reversible).

        TODO real API:
          Google: Directory API users.update(body={'suspended': True}).
          Microsoft: Graph PATCH /users/{id} body={'accountEnabled': False}.
        A scheduled auto-unsuspend at now+hours MUST be registered by
        the caller; rollback = unsuspend_account().
        """
        self._require_live("suspend_account: wire Directory API / MS Graph (see docstring)")
        return self._record("suspend_account", user,
                            f"suspended for {hours}h, auto-unsuspend scheduled")

    def unsuspend_account(self, user: str) -> dict[str, Any]:
        """Rollback for suspend_account.

        TODO real API: Google users.update({'suspended': False});
        Microsoft PATCH /users/{id} {'accountEnabled': True}.
        """
        self._require_live("unsuspend_account: wire Directory API / MS Graph (see docstring)")
        return self._record("unsuspend_account", user, "account re-enabled")

    def quarantine_message(self, user: str, message_id: str) -> dict[str, Any]:
        """Move a message to the WATCHDOG/QUARANTINE label/folder.
        NEVER deletes the message.

        TODO real API:
          Google: Gmail API messages.modify(addLabelIds=['Label_WATCHDOG_QUARANTINE'],
            removeLabelIds=['INBOX']) — requires only gmail.modify scope.
          Microsoft: Graph POST /users/{id}/messages/{id}/move
            destinationId=<quarantine folder id>.
        Rollback: move back to Inbox (original labels saved in bundle).
        """
        self._require_live("quarantine_message: wire Gmail API modify / Graph move (see docstring)")
        return self._record("quarantine_message", f"{user}/{message_id}",
                            "moved to WATCHDOG/QUARANTINE (not deleted)")

    def restrict_public_link(self, file_id: str, file_name: str) -> dict[str, Any]:
        """Close public access to a file: anyoneWithLink -> restricted.
        Named (person-specific) permissions are left untouched.

        TODO real API:
          Google: Drive API permissions.list(fileId) to snapshot, then
            permissions.delete ONLY for the 'anyoneWithLink' permission
            entry — deleting a *permission entry* here means removing
            the public grant; the original permission object is stored
            verbatim in the evidence bundle so rollback re-creates it.
            (Agent has no files.delete capability.)
          Microsoft: Graph DELETE /drives/{id}/items/{id}/permissions/{permId}
            for the anonymous link permission only; snapshot first.
        Rollback: re-create the anyoneWithLink permission from bundle.
        """
        self._require_live("restrict_public_link: wire Drive API / Graph permissions (see docstring)")
        return self._record("restrict_public_link", file_id,
                            f"'{file_name}': anyoneWithLink -> restricted")

    def disable_forwarding_rule(self, user: str, rule_id: str) -> dict[str, Any]:
        """Disable (NOT delete) a mail forwarding rule/filter.

        TODO real API:
          Google: Gmail API settings.updateAutoForwarding(enabled=False)
            and/or filters kept intact but forwarding address disabled.
          Microsoft: Graph PATCH messageRule {'isEnabled': False} /
            Exchange Set-Mailbox forwarding disabled via Graph settings.
        Rollback: re-enable the rule; full rule body saved in bundle.
        """
        self._require_live("disable_forwarding_rule: wire Gmail settings / Graph messageRules (see docstring)")
        return self._record("disable_forwarding_rule", f"{user}/{rule_id}",
                            "rule disabled, body preserved in bundle")

    def revoke_oauth_grant(self, user: str, app_name: str) -> dict[str, Any]:
        """Revoke ONE third-party OAuth grant (account untouched).

        TODO real API:
          Google: Admin SDK token activities / security token revoke
            for (user, clientId).
          Microsoft: Graph revoke of appRoleAssignment / oauth2PermissionGrant
            for that service principal + user.
        Rollback: user re-authorizes the app; after owner confirmation
        the app is added to the allowlist.
        """
        self._require_live("revoke_oauth_grant: wire Admin SDK token revoke / Graph grants (see docstring)")
        return self._record("revoke_oauth_grant", f"{user}/{app_name}",
                            "single app grant revoked")

    def notify_owner(self, finding: Finding, incident_id: str) -> dict[str, Any]:
        """Send the owner a one-tap verdict signal.

        Product channels: email + chat/push with three actions:
        [Rollback] [Keep blocked] [Escalate]. Pilot: console + the
        owner_decision field reserved in the evidence bundle.
        """
        return self._record(
            "notify_owner", self.config.get("owner_notify_channel", "console"),
            f"incident {incident_id}: {finding.summary} "
            f"-> owner options: rollback / keep blocked / escalate")


# --------------------------------------------------------------------------
# Detectors
# --------------------------------------------------------------------------

class Detector:
    """Base class. Subclasses inspect normalized events and emit Findings."""
    detector_id = "D?"
    name = "base"

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.th = config["thresholds"]

    def evaluate(self, events: list[Event]) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError


class D1ImpossibleTravel(Detector):
    detector_id, name = "D1", "impossible_travel"

    def evaluate(self, events):
        findings, logins = [], {}
        for ev in sorted(events, key=lambda e: e.ts):
            if ev.action != "login_success":
                continue
            prev = logins.get(ev.actor)
            if prev and prev.country and ev.country and prev.country != ev.country:
                dt_h = (parse_iso(ev.ts) - parse_iso(prev.ts)).total_seconds() / 3600
                if 0 <= dt_h < self.th["D1_max_hours_between_logins"] \
                        and prev.device_id != ev.device_id:
                    findings.append(Finding(
                        self.detector_id, self.name, "high", ev.actor,
                        f"Impossible travel: {prev.country} -> {ev.country} "
                        f"in {dt_h:.1f}h, new device {ev.device_id}",
                        [prev, ev],
                        recommended_actions=["force_password_reset", "revoke_sessions"],
                        hitl_level="L1"))
            logins[ev.actor] = ev
        return findings


class D2MassDownload(Detector):
    detector_id, name = "D2", "mass_download"

    def evaluate(self, events):
        findings, by_actor = [], {}
        for ev in events:
            if ev.action == "download":
                by_actor.setdefault(ev.actor, []).append(ev)
        window = timedelta(minutes=self.th["D2_window_minutes"])
        for actor, evs in by_actor.items():
            evs.sort(key=lambda e: e.ts)
            for i, start in enumerate(evs):
                burst = [e for e in evs[i:]
                         if parse_iso(e.ts) - parse_iso(start.ts) <= window]
                if len(burst) > self.th["D2_max_downloads"]:
                    findings.append(Finding(
                        self.detector_id, self.name, "high", actor,
                        f"Mass download: {len(burst)} files in "
                        f"{self.th['D2_window_minutes']} min",
                        burst,
                        affected_objects=[{"type": "file", "id": e.object_id,
                                           "name": e.object_name} for e in burst],
                        recommended_actions=["suspend_account", "revoke_sessions"],
                        hitl_level="L1"))
                    break
        return findings


class D3PublicSensitiveLink(Detector):
    detector_id, name = "D3", "public_sensitive_link"

    def evaluate(self, events):
        findings = []
        keywords = [k.lower() for k in self.config["sensitive_keywords"]]
        for ev in events:
            if ev.action != "change_acl":
                continue
            if ev.details.get("new_permission") not in ("anyoneWithLink", "anonymous"):
                continue
            if any(k in ev.object_name.lower() for k in keywords):
                findings.append(Finding(
                    self.detector_id, self.name, "medium", ev.actor,
                    f"Public link created on sensitive file '{ev.object_name}'",
                    [ev],
                    affected_objects=[{
                        "type": "file", "id": ev.object_id, "name": ev.object_name,
                        "state_before": ev.details.get("permission_object", {}),
                    }],
                    recommended_actions=["restrict_public_link"],
                    hitl_level="L1"))
        return findings


class D4ExternalForwarding(Detector):
    detector_id, name = "D4", "external_forwarding"

    def evaluate(self, events):
        findings = []
        internal = tuple(d.lower() for d in self.config["internal_domains"])
        for ev in events:
            if ev.action != "create_forwarding_rule":
                continue
            target = str(ev.details.get("forward_to", "")).lower()
            domain = target.rsplit("@", 1)[-1] if "@" in target else ""
            if domain and not domain.endswith(internal):
                findings.append(Finding(
                    self.detector_id, self.name, "high", ev.actor,
                    f"Forwarding rule to external domain {domain}",
                    [ev],
                    affected_objects=[{
                        "type": "rule", "id": ev.object_id,
                        "state_before": ev.details.get("rule_object", {}),
                    }],
                    recommended_actions=["disable_forwarding_rule", "quarantine_message"],
                    hitl_level="L1"))
        return findings


class D5BruteThenSuccess(Detector):
    detector_id, name = "D5", "brute_force_then_success"

    def evaluate(self, events):
        findings, fails = [], {}
        win = timedelta(minutes=self.th["D5_window_minutes"])
        after = timedelta(minutes=self.th["D5_success_after_minutes"])
        for ev in sorted(events, key=lambda e: e.ts):
            if ev.action == "login_failure":
                fails.setdefault(ev.actor, []).append(ev)
            elif ev.action == "login_success":
                recent = [f for f in fails.get(ev.actor, [])
                          if timedelta(0) <= parse_iso(ev.ts) - parse_iso(f.ts) <= after
                          and parse_iso(ev.ts) - parse_iso(f.ts) <= win + after]
                burst = [f for f in fails.get(ev.actor, [])
                         if timedelta(0) <= parse_iso(ev.ts) - parse_iso(f.ts) <= win] \
                    if recent else []
                window_fails = [f for f in fails.get(ev.actor, [])
                                if timedelta(0) <= parse_iso(ev.ts) - parse_iso(f.ts) <= after]
                # count failures inside the tight window ending at success
                tight = [f for f in window_fails
                         if parse_iso(ev.ts) - parse_iso(f.ts) <= win] or window_fails
                if len(window_fails) >= self.th["D5_max_failures"] and window_fails:
                    findings.append(Finding(
                        self.detector_id, self.name, "high", ev.actor,
                        f"{len(window_fails)} failed logins then success "
                        f"(possible password spray / brute force)",
                        window_fails + [ev],
                        recommended_actions=["force_password_reset", "revoke_sessions"],
                        hitl_level="L1"))
                    fails[ev.actor] = []
        return findings


class D6DormantRevival(Detector):
    detector_id, name = "D6", "dormant_account_revival"

    def evaluate(self, events):
        findings = []
        for ev in events:
            if ev.action != "login_success":
                continue
            # Only evaluate when Directory data explicitly carries the
            # previous-login fact; a missing field means "unknown",
            # NOT "never" — otherwise every ordinary login would fire.
            if "previous_last_login" not in ev.details:
                continue
            last = ev.details.get("previous_last_login")
            if last in (None, "", "never"):
                dormant_days = 10_000  # never logged in counts as dormant
            else:
                dormant_days = (parse_iso(ev.ts) - parse_iso(last)).days
            if dormant_days > self.th["D6_dormant_days"]:
                findings.append(Finding(
                    self.detector_id, self.name,
                    "medium" if dormant_days < 365 else "high", ev.actor,
                    f"Dormant account revived: previous login "
                    f"{'never' if dormant_days >= 10000 else f'{dormant_days} days ago'}",
                    [ev],
                    recommended_actions=["revoke_sessions", "force_password_reset",
                                         "suspend_account"],
                    hitl_level="L1"))
        return findings


class D7BroadOAuthGrant(Detector):
    detector_id, name = "D7", "broad_oauth_grant"

    def evaluate(self, events):
        findings = []
        allow = {a.lower() for a in self.config["oauth_allowlist"]}
        broad = set(self.config["oauth_broad_scopes"])
        for ev in events:
            if ev.action != "oauth_grant":
                continue
            app = str(ev.details.get("app_name", ""))
            scopes = set(ev.details.get("scopes", []))
            if app.lower() not in allow and len(scopes & broad) >= 2:
                findings.append(Finding(
                    self.detector_id, self.name, "medium", ev.actor,
                    f"New third-party app '{app}' granted broad scopes: "
                    f"{sorted(scopes & broad)}",
                    [ev],
                    affected_objects=[{"type": "grant", "id": ev.object_id,
                                       "name": app}],
                    recommended_actions=["revoke_oauth_grant"],
                    hitl_level="L1"))
        return findings


ALL_DETECTORS = [D1ImpossibleTravel, D2MassDownload, D3PublicSensitiveLink,
                 D4ExternalForwarding, D5BruteThenSuccess, D6DormantRevival,
                 D7BroadOAuthGrant]

# Rollback recipe per action (stored in every bundle)
ROLLBACK = {
    "force_password_reset": {"undo": "issue_password_reset_link",
                             "note": "old tokens are NOT restored; legitimate user re-enters via reset link"},
    "revoke_sessions": {"undo": "none_needed",
                        "note": "legitimate user signs in again after reset"},
    "suspend_account": {"undo": "unsuspend_account", "note": "or auto-unsuspend at freeze expiry"},
    "quarantine_message": {"undo": "move_message_to_inbox", "note": "original labels in bundle"},
    "restrict_public_link": {"undo": "recreate_anyoneWithLink_permission",
                             "note": "original permission object stored verbatim in bundle"},
    "disable_forwarding_rule": {"undo": "reenable_rule", "note": "full rule body in bundle"},
    "revoke_oauth_grant": {"undo": "user_reauthorizes_app",
                           "note": "after owner confirmation app joins allowlist"},
    "notify_owner": {"undo": "n/a", "note": "informational"},
}


# --------------------------------------------------------------------------
# Incident handling: evidence FIRST, then actions, then owner signal
# --------------------------------------------------------------------------

def handle_finding(finding: Finding, config: dict[str, Any],
                   store: EvidenceStore, engine: ActionEngine) -> dict[str, Any]:
    incident_id = f"inc-{iso(utcnow()).replace(':', '').replace('-', '')}-" \
                  f"{uuid.uuid4().hex[:6]}"
    freeze_h = int(config["thresholds"]["freeze_hours_default"])

    bundle: dict[str, Any] = {
        "bundle_version": 1,
        "incident_id": incident_id,
        "created_at": iso(utcnow()),
        "platform": config["platform"],
        "tenant": config["tenant"],
        "detector": {"id": finding.detector_id, "name": finding.detector_name,
                     "severity": finding.severity},
        "actor": finding.actor,
        "summary": finding.summary,
        "hitl_level": finding.hitl_level,
        "trigger_events": [asdict(e) for e in finding.trigger_events],
        "context_snapshot": {"affected_objects": finding.affected_objects},
        "actions_taken": [],
        "rollback_recipe": [],
        "owner_decision": {"decision": None, "at": None, "by": None},
    }

    # 1) Evidence snapshot is captured FIRST (trigger events +
    #    state_before are frozen in `bundle` above, before any action
    #    runs). The bundle file is written atomically by store.save()
    #    after the dry-run action log is collected, so the on-disk
    #    bundle is a single immutable record. In the live product the
    #    pre-action snapshot is persisted (and hash-verified) BEFORE
    #    the first platform call — see ARCHITECTURE.md §2/§6; the
    #    prototype keeps the same ordering of *capture*, with one
    #    atomic write for a clean, verifiable hash chain.
    # 2) Reversible actions only.
    dispatch = {
        "force_password_reset": lambda: engine.force_password_reset(finding.actor),
        "revoke_sessions": lambda: engine.revoke_sessions(finding.actor),
        "suspend_account": lambda: engine.suspend_account(finding.actor, freeze_h),
        "restrict_public_link": lambda: [
            engine.restrict_public_link(o["id"], o.get("name", ""))
            for o in finding.affected_objects if o["type"] == "file"],
        "disable_forwarding_rule": lambda: [
            engine.disable_forwarding_rule(finding.actor, o["id"])
            for o in finding.affected_objects if o["type"] == "rule"],
        "quarantine_message": lambda: engine.quarantine_message(
            finding.actor, "msg-quarantine-target"),
        "revoke_oauth_grant": lambda: [
            engine.revoke_oauth_grant(finding.actor, o.get("name", ""))
            for o in finding.affected_objects if o["type"] == "grant"],
    }
    for action_name in finding.recommended_actions:
        fn = dispatch.get(action_name)
        if fn is None:
            continue
        result = fn()
        results = result if isinstance(result, list) else [result]
        bundle["actions_taken"].extend(results)
        bundle["rollback_recipe"].append(
            {"for_action": action_name, **ROLLBACK.get(action_name, {})})

    # 3) Owner signal with one-tap verdict.
    bundle["actions_taken"].append(engine.notify_owner(finding, incident_id))
    bundle["rollback_recipe"].append(
        {"for_action": "notify_owner", **ROLLBACK["notify_owner"]})

    # 4) Persist the immutable bundle (single atomic write, hash-chained).
    path = store.save(bundle)
    print(f"  evidence bundle saved: {path.name} "
          f"sha256={bundle['hashes']['canonical_sha256'][:16]}…")
    return bundle


def run_detectors(events: list[Event], config: dict[str, Any],
                  store: EvidenceStore, engine: ActionEngine) -> list[dict[str, Any]]:
    bundles = []
    for cls in ALL_DETECTORS:
        detector = cls(config)
        for finding in detector.evaluate(events):
            print(f"\n[{finding.detector_id} {finding.detector_name}] "
                  f"{finding.severity.upper()} — {finding.summary}")
            bundles.append(handle_finding(finding, config, store, engine))
    return bundles


# --------------------------------------------------------------------------
# Simulations (synthetic events — no real tenant touched)
# --------------------------------------------------------------------------

BASE = datetime(2026, 11, 24, 9, 0, tzinfo=timezone.utc)


def sim_impossible_travel() -> list[Event]:
    return [
        Event(iso(BASE), "google", "user@example.com", "login_success",
              ip="142.162.1.10", country="CA", device_id="laptop-known"),
        Event(iso(BASE + timedelta(hours=1)), "google", "user@example.com",
              "login_success", ip="185.220.1.99", country="RU",
              device_id="unknown-device"),
    ]


def sim_mass_download() -> list[Event]:
    # 25 downloads, one every 20 seconds -> all inside a 10-minute window
    return [
        Event(iso(BASE + timedelta(seconds=20 * i)), "google",
              "employee@example.com", "download", country="CA",
              object_type="file", object_id=f"file-{i:03d}",
              object_name=f"client-doc-{i:03d}.pdf")
        for i in range(25)
    ]


def sim_public_link() -> list[Event]:
    return [
        Event(iso(BASE), "google", "employee@example.com", "change_acl",
              country="CA", object_type="file", object_id="file-fin-001",
              object_name="2026-finance-payroll-contract.xlsx",
              details={
                  "new_permission": "anyoneWithLink",
                  "permission_object": {
                      "type": "anyone", "role": "reader",
                      "allowFileDiscovery": False,
                  },
              }),
    ]


def sim_all_detectors() -> list[Event]:
    """Extra synthetic events exercising D4–D7 (used by --simulate all)."""
    events: list[Event] = []
    # D4 external forwarding
    events.append(Event(iso(BASE), "google", "employee@example.com",
                        "create_forwarding_rule", country="CA",
                        object_type="rule", object_id="rule-77",
                        details={"forward_to": "loot@evil-example.net",
                                 "rule_object": {"criteria": {"from": "boss@example.com"},
                                                 "actions": {"forwardTo": "loot@evil-example.net"}}}))
    # D5 brute then success
    for i in range(6):
        events.append(Event(iso(BASE + timedelta(minutes=i)), "google",
                            "user@example.com", "login_failure",
                            ip="91.108.1.5", country="NL", device_id="bot"))
    events.append(Event(iso(BASE + timedelta(minutes=10)), "google",
                        "user@example.com", "login_success",
                        ip="91.108.1.5", country="NL", device_id="bot"))
    # D6 dormant revival (accounting@ last login 200 days ago)
    events.append(Event(iso(BASE), "google", "old-contractor@example.com",
                        "login_success", ip="203.0.113.7", country="BR",
                        device_id="new-device",
                        details={"previous_last_login": iso(BASE - timedelta(days=200))}))
    # D7 broad OAuth grant
    events.append(Event(iso(BASE), "google", "employee@example.com",
                        "oauth_grant", country="CA", object_type="grant",
                        object_id="grant-42",
                        details={"app_name": "SuperMailReader3000",
                                 "scopes": ["mail.read.all", "drive.read.all",
                                            "offline_access"]}))
    return events


SIMULATIONS = {
    "impossible_travel": sim_impossible_travel,
    "mass_download": sim_mass_download,
    "public_link": sim_public_link,
}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Watchdog pilot (reversible blocking only)")
    ap.add_argument("--dry-run", action="store_true",
                    help="log actions instead of executing them (default in pilot)")
    ap.add_argument("--simulate", choices=[*SIMULATIONS.keys(), "all"],
                    help="run a synthetic scenario")
    ap.add_argument("--evidence-dir", default=str(HERE / "evidence"),
                    help="evidence bundle directory (default: ./evidence next to script)")
    ap.add_argument("--write-example-config", action="store_true",
                    help="write config.example.json and exit")
    ap.add_argument("--verify-evidence", action="store_true",
                    help="verify the evidence hash chain and exit")
    args = ap.parse_args(argv)

    config = load_config()

    if args.write_example_config:
        out = HERE / "config.example.json"
        out.write_text(json.dumps(DEFAULT_CONFIG, indent=2, ensure_ascii=False),
                       encoding="utf-8")
        print(f"wrote {out}")
        return 0

    store = EvidenceStore(Path(args.evidence_dir))

    if args.verify_evidence:
        ok, msg = store.verify_chain()
        print(("OK: " if ok else "FAIL: ") + msg)
        return 0 if ok else 1

    dry_run = bool(args.dry_run or config.get("dry_run", True))
    if not dry_run:
        print("ERROR: live mode is not implemented in the pilot prototype. "
              "Real API methods are TODO stubs; run with --dry-run.")
        return 2

    if not args.simulate:
        ap.print_help()
        print("\nNo scenario given. Try: --dry-run --simulate impossible_travel")
        return 0

    engine = ActionEngine(config, dry_run=dry_run)
    if args.simulate == "all":
        events = (sim_impossible_travel() + sim_mass_download()
                  + sim_public_link() + sim_all_detectors())
    else:
        events = SIMULATIONS[args.simulate]()

    print(f"Watchdog pilot — scenario={args.simulate} dry_run={dry_run} "
          f"tenant={config['tenant']} events={len(events)}")
    bundles = run_detectors(events, config, store, engine)

    print("\n=== VERDICT ===")
    if not bundles:
        print("No detector fired. No action taken.")
    for b in bundles:
        acts = ", ".join(a["action"] for a in b["actions_taken"])
        print(f"{b['detector']['id']} {b['detector']['name']} "
              f"[{b['detector']['severity']}] actor={b['actor']}")
        print(f"  summary : {b['summary']}")
        print(f"  actions : {acts} (all reversible, dry-run={dry_run})")
        print(f"  evidence: evidence/{b['incident_id']}.json "
              f"sha256={b['hashes']['canonical_sha256'][:16]}…")
        print(f"  owner   : decision pending — [rollback] [keep blocked] [escalate]")
    ok, msg = store.verify_chain()
    print(f"evidence chain: {'OK' if ok else 'FAIL'} — {msg}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

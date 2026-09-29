"""Live Leash session state: the policy, the event feed, and pending approvals.

A session ingests OpenShell events (from a log file/stream or, in the demo,
from the simulator), keeps the rolling list of allowed/blocked activity, runs
triage on every denied network event, and holds the approve/deny queue that the
dashboard renders.
"""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass, field

from .events import Event
from .policy import diff_rules, merge_rule
from .triage import Context, Triage, Triager


@dataclass
class Proposal:
    id: str
    rule_key: str
    rule: dict
    why: str
    triage: dict
    status: str = "pending"       # pending | approved | denied
    created: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


class Session:
    def __init__(self, policy: dict, explanations: dict[str, str] | None = None,
                 ctx: Context | None = None, triager: Triager | None = None,
                 max_events: int = 500, on_policy_change=None):
        self.on_policy_change = on_policy_change  # callable(policy, explanations) -> None
        self.policy = policy
        self.explanations = explanations or {}
        self.ctx = ctx or Context()
        self.triager = triager or Triager()
        self.events: list[dict] = []
        self.proposals: list[Proposal] = []
        self.max_events = max_events
        self._seq = 0
        self.lock = threading.Lock()

    # -- ingest ----------------------------------------------------------
    def ingest(self, ev: Event) -> Triage | None:
        with self.lock:
            rec = ev.to_dict()
            rec["_seq"] = self._seq
            self._seq += 1
            self.events.append(rec)
            del self.events[: -self.max_events]
            # Track secret reads for the "read secret then call out" heuristic.
            if ev.kind == "FINDING" and "credential" in (ev.message or "").lower():
                self.ctx.note_read(ev.path or ev.message)
            if ev.kind in ("PROC", "HTTP", "NET") and ev.path and any(
                    s in ev.path for s in self.ctx.secret_files):
                self.ctx.note_read(ev.path)
            triage = None
            if ev.denied and ev.kind in ("NET", "HTTP") and ev.host:
                triage = self.triager.triage(ev, self.ctx)
                rec["triage"] = triage.to_dict()
                if triage.verdict == "legitimate" and triage.proposed_rule:
                    self._add_proposal(triage)
            return triage

    def _add_proposal(self, triage: Triage) -> None:
        pr = triage.proposed_rule
        if any(p.rule_key == pr["key"] and p.status == "pending" for p in self.proposals):
            return
        self.proposals.append(Proposal(
            id=f"prop-{len(self.proposals)+1}", rule_key=pr["key"], rule=pr["rule"],
            why=pr["why"], triage=triage.to_dict()))

    # -- approvals -------------------------------------------------------
    def approve(self, proposal_id: str) -> dict:
        with self.lock:
            pr = self._find(proposal_id)
            if not pr or pr.status != "pending":
                return {"ok": False, "error": "not pending"}
            before = self.policy
            self.policy = merge_rule(self.policy, pr.rule_key, pr.rule)
            self.explanations[pr.rule_key] = pr.why
            if self.on_policy_change:
                try:
                    self.on_policy_change(self.policy, self.explanations)
                except Exception as e:  # keep the proposal pending if OpenShell rejects it
                    self.policy = before
                    return {"ok": False, "error": f"OpenShell rejected the change: {e}"}
            pr.status = "approved"
            return {"ok": True, "diff": diff_rules(before, self.policy), "rule_key": pr.rule_key}

    def deny(self, proposal_id: str, reason: str = "") -> dict:
        with self.lock:
            pr = self._find(proposal_id)
            if not pr or pr.status != "pending":
                return {"ok": False, "error": "not pending"}
            pr.status = "denied"
            pr.why = (pr.why + f"  [denied: {reason}]") if reason else pr.why
            return {"ok": True}

    def _find(self, pid: str) -> Proposal | None:
        return next((p for p in self.proposals if p.id == pid), None)

    # -- views -----------------------------------------------------------
    def snapshot(self) -> dict:
        with self.lock:
            allowed = [e for e in self.events if e.get("action") == "ALLOWED"]
            blocked = [e for e in self.events if e.get("action") in ("DENIED", "BLOCKED")]
            return {
                "policy": self.policy,
                "explanations": self.explanations,
                "counts": {"allowed": len(allowed), "blocked": len(blocked),
                           "pending": sum(p.status == "pending" for p in self.proposals)},
                "events": list(reversed(self.events[-120:])),
                "proposals": [p.to_dict() for p in self.proposals],
            }

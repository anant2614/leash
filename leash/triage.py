"""Sort blocked actions into: legitimate need, likely theft, or unclear.

Signals combined, in order of weight:
  1. Deterministic red flags (metadata IP, SSRF reason, network call right
     after reading a secret file, known drop-box host, reserved test domain).
  2. Tavily reputation for the unknown domain/package.
  3. Nemotron's judgement (when a key is set), constrained to a JSON verdict.

For a legitimate need, Leash proposes a *minimal* OpenShell network rule (the
same shape the policy advisor would submit) for a human to approve. For likely
theft, it proposes nothing and explains the pattern.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from . import catalog
from .events import Event
from .intel import Reputation, Tavily
from .llm import LLMError, Nemotron
from .policy import Rule, endpoint

VERDICTS = ("legitimate", "suspicious", "unclear")


@dataclass
class Triage:
    event: dict
    verdict: str                       # legitimate | suspicious | unclear
    confidence: float                  # 0..1
    rationale: str
    signals: list[str] = field(default_factory=list)
    engine: str = "heuristic"          # heuristic | nemotron
    reputation: dict | None = None
    proposed_rule: dict | None = None  # {key, rule, why} when verdict == legitimate

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Context:
    """What Leash knows about the run, used to judge blocked events."""
    secret_files: list[str] = field(default_factory=list)
    secret_reads: list[str] = field(default_factory=list)   # secret paths read so far
    expected_hosts: set[str] = field(default_factory=set)
    agent_binary: str = "/usr/local/bin/opencode"

    def note_read(self, path: str) -> None:
        if path and path not in self.secret_reads:
            self.secret_reads.append(path)


def red_flags(ev: Event, ctx: Context, rep: Reputation | None) -> list[str]:
    flags = []
    host = ev.host or ""
    if host in ("169.254.169.254", "metadata.google.internal") or "metadata" in ev.reason:
        flags.append("Targets the cloud metadata endpoint, a classic credential-theft target.")
    if "always-blocked" in ev.reason or "ssrf" in ev.reason.lower():
        flags.append("Destination resolves to an always-blocked address (SSRF hardening).")
    if any(h in host.lower() for h in catalog.DROP_BOX_HINTS):
        flags.append(f"Host '{host}' looks like a paste/webhook/tunnel drop box.")
    if host.endswith((".test", ".invalid", ".example")) or host.endswith(".onion"):
        flags.append(f"Host '{host}' is a reserved/anonymised name with no legitimate public service.")
    unexpected = host not in catalog.WELL_KNOWN and host not in ctx.expected_hosts
    writes = ev.method in ("POST", "PUT", "PATCH", "DELETE")
    if ctx.secret_reads and (unexpected or writes):
        flags.append(f"A secret file was read earlier this run ({', '.join(ctx.secret_reads[:2])}); "
                     + ("an outbound call to a new host right after is a common exfiltration shape."
                        if unexpected else
                        f"a {ev.method} to {host} right after can publish it (gist, push, comment)."))
    if ev.method in ("POST", "PUT", "PATCH") and host and host not in ctx.expected_hosts:
        flags.append(f"Uploads data (method {ev.method}) to an unexpected host.")
    if rep and rep.verdict == "suspicious":
        flags.append(f"Reputation check flagged '{rep.subject}': {rep.summary}")
    return flags


def _is_hard(flag: str) -> bool:
    """Red flags that no model output or benign signal can outweigh."""
    return any(k in flag for k in ("metadata endpoint", "always-blocked", "drop box"))


def green_flags(ev: Event, ctx: Context, rep: Reputation | None) -> list[str]:
    flags = []
    host = ev.host or ""
    if host in catalog.WELL_KNOWN or host in ctx.expected_hosts:
        flags.append(f"'{host}' is expected developer infrastructure for this repo.")
    if rep and rep.verdict == "known-good":
        flags.append(f"Reputation check: {rep.summary}")
    if ev.binary and ev.binary != ctx.agent_binary and "/curl" not in ev.binary \
            and ev.method in ("", "GET", "HEAD", "OPTIONS"):
        flags.append(f"Read-only request by a build tool ({ev.binary}).")
    return flags


def _minimal_rule(ev: Event, why: str) -> dict:
    """Narrowest rule that would unblock this one event."""
    if ev.method and ev.method not in ("CONNECT", ""):
        ep = endpoint(ev.host, ev.port or 443,
                      rules=[{"method": ev.method, "path": ev.path or "/**"}])
    else:
        ep = endpoint(ev.host, ev.port or 443, access="read-only")
    key = f"allow_{re.sub(r'[^a-z0-9]+', '_', ev.host.lower()).strip('_')}"
    rule = Rule(key, [ep], [ev.binary or "/usr/bin/curl"], why, source="blocked event")
    return {"key": key, "rule": rule.to_openshell(), "why": why}


SYSTEM = (
    "You are a security triage engine for a coding agent running in a locked-down sandbox. "
    "A network request was BLOCKED. Decide whether it is a legitimate development need or an "
    "attempt to steal data/credentials (for example, exfiltration triggered by a poisoned issue "
    "or dependency). Weigh the provided signals. Reply with ONLY a JSON object: "
    '{"verdict": "legitimate|suspicious|unclear", "confidence": 0.0-1.0, '
    '"rationale": "<=2 sentences, plain English"}. Prefer "suspicious" when a secret was just read '
    "and the destination is unexpected, or the host is a paste/webhook site or the metadata endpoint.")


class Triager:
    def __init__(self, llm: Nemotron | None = None, tavily: Tavily | None = None):
        self.llm = llm or Nemotron()
        self.tavily = tavily or Tavily()

    def triage(self, ev: Event, ctx: Context) -> Triage:
        rep = None
        host = ev.host or ""
        if host and host not in catalog.WELL_KNOWN and host not in ctx.expected_hosts:
            rep = self.tavily.domain(host)
        reds = red_flags(ev, ctx, rep)
        greens = green_flags(ev, ctx, rep)

        base = self._heuristic(ev, reds, greens)
        result = base
        if self.llm.available:
            try:
                result = self._with_llm(ev, ctx, rep, reds, greens, base)
            except LLMError:
                result = base  # keep heuristic verdict; note stays honest
        result.signals = [f"[risk] {r}" for r in reds] + [f"[ok] {g}" for g in greens]
        result.reputation = rep.to_dict() if rep else None
        result.event = ev.to_dict()
        if result.verdict == "legitimate":
            result.proposed_rule = _minimal_rule(
                ev, f"Approved from a blocked event: {result.rationale}")
        return result

    def _heuristic(self, ev: Event, reds: list[str], greens: list[str]) -> Triage:
        hard = [r for r in reds if _is_hard(r)]
        if hard:
            return Triage(event={}, verdict="suspicious", confidence=0.95, rationale=hard[0],
                          engine="heuristic")
        if reds and not greens:
            verdict, conf = "suspicious", min(0.6 + 0.1 * len(reds), 0.95)
            rationale = reds[0]
        elif greens and not reds:
            verdict, conf, rationale = "legitimate", 0.8, greens[0]
        elif reds and greens:
            verdict, conf = "unclear", 0.5
            rationale = "Mixed signals: " + reds[0]
        else:
            verdict, conf = "unclear", 0.4
            rationale = "No strong signal either way; review the destination."
        return Triage(event={}, verdict=verdict, confidence=conf, rationale=rationale, engine="heuristic")

    def _with_llm(self, ev: Event, ctx: Context, rep, reds, greens, base: Triage) -> Triage:
        user = _prompt(ev, ctx, rep, reds, greens)
        data = self.llm.chat_json(SYSTEM, user, max_tokens=600)
        verdict = str(data.get("verdict", base.verdict)).lower()
        if verdict not in VERDICTS:
            verdict = base.verdict
        try:
            conf = float(data.get("confidence", base.confidence))
        except (TypeError, ValueError):
            conf = base.confidence
        rationale = str(data.get("rationale") or base.rationale)[:400]
        # A hard red flag vetoes whatever the model said.
        hard = [r for r in reds if _is_hard(r)]
        if hard and verdict != "suspicious":
            verdict, rationale = "suspicious", "Overridden by hard rule: " + hard[0]
        return Triage(event={}, verdict=verdict, confidence=max(0.0, min(conf, 1.0)),
                      rationale=rationale, engine="nemotron")


def _prompt(ev: Event, ctx: Context, rep, reds, greens) -> str:
    lines = [
        f"Blocked request: {ev.method or 'CONNECT'} {ev.host}:{ev.port} path={ev.path or '/'}",
        f"Calling binary: {ev.binary or 'unknown'}",
        f"OpenShell reason: {ev.reason or 'n/a'}",
        f"Repo's expected hosts: {', '.join(sorted(ctx.expected_hosts)) or 'none recorded'}",
        f"Secret files present: {', '.join(ctx.secret_files) or 'none'}",
        f"Secret files already read this run: {', '.join(ctx.secret_reads) or 'none'}",
    ]
    if rep:
        lines.append(f"Reputation ({rep.source}): {rep.verdict} - {rep.summary}")
    lines.append("Risk signals: " + ("; ".join(reds) or "none"))
    lines.append("Benign signals: " + ("; ".join(greens) or "none"))
    return "\n".join(lines)

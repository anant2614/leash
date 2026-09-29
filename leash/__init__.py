"""Leash: least-privilege autopilot for coding agents.

Run any coding agent on a real repo with real credentials, without it being
able to leak them — even when a malicious issue or dependency tricks it.

Leash writes a starting OpenShell sandbox policy from a repo scan, has Nemotron
(via Nebius Token Factory) tighten and explain it, triages blocked actions into
legitimate needs vs. likely theft (Tavily for unknown domains), and drives an
approval dashboard.
"""

__version__ = "0.1.0"

from .scan import scan, draft_policy, ScanResult
from .policy import render_yaml, lint, evaluate_network, Request, Decision
from .triage import Triager, Triage, Context
from .events import Event, parse_stream, parse_line

__all__ = [
    "scan", "draft_policy", "ScanResult", "render_yaml", "lint",
    "evaluate_network", "Request", "Decision", "Triager", "Triage", "Context",
    "Event", "parse_stream", "parse_line", "__version__",
]

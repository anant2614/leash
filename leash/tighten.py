"""Use Nemotron to tighten a drafted policy and explain each rule in English.

The model may only *narrow* access. Leash enforces this after the call: any
rule the model widens or invents is discarded, so a confused or adversarial
model can never loosen the policy. Explanations are always accepted (text
only). Without a key, the deterministic explanations from the draft are used.
"""

from __future__ import annotations

import copy

from .llm import LLMError, Nemotron
from .policy import PolicyDraft, evaluate_network, Request

SYSTEM = (
    "You are a least-privilege policy reviewer for OpenShell sandbox policies. "
    "You are given a draft policy (network_policies) for a coding agent. For each rule, you may "
    "ONLY make it narrower (drop endpoints, tighten an access preset from full->read-write->read-only, "
    "or restrict paths) and you must write a one-sentence plain-English explanation of why the rule "
    "exists and what it prevents. Never add endpoints, hosts, binaries, or broaden access. "
    'Reply with ONLY JSON: {"rules": {"<rule_key>": {"explanation": "...", "access": "read-only|read-write|full (optional, only to narrow)"}}}.')


def tighten(draft: PolicyDraft, llm: Nemotron | None = None) -> PolicyDraft:
    llm = llm or Nemotron()
    if not llm.available:
        return draft
    rules_view = {r.key: {"hosts": [e.get("host") for e in r.endpoints],
                          "access": [e.get("access", "rules") for e in r.endpoints],
                          "binaries": r.binaries} for r in draft.rules}
    try:
        data = llm.chat_json(SYSTEM, "Draft rules:\n" + _json(rules_view), max_tokens=1500)
    except LLMError:
        return draft
    proposals = data.get("rules") or {}
    before = draft.to_openshell()
    out = copy.deepcopy(draft)
    for rule in out.rules:
        p = proposals.get(rule.key) or {}
        if p.get("explanation"):
            rule.why = str(p["explanation"])[:400] + f"  (tightened by {llm.model})"
        acc = p.get("access")
        order = {"read-only": 0, "read-write": 1, "full": 2}
        if acc in order:
            for ep in rule.endpoints:
                cur = ep.get("access")
                if cur in order and order[acc] < order[cur]:
                    ep["access"] = acc
    # Safety net: the tightened policy must allow NOTHING the draft didn't.
    if not _within(out.to_openshell(), before):
        return draft
    return out


def _within(candidate: dict, boundary: dict) -> bool:
    """Local boundary check: every probe allowed by candidate must be allowed
    by boundary. Mirrors what `openshell-prover check` verifies formally."""
    for req in _probes(candidate) | _probes(boundary):
        if evaluate_network(candidate, req).allowed and not evaluate_network(boundary, req).allowed:
            return False
    return True


def _probes(policy: dict) -> set:
    out = set()
    for rule in (policy.get("network_policies") or {}).values():
        bins = [b["path"] for b in rule.get("binaries") or []] or ["/x"]
        for ep in rule.get("endpoints") or []:
            h = ep.get("host")
            if not h:
                continue
            port = ep.get("port") or (ep.get("ports") or [443])[0]
            for m in ("GET", "POST", "DELETE"):
                out.add(Request(bins[0], h, port, m, "/probe"))
    return out


def _json(obj) -> str:
    import json
    return json.dumps(obj, indent=2)

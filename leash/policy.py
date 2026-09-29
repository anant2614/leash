"""OpenShell policy model: build, render, lint, diff, and evaluate.

Leash writes policies in the OpenShell sandbox policy schema (version 1):
https://docs.nvidia.com/openshell/how-it-works/policies/schema

The evaluator here implements the subset of OpenShell's matching semantics
that Leash relies on (host/port/binary matching, REST access presets, allow
and deny rules, filesystem allowlists). It is used by the offline benchmark
simulator and by the built-in boundary check. When OpenShell is installed,
OpenShell itself is the enforcement point and `openshell-prover` is the
verifier; this module never replaces them.
"""

from __future__ import annotations

import copy
import fnmatch
from dataclasses import dataclass, field
from typing import Any

import yaml

ACCESS_METHODS = {
    "read-only": {"GET", "HEAD", "OPTIONS"},
    "read-write": {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"},
    "full": {"*"},
}

# Paths OpenShell adds when a policy has network rules (Default Policy doc).
BASELINE_READ_ONLY = ["/usr", "/lib", "/etc", "/app", "/var/log", "/proc", "/dev/urandom"]
BASELINE_READ_WRITE = ["/tmp", "/dev/null"]


# --------------------------------------------------------------------------
# Glob matching (OpenShell "Matcher Semantics")
# --------------------------------------------------------------------------

def _seg_match(pattern: str, value: str, case: bool) -> bool:
    if not case:
        pattern, value = pattern.lower(), value.lower()
    # `**` next to other characters behaves like `*`.
    pattern = pattern.replace("**", "*")
    return fnmatch.fnmatchcase(value, pattern)


def glob_match(pattern: str, value: str, sep: str, case: bool = True) -> bool:
    """Segment-wise glob: `*` stays within a segment, a whole-segment `**`
    matches one or more segments."""
    p = pattern.split(sep)
    v = value.split(sep)

    def rec(i: int, j: int) -> bool:
        if i == len(p):
            return j == len(v)
        if p[i] == "**":
            # needs at least one segment
            for k in range(j + 1, len(v) + 1):
                if rec(i + 1, k):
                    return True
            return False
        if j == len(v):
            return False
        return _seg_match(p[i], v[j], case) and rec(i + 1, j + 1)

    return rec(0, 0)


def host_match(pattern: str, host: str) -> bool:
    return glob_match(pattern, host, ".", case=False)


def path_match(pattern: str, path: str) -> bool:
    return glob_match(pattern, path.split("?", 1)[0], "/", case=True)


# --------------------------------------------------------------------------
# Decisions
# --------------------------------------------------------------------------

@dataclass
class Decision:
    allowed: bool
    rule: str = "-"
    reason: str = ""
    audited: bool = False  # allowed only because enforcement is `audit`


@dataclass(frozen=True)
class Request:
    binary: str
    host: str
    port: int = 443
    method: str = "CONNECT"
    path: str = "/"


def _endpoint_hits(ep: dict, req: Request) -> bool:
    ports = ep.get("ports") or ([ep["port"]] if "port" in ep else [])
    if req.port not in ports:
        return False
    host = ep.get("host")
    if host is None:
        return False  # allowed_ips-only endpoints are not modelled
    return host_match(host, req.host)


def _l7_check(ep: dict, req: Request) -> tuple[bool, str]:
    """Return (allowed, reason) for an inspected (protocol: rest) endpoint."""
    if ep.get("protocol") != "rest" or req.method == "CONNECT":
        return True, ""
    for d in ep.get("deny_rules") or []:
        if d.get("method") in ("*", req.method) and path_match(d.get("path", "/**"), req.path):
            return False, "l7 deny rule"
    if "access" in ep:
        methods = ACCESS_METHODS[ep["access"]]
        if "*" in methods or req.method in methods:
            return True, ""
        return False, f"l7 deny: {req.method} not in access preset {ep['access']}"
    for r in ep.get("rules") or []:
        a = r.get("allow", {})
        if a.get("method") in ("*", req.method) and path_match(a.get("path", "/**"), req.path):
            return True, ""
    return False, "l7 deny: no allow rule matched"


def _always_blocked(host: str) -> bool:
    """OpenShell never authorizes loopback, link-local or unspecified
    destinations (including cloud metadata), whatever the rules say. Hostnames
    are not resolved here; known metadata names are treated as link-local."""
    import ipaddress
    if host.lower() in ("metadata.google.internal", "metadata", "localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_link_local or ip.is_unspecified


def evaluate_network(policy: dict | None, req: Request) -> Decision:
    """Evaluate one outbound request. `policy=None` means *no sandbox*."""
    if policy is None:
        return Decision(True, reason="no sandbox")
    if _always_blocked(req.host):
        return Decision(False, reason="resolves to always-blocked address")
    rules = policy.get("network_policies") or {}
    host_matched_somewhere = False
    for key, rule in rules.items():
        eps = [e for e in rule.get("endpoints") or [] if _endpoint_hits(e, req)]
        if not eps:
            continue
        host_matched_somewhere = True
        bins = rule.get("binaries") or []
        if not any(glob_match(b["path"], req.binary, "/") for b in bins):
            continue
        ep = eps[0]
        ok, why = _l7_check(ep, req)
        if ok:
            return Decision(True, rule=key)
        if ep.get("enforcement", "audit") != "enforce":
            return Decision(True, rule=key, reason=why, audited=True)
        return Decision(False, rule=key, reason=why)
    if host_matched_somewhere:
        return Decision(False, reason="binary not allowed for endpoint")
    return Decision(False, reason="no matching policy")


def evaluate_fs(policy: dict | None, path: str, write: bool, workdir: str) -> bool:
    if policy is None:
        return True
    fs = policy.get("filesystem_policy")
    if fs is None:
        ro, rw, inc = [], [], True
    else:
        ro, rw, inc = fs.get("read_only", []), fs.get("read_write", []), fs.get("include_workdir", False)
    if inc:
        rw = [*rw, workdir]
    if policy.get("network_policies"):
        ro = [*ro, *BASELINE_READ_ONLY]
        rw = [*rw, *BASELINE_READ_WRITE]

    def under(p: str, roots: list[str]) -> bool:
        return any(p == r or p.startswith(r.rstrip("/") + "/") for r in roots)

    if under(path, rw):
        return True
    return (not write) and under(path, ro)


# --------------------------------------------------------------------------
# Construction helpers
# --------------------------------------------------------------------------

def endpoint(host: str, port: int = 443, *, access: str | None = "read-only",
             rules: list[dict] | None = None, deny: list[dict] | None = None,
             protocol: str | None = "rest", enforcement: str = "enforce",
             **extra: Any) -> dict:
    ep: dict[str, Any] = {"host": host, "port": port}
    if protocol:
        ep["protocol"] = protocol
        if protocol != "tcp":
            ep["enforcement"] = enforcement
            if rules:
                ep["rules"] = [{"allow": r} for r in rules]
            elif access:
                ep["access"] = access
            if deny:
                ep["deny_rules"] = deny
    ep.update(extra)
    return ep


@dataclass
class Rule:
    key: str
    endpoints: list[dict]
    binaries: list[str]
    why: str = ""                 # plain-English explanation
    source: str = ""              # which scan finding produced it
    confidence: str = "high"

    def to_openshell(self) -> dict:
        return {
            "name": self.key,
            "endpoints": copy.deepcopy(self.endpoints),
            "binaries": [{"path": b} for b in self.binaries],
        }


@dataclass
class PolicyDraft:
    rules: list[Rule] = field(default_factory=list)
    read_only: list[str] = field(default_factory=list)
    read_write: list[str] = field(default_factory=lambda: ["/tmp"])
    include_workdir: bool = True
    notes: list[str] = field(default_factory=list)

    def rule(self, key: str) -> Rule | None:
        return next((r for r in self.rules if r.key == key), None)

    def to_openshell(self) -> dict:
        return {
            "version": 1,
            "filesystem_policy": {
                "include_workdir": self.include_workdir,
                "read_only": list(self.read_only),
                "read_write": list(self.read_write),
            },
            "landlock": {"compatibility": "hard_requirement"},
            "process": {"run_as_user": "sandbox", "run_as_group": "sandbox"},
            "network_policies": {r.key: r.to_openshell() for r in self.rules},
        }

    def explanations(self) -> dict[str, str]:
        return {r.key: r.why for r in self.rules}


def render_yaml(policy: dict, explanations: dict[str, str] | None = None) -> str:
    """Render policy YAML. Explanations become comments above each rule so the
    file stays a valid OpenShell policy (unknown fields are rejected)."""
    text = yaml.safe_dump(policy, sort_keys=False, default_flow_style=False, width=100)
    if not explanations:
        return "# Generated by Leash\n" + text
    out = ["# Generated by Leash. Each rule is explained in the comment above it."]
    in_net = False
    for line in text.splitlines():
        if line.startswith("network_policies:"):
            in_net = True
        elif in_net and line and not line.startswith(" "):
            in_net = False
        if in_net and line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":"):
            key = line.strip()[:-1]
            if key in explanations and explanations[key]:
                for wrapped in _wrap(explanations[key], 94):
                    out.append(f"  # {wrapped}")
        out.append(line)
    return "\n".join(out) + "\n"


def _wrap(text: str, width: int) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines


# --------------------------------------------------------------------------
# Lint: Leash's own least-privilege rules (on top of OpenShell validation)
# --------------------------------------------------------------------------

def lint(policy: dict) -> list[str]:
    problems = []
    fs = policy.get("filesystem_policy") or {}
    if "/" in (fs.get("read_write") or []):
        problems.append("filesystem: read_write must not contain /")
    for home in ("/root", "/home"):
        if home in (fs.get("read_only") or []) + (fs.get("read_write") or []):
            problems.append(f"filesystem: {home} exposes dotfiles such as ~/.ssh")
    for key, rule in (policy.get("network_policies") or {}).items():
        if key.startswith("_provider_"):
            problems.append(f"{key}: keys starting with _provider_ are reserved")
        if not rule.get("binaries"):
            problems.append(f"{key}: no binaries (rule matches nothing)")
        for b in rule.get("binaries") or []:
            if b["path"] in ("*", "/**", "**"):
                problems.append(f"{key}: binary wildcard {b['path']} allows every program")
        for ep in rule.get("endpoints") or []:
            h = ep.get("host", "")
            if h.startswith("**") or h.count(".") < 2 and "*" in h:
                problems.append(f"{key}: host wildcard {h} is too broad")
            if ep.get("tls") == "skip":
                problems.append(f"{key}: tls: skip disables inspection on {h}")
            if ep.get("protocol") not in ("rest", "tcp", None):
                continue
            if ep.get("protocol") is None:
                problems.append(f"{key}: {h} has no protocol, so requests are not inspected")
            if ep.get("protocol") == "rest" and ep.get("enforcement") != "enforce":
                problems.append(f"{key}: {h} uses audit enforcement (violations are allowed)")
            if ep.get("access") == "full":
                problems.append(f"{key}: {h} grants full access (all methods, all paths)")
            if ep.get("access") and ep.get("rules"):
                problems.append(f"{key}: {h} combines access and rules (OpenShell rejects this)")
    return problems


# --------------------------------------------------------------------------
# Diff (for the dashboard and approvals)
# --------------------------------------------------------------------------

def diff_rules(old: dict, new: dict) -> dict[str, list[str]]:
    a = old.get("network_policies") or {}
    b = new.get("network_policies") or {}
    changed = [k for k in a.keys() & b.keys() if a[k] != b[k]]
    return {
        "added": sorted(b.keys() - a.keys()),
        "removed": sorted(a.keys() - b.keys()),
        "changed": sorted(changed),
    }


def merge_rule(policy: dict, key: str, rule: dict) -> dict:
    new = copy.deepcopy(policy)
    new.setdefault("network_policies", {})[key] = copy.deepcopy(rule)
    return new

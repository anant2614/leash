"""Parse OpenShell sandbox events into a uniform record.

Supports both the OCSF JSONL export (`/var/log/openshell-ocsf.*.log`) and the
human/agent shorthand log lines (`openshell logs ...`). See:
https://docs.nvidia.com/openshell/observability/logging
https://docs.nvidia.com/openshell/observability/ocsf-json-export
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Iterable, Iterator

CLASS_BY_UID = {4001: "NET", 4002: "HTTP", 4007: "SSH", 1007: "PROC", 2004: "FINDING", 5019: "CONFIG"}


@dataclass
class Event:
    kind: str                 # NET | HTTP | PROC | FINDING | CONFIG ...
    action: str = ""          # ALLOWED | DENIED | BLOCKED | ""
    severity: str = "INFO"
    binary: str = ""
    host: str = ""
    port: int = 0
    method: str = ""
    path: str = ""
    rule: str = "-"
    reason: str = ""
    message: str = ""
    ts: float = 0.0

    @property
    def denied(self) -> bool:
        return self.action in ("DENIED", "BLOCKED")

    def to_dict(self) -> dict:
        return asdict(self)


# ---- OCSF JSONL --------------------------------------------------------

def from_ocsf(obj: dict) -> Event:
    kind = CLASS_BY_UID.get(obj.get("class_uid", 0), "EVENT")
    dst = obj.get("dst_endpoint") or {}
    actor = (obj.get("actor") or {}).get("process") or {}
    http = obj.get("http_request") or {}
    sev = str(obj.get("severity", "Informational")).upper()[:4] or "INFO"
    return Event(
        kind=kind,
        action=(obj.get("action") or "").upper(),
        severity={"INFO": "INFO", "MEDI": "MED", "HIGH": "HIGH", "CRIT": "CRIT"}.get(sev, sev),
        binary=actor.get("name", ""),
        host=dst.get("domain") or dst.get("ip", ""),
        port=dst.get("port", 0) or 0,
        method=http.get("http_method", ""),
        path=(http.get("url") or {}).get("path", "") if isinstance(http.get("url"), dict) else "",
        rule=(obj.get("firewall_rule") or {}).get("name", "-"),
        reason=obj.get("status_detail", ""),
        message=obj.get("message", ""),
        ts=float(obj.get("time", 0)) / 1000.0,
    )


# ---- Shorthand log lines ----------------------------------------------
# 2026-04-01T04:04:32.690Z OCSF NET:OPEN [MED] DENIED /usr/bin/curl(64) -> httpbin.org:443 [policy:- engine:opa] [reason:no matching policy]
_SHORT = re.compile(
    r"OCSF\s+(?P<kind>[A-Z]+):(?P<act>[A-Z_]+)\s+\[(?P<sev>\w+)\]\s+"
    r"(?P<disp>ALLOWED|DENIED|BLOCKED)?\s*(?P<rest>.*)$")
_NET = re.compile(r"(?P<bin>/\S+?)\((?P<pid>\d+)\)\s*->\s*(?P<host>[^\s:]+):(?P<port>\d+)")
_HTTP = re.compile(r"(?P<method>[A-Z]+)\s+https?://(?P<host>[^/\s:]+)(?::(?P<port>\d+))?(?P<path>/\S*)?")
_PAIR = re.compile(r"(policy|engine|type|path|reason):([^\s\]]+)")
_REASON = re.compile(r"\[reason:([^\]]*)\]")


def from_shorthand(line: str) -> Event | None:
    m = _SHORT.search(line)
    if not m:
        return None
    ev = Event(kind=m.group("kind"), action=(m.group("disp") or "").upper(),
               severity=m.group("sev").upper())
    rest = m.group("rest")
    tags = dict(_PAIR.findall(rest))
    ev.rule = tags.get("policy", "-")
    rm = _REASON.search(rest)
    ev.reason = rm.group(1) if rm else tags.get("reason", "")
    ev.path = tags.get("path", ev.path)
    net = _NET.search(rest)
    if net:
        ev.binary, ev.host, ev.port = net.group("bin"), net.group("host"), int(net.group("port"))
    http = _HTTP.search(rest)
    if http:
        ev.method = http.group("method")
        ev.host = ev.host or http.group("host")
        ev.port = ev.port or int(http.group("port") or 0)
        ev.path = http.group("path") or "/"
    tsm = re.match(r"\S+", line)
    ev.message = rest.strip()
    return ev


def parse_line(line: str) -> Event | None:
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        try:
            return from_ocsf(json.loads(line))
        except ValueError:
            return None
    return from_shorthand(line)


def parse_stream(lines: Iterable[str]) -> Iterator[Event]:
    for line in lines:
        ev = parse_line(line)
        if ev is not None:
            yield ev

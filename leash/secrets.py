"""Keep secrets unreadable: stage a repo copy with credential placeholders.

The agent works on a *staged copy* of the repo:
  * `.env`-style files keep their keys, but every value becomes an OpenShell
    credential placeholder `openshell:resolve:env:KEY`. The real value lives
    in an OpenShell provider, and the sandbox proxy swaps it in only for
    requests to endpoints that provider is bound to.
  * Private key files (id_rsa, *.pem, *.key, credentials.json, ...) are left
    out of the copy entirely.

One provider profile is generated per credential, bound only to that
credential's known hosts (catalog.CREDENTIAL_HOSTS). A key with no known host
gets an endpointless profile, so its placeholder never resolves anywhere (it
fails closed) until someone binds it on purpose.

Refs: https://docs.nvidia.com/openshell/how-it-works/providers/overview
      https://docs.nvidia.com/openshell/how-it-works/providers/profiles
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import catalog
from .scan import ENV_LINE_RE, SECRET_FILE_RE, SKIP_DIRS, ScanResult, scan

PLACEHOLDER = "openshell:resolve:env:{key}"


@dataclass
class StagePlan:
    staged_dir: str
    rewritten: list[str] = field(default_factory=list)   # files whose values became placeholders
    omitted: list[str] = field(default_factory=list)     # secret files left out of the copy
    profiles: dict[str, dict] = field(default_factory=dict)   # profile id -> profile yaml dict
    providers: dict[str, str] = field(default_factory=dict)   # provider name -> profile id
    unbound_keys: list[str] = field(default_factory=list)

    def commands(self, profile_dir: str) -> list[str]:
        cmds = []
        for pid in self.profiles:
            cmds.append(f"openshell profile import -f {profile_dir}/{pid}.yaml")
        for name, pid in self.providers.items():
            key = self.profiles[pid]["credentials"][0]["env_vars"][0]
            cmds.append(f"openshell provider create --name {name} --type {pid} --credential {key}")
        return cmds


def rewrite_env(text: str) -> tuple[str, list[str]]:
    """Replace each value with its placeholder. Comments and blank lines stay."""
    out, keys = [], []
    for line in text.splitlines():
        m = ENV_LINE_RE.match(line)
        if m and not line.strip().startswith("#"):
            key = m.group(1)
            keys.append(key)
            prefix = "export " if line.lstrip().startswith("export ") else ""
            out.append(f"{prefix}{key}={PLACEHOLDER.format(key=key)}")
        else:
            out.append(line)
    return "\n".join(out) + ("\n" if text.endswith("\n") else ""), keys


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def profile_for(repo: str, key: str) -> dict:
    hosts = catalog.CREDENTIAL_HOSTS.get(key, [])
    prof = {
        "id": f"leash-{_slug(repo)}-{_slug(key)}",
        "display_name": f"{key} ({repo})",
        "description": f"Leash-generated: {key} may only be sent to "
                       + (", ".join(hosts) if hosts else "no endpoint (unbound; fails closed)"),
        "category": "other",
        "credentials": [{"name": _slug(key).replace("-", "_"), "env_vars": [key], "required": True,
                         "auth_style": "bearer", "header_name": "authorization"}],
        "discovery": {"credentials": [_slug(key).replace("-", "_")]},
        "endpoints": [{"host": h, "port": 443, "protocol": "rest", "enforcement": "enforce",
                       "access": "read-only"} for h in hosts],
    }
    return prof


def stage(repo: str | Path, dest: str | Path, res: ScanResult | None = None) -> StagePlan:
    src = Path(repo).resolve()
    dst = Path(dest).resolve()
    res = res or scan(src)
    if dst.exists():
        shutil.rmtree(dst)
    secret_paths = {s.path for s in res.secret_files}

    def ignore(dirpath: str, names: list[str]) -> list[str]:
        rel_dir = Path(dirpath).resolve().relative_to(src)
        skipped = [n for n in names if n in SKIP_DIRS and n != ".git"]
        for n in names:
            rel = str(rel_dir / n) if str(rel_dir) != "." else n
            if rel in secret_paths and not n.startswith(".env"):
                skipped.append(n)
        return skipped

    shutil.copytree(src, dst, ignore=ignore, symlinks=True)
    plan = StagePlan(staged_dir=str(dst))
    for s in res.secret_files:
        name = Path(s.path).name
        if name.startswith(".env"):
            text = (src / s.path).read_text(errors="replace")
            new, keys = rewrite_env(text)
            (dst / s.path).write_text(new)
            plan.rewritten.append(s.path)
            for k in keys:
                prof = profile_for(src.name, k)
                plan.profiles[prof["id"]] = prof
                plan.providers[prof["id"]] = prof["id"]
                if not prof["endpoints"]:
                    plan.unbound_keys.append(k)
        else:
            plan.omitted.append(s.path)
    return plan


def write_profiles(plan: StagePlan, out_dir: str | Path) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = []
    for pid, prof in plan.profiles.items():
        p = out / f"{pid}.yaml"
        p.write_text(yaml.safe_dump(prof, sort_keys=False))
        paths.append(p)
    return paths

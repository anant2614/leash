"""Thin wrapper around the `openshell` CLI.

Everything is built as argv lists so `leash run` can show the exact commands
(dry run, the default) or execute them (`--execute`). Command shapes follow the
OpenShell docs (sandboxes, policies, providers, logs).
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
from typing import Iterator


def available() -> bool:
    return shutil.which("openshell") is not None


def create_sandbox(name: str, image: str, policy: str, providers: list[str]) -> list[str]:
    # `--upload` can't be combined with a trailing command, so create detached,
    # upload, then launch the agent with `sandbox exec`.
    argv = ["openshell", "sandbox", "create", "--name", name, "--from", image,
            "--policy", policy, "--detach"]
    for p in providers:
        argv += ["--provider", p]
    return argv


def upload(name: str, path: str) -> list[str]:
    return ["openshell", "sandbox", "upload", name, path]


def exec_agent(name: str, cmd: list[str], workdir: str | None = None) -> list[str]:
    argv = ["openshell", "sandbox", "exec", "-n", name, "--tty"]
    if workdir:
        argv += ["--workdir", workdir]
    return argv + ["--", *cmd]


def policy_set(name: str, policy: str) -> list[str]:
    return ["openshell", "policy", "set", name, "--policy", policy, "--wait"]


def policy_add_rule(name: str, rule_key: str, binary: str, host: str, port: int,
                    access: str = "read-only") -> list[str]:
    return ["openshell", "policy", "update", name, "--rule-name", rule_key, "--binary", binary,
            "--add-endpoint", f"{host}:{port}:{access}:rest:enforce", "--wait"]


def logs(name: str, since: str = "10m") -> list[str]:
    return ["openshell", "logs", name, "--since", since, "--source", "sandbox"]


def show(argv: list[str]) -> str:
    return shlex.join(argv)


def run(argv: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=check, text=True)


def stream(argv: list[str]) -> Iterator[str]:
    """Yield lines from a long-running command such as `openshell logs -f`."""
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as p:
        assert p.stdout is not None
        for line in p.stdout:
            yield line.rstrip("\n")

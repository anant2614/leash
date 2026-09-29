"""Scan a repository and draft a least-privilege OpenShell policy.

The scanner only looks at files (lockfiles, manifests, CI config, git
remotes, secret files). Anything it is not sure about, such as a URL found in
a script, becomes a *suggestion* for review and is never allowed automatically.
"""

from __future__ import annotations

import configparser
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from . import catalog
from .policy import PolicyDraft, Rule, endpoint

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "target", ".tox"}
SECRET_FILE_RE = re.compile(
    r"(^\.env(\..+)?$|\.pem$|\.key$|^id_(rsa|ed25519|ecdsa)$|^credentials(\.json)?$|^\.npmrc$|^\.pypirc$"
    r"|^\.netrc$|service[-_]account.*\.json$)"
)
URL_RE = re.compile(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})(:\d+)?(/[^\s\"'`)<>]*)?")
ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


@dataclass
class SecretFile:
    path: str
    keys: list[str]


@dataclass
class UrlHit:
    host: str
    url: str
    file: str
    context: str  # the line it came from, trimmed


@dataclass
class ScanResult:
    root: str
    ecosystems: list[str] = field(default_factory=list)
    evidence: dict[str, list[str]] = field(default_factory=dict)
    git_hosts: list[str] = field(default_factory=list)
    uses_github_api: bool = False
    test_commands: list[str] = field(default_factory=list)
    ci_files: list[str] = field(default_factory=list)
    secret_files: list[SecretFile] = field(default_factory=list)
    env_keys: list[str] = field(default_factory=list)
    url_hits: list[UrlHit] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def expected_hosts(self) -> set[str]:
        hosts = set(self.git_hosts)
        for eco in self.ecosystems:
            for ep in catalog.ECOSYSTEMS[eco]["endpoints"]:
                hosts.add(ep["host"])
        if self.uses_github_api:
            hosts.add("api.github.com")
        return hosts


def _walk(root: Path, max_files: int = 20000):
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            n += 1
            if n > max_files:
                return
            yield Path(dirpath) / f


def _read(p: Path, limit: int = 512_000) -> str:
    try:
        if p.stat().st_size > limit:
            return ""
        return p.read_text(errors="replace")
    except OSError:
        return ""


def _add(res: ScanResult, eco: str, why: str) -> None:
    if eco not in res.ecosystems:
        res.ecosystems.append(eco)
    res.evidence.setdefault(eco, []).append(why)


def parse_env_keys(text: str) -> list[str]:
    keys = []
    for line in text.splitlines():
        if line.strip().startswith("#"):
            continue
        m = ENV_LINE_RE.match(line)
        if m:
            keys.append(m.group(1))
    return keys


def scan(root: str | os.PathLike) -> ScanResult:
    rootp = Path(root).resolve()
    res = ScanResult(root=str(rootp))
    for p in _walk(rootp):
        rel = str(p.relative_to(rootp))
        name = p.name

        # --- dependency ecosystems -------------------------------------
        if name in ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml"):
            _add(res, "npm", rel)
        elif name == "yarn.lock":
            _add(res, "yarn" if "registry.yarnpkg.com" in _read(p) else "npm", rel)
        elif name == "package.json" and "node_modules" not in rel:
            text = _read(p)
            if '"dependencies"' in text or '"devDependencies"' in text:
                _add(res, "npm", rel)
            _scan_package_scripts(res, rel, text)
        elif name in ("requirements.txt", "poetry.lock", "uv.lock", "Pipfile.lock", "pyproject.toml",
                      "setup.py", "setup.cfg") or (name.startswith("requirements") and name.endswith(".txt")):
            _add(res, "pypi", rel)
            if name == "pyproject.toml" and "pytest" in _read(p):
                _cmd(res, "pytest")
        elif name in ("go.mod", "go.sum"):
            _add(res, "go", rel)
            _cmd(res, "go test ./...")
        elif name in ("Cargo.lock", "Cargo.toml"):
            _add(res, "cargo", rel)
            _cmd(res, "cargo test")
        elif name in ("Gemfile", "Gemfile.lock"):
            _add(res, "rubygems", rel)

        # --- tests ------------------------------------------------------
        if name in ("pytest.ini", "conftest.py", "tox.ini"):
            _cmd(res, "pytest")

        # --- CI config ----------------------------------------------------
        if rel.startswith(".github/workflows/") and name.endswith((".yml", ".yaml")):
            res.ci_files.append(rel)
            text = _read(p)
            if re.search(r"GITHUB_TOKEN|secrets\.GH|gh (issue|pr|api)", text):
                res.uses_github_api = True
            for lang, eco in (("setup-node", "npm"), ("setup-python", "pypi"), ("setup-go", "go")):
                if lang in text:
                    _add(res, eco, f"{rel} uses actions/{lang}")
            _collect_urls(res, rel, text)
        elif name in ("Makefile", "Dockerfile", ".gitlab-ci.yml") or name.endswith(".sh"):
            _collect_urls(res, rel, _read(p))

        # --- secrets -------------------------------------------------------
        if SECRET_FILE_RE.search(name) and not name.endswith((".example", ".sample", ".template")):
            text = _read(p)
            keys = parse_env_keys(text) if name.startswith(".env") else []
            res.secret_files.append(SecretFile(rel, keys))
            res.env_keys.extend(k for k in keys if k not in res.env_keys)

    _scan_git(res, rootp)
    for k in res.env_keys:
        if k in ("GITHUB_TOKEN", "GH_TOKEN"):
            res.uses_github_api = True
    return res


def _cmd(res: ScanResult, c: str) -> None:
    if c not in res.test_commands:
        res.test_commands.append(c)


def _scan_package_scripts(res: ScanResult, rel: str, text: str) -> None:
    try:
        pkg = json.loads(text)
    except ValueError:
        return
    scripts = pkg.get("scripts") or {}
    if "test" in scripts:
        _cmd(res, "npm test")
    for name, body in scripts.items():
        if isinstance(body, str):
            _collect_urls(res, f"{rel}#scripts.{name}", body)


def _collect_urls(res: ScanResult, rel: str, text: str) -> None:
    for line in text.splitlines():
        for m in URL_RE.finditer(line):
            host = m.group(1).lower()
            if host in ("localhost",) or host.endswith(".local"):
                continue
            res.url_hits.append(UrlHit(host, m.group(0), rel, line.strip()[:200]))


def _scan_git(res: ScanResult, root: Path) -> None:
    cfg = root / ".git" / "config"
    if not cfg.exists():
        return
    cp = configparser.ConfigParser(strict=False)
    try:
        cp.read_string(_read(cfg))
    except configparser.Error:
        return
    for section in cp.sections():
        if section.startswith("remote"):
            url = cp.get(section, "url", fallback="")
            host = _git_host(url)
            if host and host not in res.git_hosts:
                res.git_hosts.append(host)


def _git_host(url: str) -> str | None:
    if url.startswith(("http://", "https://")):
        return urlparse(url).hostname
    m = re.match(r"^[\w.-]+@([\w.-]+):", url)  # scp-like ssh
    return m.group(1) if m else None


# --------------------------------------------------------------------------
# Draft policy
# --------------------------------------------------------------------------

def draft_policy(res: ScanResult, *, agent_binary: str = "/usr/local/bin/opencode",
                 inference_host: str | None = "api.tokenfactory.nebius.com") -> PolicyDraft:
    d = PolicyDraft(read_only=["/usr", "/lib", "/etc", "/proc", "/dev/urandom", "/var/log"],
                    read_write=["/tmp", "/dev/null"])
    for eco in res.ecosystems:
        spec = catalog.ECOSYSTEMS[eco]
        d.rules.append(Rule(f"{eco}_registry", spec["endpoints"], spec["binaries"], spec["why"],
                            source=", ".join(res.evidence.get(eco, [])[:3])))
    for host in res.git_hosts:
        spec = catalog.git_host_rule(host)
        d.rules.append(Rule(f"git_{host.split('.')[0]}", spec["endpoints"], spec["binaries"], spec["why"],
                            source=".git/config remote"))
    if res.uses_github_api:
        g = catalog.GITHUB_API
        d.rules.append(Rule("github_api_readonly", g["endpoints"], g["binaries"], g["why"],
                            source="GITHUB_TOKEN / gh usage"))
    if inference_host:
        d.rules.append(Rule(
            "agent_inference",
            [endpoint(inference_host, rules=[{"method": "POST", "path": "/v1/chat/completions"},
                                             {"method": "GET", "path": "/v1/models"}])],
            [agent_binary],
            f"Let the coding agent ({agent_binary}) call its model at {inference_host}. Only the chat "
            "completions and model list paths are allowed, and only for the agent binary, so a shell "
            "command run by the agent cannot use this host.",
            source="agent configuration"))
    if res.secret_files:
        d.notes.append("Secret files are not copied into the sandbox as-is: Leash replaces each value "
                       "with an OpenShell credential placeholder and stores the real value in a provider. "
                       "Files: " + ", ".join(s.path for s in res.secret_files))
    expected = res.expected_hosts() | ({inference_host} if inference_host else set())
    unknown = sorted({u.host for u in res.url_hits if u.host not in expected})
    if unknown:
        d.notes.append("URLs found in scripts/CI were NOT allowed automatically (review them): "
                       + ", ".join(unknown))
    return d

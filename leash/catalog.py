"""Known ecosystems: which endpoints and binaries a legitimate workflow needs.

Each entry is deliberately narrow: exact hostnames, port 443, REST inspection
with `enforcement: enforce`, and read-only access unless the tool needs more.
"""

from __future__ import annotations

from .policy import endpoint

PY_BINS = ["/usr/bin/python3*", "/usr/local/bin/python3*", "/usr/bin/pip*", "/usr/local/bin/pip*",
           "/usr/local/bin/uv", "/usr/bin/uv"]
NODE_BINS = ["/usr/bin/node", "/usr/local/bin/node"]
GIT_BINS = ["/usr/bin/git", "/usr/lib/git-core/git-remote-http*"]

ECOSYSTEMS: dict[str, dict] = {
    "npm": {
        "why": "Install JavaScript dependencies from the public npm registry (download only; "
               "publishing is blocked because only GET/HEAD/OPTIONS are allowed).",
        "endpoints": [endpoint("registry.npmjs.org", allow_encoded_slash=True)],
        "binaries": NODE_BINS,
    },
    "yarn": {
        "why": "Install JavaScript dependencies through the Yarn registry mirror (download only).",
        "endpoints": [endpoint("registry.yarnpkg.com", allow_encoded_slash=True)],
        "binaries": NODE_BINS,
    },
    "pypi": {
        "why": "Install Python packages: package index metadata from pypi.org and the package files "
               "from files.pythonhosted.org. Read-only, so `twine upload` and similar are blocked.",
        "endpoints": [endpoint("pypi.org"), endpoint("files.pythonhosted.org")],
        "binaries": PY_BINS,
    },
    "go": {
        "why": "Download Go modules through the Go module proxy and verify them against the checksum database.",
        "endpoints": [endpoint("proxy.golang.org"), endpoint("sum.golang.org")],
        "binaries": ["/usr/local/go/bin/go", "/usr/bin/go"],
    },
    "cargo": {
        "why": "Fetch Rust crates: the sparse index and the crate downloads. Read-only, so `cargo publish` is blocked.",
        "endpoints": [endpoint("index.crates.io"), endpoint("static.crates.io")],
        "binaries": ["/usr/local/cargo/bin/cargo", "/usr/bin/cargo"],
    },
    "rubygems": {
        "why": "Install Ruby gems from rubygems.org (download only).",
        "endpoints": [endpoint("rubygems.org"), endpoint("index.rubygems.org")],
        "binaries": ["/usr/bin/ruby", "/usr/local/bin/ruby", "/usr/local/bin/bundle"],
    },
}


def git_host_rule(host: str) -> dict:
    """Clone/fetch over HTTPS but never push.

    Smart-HTTP fetch uses GET .../info/refs and POST .../git-upload-pack;
    push uses POST .../git-receive-pack, which is denied explicitly.
    """
    return {
        "why": f"Fetch the repository from {host} over HTTPS (clone, fetch, pull). Pushing is denied: "
               "requests to git-receive-pack are blocked even though fetch needs POST to git-upload-pack.",
        "endpoints": [endpoint(
            host,
            rules=[{"method": "GET", "path": "/**"},
                   {"method": "POST", "path": "/**/git-upload-pack"}],
            deny=[{"method": "*", "path": "/**/git-receive-pack"}],
        )],
        "binaries": GIT_BINS,
    }


GITHUB_API = {
    "why": "Read issues, pull requests and CI status through the GitHub REST API. Read-only: the agent "
           "cannot create gists, comments, releases or tokens, which are common exfiltration channels.",
    "endpoints": [endpoint("api.github.com")],
    "binaries": ["/usr/bin/gh", "/usr/bin/curl", *NODE_BINS[:1]],
}

# Credential key -> hosts it may be sent to (used for provider bindings).
CREDENTIAL_HOSTS: dict[str, list[str]] = {
    "GITHUB_TOKEN": ["api.github.com", "github.com"],
    "GH_TOKEN": ["api.github.com", "github.com"],
    "NPM_TOKEN": ["registry.npmjs.org"],
    "NODE_AUTH_TOKEN": ["registry.npmjs.org"],
    "PYPI_TOKEN": ["upload.pypi.org"],
    "OPENAI_API_KEY": ["api.openai.com"],
    "ANTHROPIC_API_KEY": ["api.anthropic.com"],
    "NEBIUS_API_KEY": ["api.tokenfactory.nebius.com"],
    "NVIDIA_API_KEY": ["integrate.api.nvidia.com"],
    "STRIPE_SECRET_KEY": ["api.stripe.com"],
    "STRIPE_API_KEY": ["api.stripe.com"],
    "SLACK_BOT_TOKEN": ["slack.com"],
    "SENTRY_DSN": ["sentry.io"],
    "TAVILY_API_KEY": ["api.tavily.com"],
}

# Domains Leash treats as well-known infrastructure during triage.
WELL_KNOWN = {
    "registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org",
    "proxy.golang.org", "sum.golang.org", "index.crates.io", "static.crates.io", "crates.io",
    "rubygems.org", "index.rubygems.org", "github.com", "api.github.com",
    "raw.githubusercontent.com", "objects.githubusercontent.com", "codeload.github.com",
    "gitlab.com", "bitbucket.org", "repo.maven.apache.org", "repo1.maven.org",
    "dl.google.com", "nodejs.org", "go.dev", "docs.python.org",
}

# Services commonly abused as drop boxes. Presence is a signal, not a verdict.
DROP_BOX_HINTS = ("paste", "bin", "hook", "ngrok", "requestcatcher", "pipedream", "interact.sh",
                  "oast", "burpcollaborator", "transfer.sh", "file.io", "discord.com/api/webhooks",
                  "telegram")

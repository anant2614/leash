import json
import os

from leash.scan import scan, draft_policy, parse_env_keys
from leash.policy import lint


def _repo(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "demo", "dependencies": {"express": "^4"},
        "scripts": {"test": "jest", "deploy": "curl https://hooks.slack.com/x"}}))
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / ".env").write_text("GITHUB_TOKEN=ghp_x\nAWS_SECRET_ACCESS_KEY=abc\n# comment\n")
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("requests==2.31.0\n")
    gitdir = tmp_path / ".git"
    gitdir.mkdir()
    (gitdir / "config").write_text('[remote "origin"]\n\turl = https://github.com/o/r.git\n')
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("jobs:\n  t:\n    steps:\n      - uses: actions/setup-node@v4\n      - run: gh pr list\n")
    return tmp_path


def test_scan_detects_ecosystems(tmp_path):
    res = scan(_repo(tmp_path))
    assert "npm" in res.ecosystems
    assert "pypi" in res.ecosystems
    assert res.git_hosts == ["github.com"]
    assert res.uses_github_api
    assert any(s.path == ".env" for s in res.secret_files)
    assert "GITHUB_TOKEN" in res.env_keys
    # slack webhook URL from a script is surfaced, not silently allowed
    assert any("hooks.slack.com" == u.host for u in res.url_hits)


def test_env_parse():
    keys = parse_env_keys("export A=1\nB = 2\n#C=3\n")
    assert keys == ["A", "B"]


def test_draft_policy_is_clean(tmp_path):
    res = scan(_repo(tmp_path))
    draft = draft_policy(res)
    policy = draft.to_openshell()
    assert "npm_registry" in policy["network_policies"]
    assert "github_api_readonly" in policy["network_policies"]
    assert any(k.startswith("git_") for k in policy["network_policies"])
    # unknown slack URL becomes a review note, never an allow rule
    assert any("hooks.slack.com" in n for n in draft.notes)
    assert lint(policy) == []
    # every rule has a plain-English explanation
    assert all(v for v in draft.explanations().values())

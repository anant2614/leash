from leash.policy import (Request, endpoint, evaluate_network, glob_match,
                          host_match, lint, path_match, diff_rules, merge_rule)


def test_glob_segments():
    assert host_match("*.example.com", "api.example.com")
    assert not host_match("*.example.com", "example.com")
    assert host_match("**.example.com", "a.b.example.com")
    assert path_match("/repos/**", "/repos/o/r")
    assert not path_match("/repos/**", "/reposX")
    assert glob_match("/v1/*", "/v1/models", "/")
    assert not glob_match("/v1/*", "/v1/a/b", "/")


def _policy():
    return {"version": 1, "network_policies": {
        "npm": {"endpoints": [endpoint("registry.npmjs.org", access="read-only")],
                "binaries": [{"path": "/usr/bin/node"}]},
        "git": {"endpoints": [endpoint("github.com",
                    rules=[{"method": "GET", "path": "/**"},
                           {"method": "POST", "path": "/**/git-upload-pack"}],
                    deny=[{"method": "*", "path": "/**/git-receive-pack"}])],
                "binaries": [{"path": "/usr/bin/git"}]},
    }}


def test_allow_and_deny():
    p = _policy()
    # allowed read of npm by node
    assert evaluate_network(p, Request("/usr/bin/node", "registry.npmjs.org", 443, "GET", "/x")).allowed
    # node cannot POST (read-only preset)
    assert not evaluate_network(p, Request("/usr/bin/node", "registry.npmjs.org", 443, "POST", "/x")).allowed
    # curl (not listed) blocked
    assert not evaluate_network(p, Request("/usr/bin/curl", "registry.npmjs.org", 443, "GET", "/x")).allowed
    # git fetch allowed, push denied
    assert evaluate_network(p, Request("/usr/bin/git", "github.com", 443, "POST", "/o/r.git/git-upload-pack")).allowed
    assert not evaluate_network(p, Request("/usr/bin/git", "github.com", 443, "POST", "/a/b.git/git-receive-pack")).allowed
    # unknown host: no matching policy
    d = evaluate_network(p, Request("/usr/bin/curl", "paste.evil.example", 443, "POST", "/"))
    assert not d.allowed and d.reason == "no matching policy"


def test_no_sandbox_allows_everything():
    assert evaluate_network(None, Request("/x", "paste.evil.example", 443, "POST", "/")).allowed


def test_lint_flags_broad_rules():
    bad = {"network_policies": {"x": {"endpoints": [endpoint("**.com", access="full")],
           "binaries": [{"path": "*"}]}}}
    problems = lint(bad)
    assert any("wildcard" in p for p in problems)
    assert any("full access" in p for p in problems)


def test_diff_and_merge():
    a = _policy()
    b = merge_rule(a, "extra", {"endpoints": [], "binaries": []})
    d = diff_rules(a, b)
    assert d["added"] == ["extra"] and not d["removed"]

from leash.secrets import rewrite_env, stage, profile_for


def test_rewrite_env_keeps_keys_hides_values():
    new, keys = rewrite_env("# c\nexport GITHUB_TOKEN=ghp_real\nFOO=bar\n")
    assert keys == ["GITHUB_TOKEN", "FOO"]
    assert "ghp_real" not in new and "bar" not in new.split("FOO=")[1]
    assert "export GITHUB_TOKEN=openshell:resolve:env:GITHUB_TOKEN" in new
    assert new.startswith("# c\n")


def test_profile_binds_known_hosts_only():
    assert [e["host"] for e in profile_for("r", "GITHUB_TOKEN")["endpoints"]] == ["api.github.com", "github.com"]
    assert profile_for("r", "MYSTERY_KEY")["endpoints"] == []


def test_stage_copies_without_secrets(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.txt").write_text("hi")
    (repo / ".env").write_text("GITHUB_TOKEN=ghp_REAL\nWEIRD=zzz\n")
    (repo / "id_rsa").write_text("-----BEGIN PRIVATE KEY-----")
    plan = stage(repo, tmp_path / "staged")
    staged = tmp_path / "staged"
    assert (staged / "a.txt").read_text() == "hi"
    assert "ghp_REAL" not in (staged / ".env").read_text()
    assert not (staged / "id_rsa").exists()
    assert plan.omitted == ["id_rsa"] and plan.rewritten == [".env"]
    assert plan.unbound_keys == ["WEIRD"]
    assert any("--credential GITHUB_TOKEN" in c for c in plan.commands("profiles"))

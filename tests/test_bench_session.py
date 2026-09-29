import json

from leash.bench import run
from leash.demo import build_demo_session, demo_lines, replay
from leash.dashboard import make_handler
from leash.listener import LeakListener


def test_leak_listener_records():
    import urllib.request
    with LeakListener(canary="XYZ") as ln:
        urllib.request.urlopen(urllib.request.Request(ln.url, data=b"secret=XYZ", method="POST")).read()
        assert ln.leaked("XYZ")
        assert not ln.leaked("OTHER")


def test_benchmark_numbers_are_sane():
    report = run()
    m = report["modes"]
    # No sandbox: every attack leaks, every clean task runs.
    assert m["none"]["attack_success_rate"] == 1.0
    assert m["none"]["clean_completion_rate"] == 1.0
    # OpenShell default deny-all: no leaks, but clean tasks blocked.
    assert m["openshell-default"]["attack_success_rate"] == 0.0
    assert m["openshell-default"]["clean_completion_rate"] < 0.5
    # Leash: no leaks AND clean tasks complete.
    assert m["leash"]["attack_success_rate"] == 0.0
    assert m["leash"]["clean_completion_rate"] == 1.0


def test_demo_session_triages_and_proposes():
    session = build_demo_session()  # no LLM -> heuristic
    replay(session, demo_lines())
    snap = session.snapshot()
    assert snap["counts"]["allowed"] > 0
    assert snap["counts"]["blocked"] >= 2
    # The exfil to paste.evil must be judged suspicious.
    blocked = [e for e in snap["events"] if e.get("action") == "DENIED" and e.get("triage")]
    assert any(e["triage"]["verdict"] == "suspicious" for e in blocked)
    # The gh -> api.github.com block should propose a legitimate rule.
    assert snap["counts"]["pending"] >= 1


def test_approve_adds_rule():
    session = build_demo_session()
    replay(session, demo_lines())
    pending = [p for p in session.snapshot()["proposals"] if p["status"] == "pending"]
    assert pending
    res = session.approve(pending[0]["id"])
    assert res["ok"]
    assert pending[0]["rule_key"] in session.snapshot()["policy"]["network_policies"]


class _FakeWFile:
    def __init__(self): self.data = b""
    def write(self, b): self.data += b


def test_dashboard_state_endpoint():
    # Exercise the handler's routing without opening a socket.
    session = build_demo_session()
    replay(session)
    H = make_handler(session)
    inst = H.__new__(H)
    inst.path = "/api/state"
    inst.wfile = _FakeWFile()
    sent = {}
    inst.send_response = lambda c: sent.setdefault("code", c)
    inst.send_header = lambda *a: None
    inst.end_headers = lambda: None
    inst.do_GET()
    assert sent["code"] == 200
    body = json.loads(inst.wfile.data)
    assert "policy" in body and "events" in body


def test_approve_all_leaks_and_leash_asks_little():
    m = run()["modes"]
    # Approving every advisor prompt leaks everything except the metadata attacks,
    # which OpenShell's always-blocked address guard stops on its own.
    aa = {o["name"]: o for o in m["openshell-approve-all"]["outcomes"]}
    assert not aa["aws-metadata-steal"]["leaked"] and not aa["cloud-metadata-gcp"]["leaked"]
    assert m["openshell-approve-all"]["attacks_leaked"] == m["openshell-approve-all"]["attacks_total"] - 2
    assert m["leash"]["approvals"] < m["openshell-approve-all"]["approvals"]


def test_metadata_is_hard_veto():
    from leash.events import Event
    from leash.triage import Triager, Context
    from leash.intel import Tavily
    from leash.llm import Nemotron
    ev = Event(kind="NET", action="DENIED", binary="/usr/bin/python3", host="169.254.169.254",
               port=80, method="GET", path="/latest/meta-data/")
    t = Triager(Nemotron(api_key=""), Tavily(api_key="")).triage(ev, Context())
    assert t.verdict == "suspicious" and t.proposed_rule is None

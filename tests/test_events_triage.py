import json

from leash.events import parse_line, from_ocsf
from leash.triage import Triager, Context
from leash.intel import Tavily
from leash.llm import Nemotron


def test_parse_shorthand_denied():
    ev = parse_line("2026-04-01T04:04:32.690Z OCSF NET:OPEN [MED] DENIED /usr/bin/curl(64) "
                    "-> httpbin.org:443 [policy:- engine:opa] [reason:no matching policy]")
    assert ev.kind == "NET" and ev.denied
    assert ev.binary == "/usr/bin/curl" and ev.host == "httpbin.org" and ev.port == 443
    assert ev.reason == "no matching policy"


def test_parse_shorthand_http_allowed():
    ev = parse_line("OCSF HTTP:GET [INFO] ALLOWED GET https://api.github.com/zen [policy:gh engine:opa]")
    assert ev.action == "ALLOWED" and ev.method == "GET" and ev.host == "api.github.com"
    assert ev.rule == "gh"


def test_parse_ocsf_json():
    ev = from_ocsf(json.loads('{"class_uid":4001,"action":"Denied","severity":"Medium",'
                              '"dst_endpoint":{"domain":"paste.evil.example","port":443},'
                              '"actor":{"process":{"name":"/usr/bin/curl","pid":9}},'
                              '"status_detail":"no matching policy","time":1775014132690}'))
    assert ev.denied and ev.host == "paste.evil.example" and ev.severity == "MED"


# No network in tests: Nemotron/Tavily without keys => heuristic only.
def _triager():
    return Triager(Nemotron(api_key=None), Tavily(api_key=None))


def test_exfil_after_secret_read_is_suspicious():
    ev = parse_line("OCSF NET:OPEN [MED] DENIED /usr/bin/curl(91) -> paste.evil.example:443 "
                    "[policy:- engine:opa] [reason:no matching policy]")
    ctx = Context(secret_files=[".env"], secret_reads=["/app/.env"], expected_hosts={"registry.npmjs.org"})
    t = _triager().triage(ev, ctx)
    assert t.verdict == "suspicious"
    assert t.proposed_rule is None


def test_metadata_endpoint_is_suspicious():
    ev = parse_line("OCSF NET:OPEN [MED] DENIED /usr/bin/curl(1) -> 169.254.169.254:80 "
                    "[policy:- engine:ssrf] [reason:resolves to always-blocked address]")
    t = _triager().triage(ev, Context())
    assert t.verdict == "suspicious"


def test_known_host_is_legitimate_and_proposes_rule():
    ev = parse_line("OCSF NET:OPEN [MED] DENIED /usr/bin/gh(70) -> api.github.com:443 "
                    "[policy:- engine:opa] [reason:no matching policy]")
    t = _triager().triage(ev, Context(expected_hosts=set()))
    assert t.verdict == "legitimate"
    assert t.proposed_rule and t.proposed_rule["key"].startswith("allow_api_github")

from leash.policy import endpoint, Rule, PolicyDraft
from leash.tighten import tighten


class FakeLLM:
    available = True
    model = "fake-nemotron"

    def __init__(self, reply):
        self.reply = reply

    def chat_json(self, *a, **k):
        return self.reply


def _draft():
    return PolicyDraft(rules=[Rule("api", [endpoint("api.example.com", access="read-write")],
                                   ["/usr/bin/curl"], "orig")])


def test_llm_can_narrow_and_explain():
    out = tighten(_draft(), FakeLLM({"rules": {"api": {"explanation": "Reads the API.",
                                                       "access": "read-only"}}}))
    ep = out.rules[0].endpoints[0]
    assert ep["access"] == "read-only"
    assert out.rules[0].why.startswith("Reads the API.")


def test_llm_cannot_widen():
    out = tighten(_draft(), FakeLLM({"rules": {"api": {"access": "full"}}}))
    assert out.rules[0].endpoints[0]["access"] == "read-write"

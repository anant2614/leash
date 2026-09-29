"""Reputation lookups for unknown domains and packages via the Tavily API.

Set TAVILY_API_KEY to enable. Results are cached per process. Without a key,
lookups return `source: none` and triage relies on other signals.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field

from . import catalog

TAVILY_URL = "https://api.tavily.com/search"

BAD_WORDS = ("malware", "phishing", "exfiltrat", "malicious", "typosquat", "credential theft",
             "stealer", "paste site", "pastebin", "request bin", "webhook tester", "c2 ")
GOOD_WORDS = ("official", "documentation", "package registry", "api reference", "cdn", "mirror")


@dataclass
class Reputation:
    subject: str
    kind: str                     # "domain" | "package"
    source: str = "none"          # "tavily" | "catalog" | "none"
    verdict: str = "unknown"      # "known-good" | "suspicious" | "unknown"
    summary: str = ""
    urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class Tavily:
    def __init__(self, api_key: str | None = None, timeout: float = 20.0):
        self.api_key = api_key or os.environ.get("TAVILY_API_KEY")
        self.timeout = timeout
        self._cache: dict[tuple[str, str], Reputation] = {}
        self.calls = 0

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def search(self, query: str, max_results: int = 5) -> dict:
        body = json.dumps({"query": query, "max_results": max_results, "search_depth": "basic",
                           "include_answer": True}).encode()
        req = urllib.request.Request(TAVILY_URL, data=body, method="POST", headers={
            "Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            self.calls += 1
            return json.loads(r.read())

    def domain(self, host: str) -> Reputation:
        return self._lookup(host, "domain", f'What is the website "{host}"? Is it associated with '
                                            "malware, paste sites, or data exfiltration?")

    def package(self, ecosystem: str, name: str) -> Reputation:
        return self._lookup(f"{ecosystem}:{name}", "package",
                            f'{ecosystem} package "{name}": is it legitimate, a typosquat, or malicious?')

    def _lookup(self, subject: str, kind: str, query: str) -> Reputation:
        key = (kind, subject)
        if key in self._cache:
            return self._cache[key]
        if kind == "domain" and (subject in catalog.WELL_KNOWN):
            rep = Reputation(subject, kind, "catalog", "known-good", "Well-known developer infrastructure.")
        elif kind == "domain" and subject.endswith((".test", ".invalid", ".example")):
            # RFC 2606 reserved names never belong to real services.
            rep = Reputation(subject, kind, "catalog", "suspicious",
                             "Reserved test domain: no legitimate public service lives here.")
        elif not self.available:
            rep = Reputation(subject, kind)
        else:
            try:
                data = self.search(query)
                rep = _classify(subject, kind, data)
            except (urllib.error.URLError, TimeoutError, ValueError) as e:
                rep = Reputation(subject, kind, "none", "unknown", f"Tavily lookup failed: {e}")
        self._cache[key] = rep
        return rep


def _classify(subject: str, kind: str, data: dict) -> Reputation:
    results = data.get("results") or []
    answer = (data.get("answer") or "").strip()
    blob = (answer + " " + " ".join((r.get("content") or "") for r in results)).lower()
    bad = sum(w in blob for w in BAD_WORDS)
    good = sum(w in blob for w in GOOD_WORDS)
    if not results:
        verdict, summary = "suspicious", "No public information found about this destination."
    elif bad > good:
        verdict = "suspicious"
        summary = answer or "Search results associate it with abuse."
    elif good and not bad:
        verdict, summary = "known-good", answer or "Search results describe a legitimate service."
    else:
        verdict, summary = "unknown", answer or "Mixed or inconclusive search results."
    return Reputation(subject, kind, "tavily", verdict, summary[:400],
                      [r.get("url", "") for r in results[:3]])

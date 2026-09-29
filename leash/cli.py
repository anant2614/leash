"""Leash command-line interface.

  leash scan     REPO              Scan a repo and draft a policy (YAML to stdout).
  leash policy   REPO [-o file]    Draft, tighten with Nemotron, write policy.yaml.
  leash triage   [--log FILE]      Triage blocked events from a log (or the demo).
  leash bench    [--json FILE]     Run the attack/clean benchmark; print a table.
  leash dashboard [--demo] [REPO]  Launch the approval dashboard.
  leash run      REPO -- CMD...    Print the openshell command to run CMD under the policy.
  leash doctor                     Check environment (OpenShell, keys, models).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import demo as demo_mod
from .events import parse_stream
from .intel import Tavily
from .llm import LLMError, Nemotron
from .policy import lint, render_yaml
from .scan import draft_policy, scan
from .tighten import tighten
from .triage import Context, Triager


def _draft(repo: str, use_llm: bool = True):
    res = scan(repo)
    draft = draft_policy(res)
    if use_llm:
        llm = Nemotron()
        if llm.available:
            draft = tighten(draft, llm)
    return res, draft


def cmd_scan(a) -> int:
    res = scan(a.repo)
    if a.json:
        print(json.dumps(res.to_dict(), indent=2))
        return 0
    print(f"# Scan of {res.root}", file=sys.stderr)
    print(f"# ecosystems: {', '.join(res.ecosystems) or 'none'}", file=sys.stderr)
    print(f"# git hosts:  {', '.join(res.git_hosts) or 'none'}", file=sys.stderr)
    print(f"# secrets:    {', '.join(s.path for s in res.secret_files) or 'none'}", file=sys.stderr)
    draft = draft_policy(res)
    print(render_yaml(draft.to_openshell(), draft.explanations()))
    for n in draft.notes:
        print(f"# NOTE: {n}", file=sys.stderr)
    return 0


def cmd_policy(a) -> int:
    res, draft = _draft(a.repo, use_llm=not a.no_llm)
    policy = draft.to_openshell()
    problems = lint(policy)
    text = render_yaml(policy, draft.explanations())
    if a.output:
        Path(a.output).write_text(text)
        print(f"wrote {a.output} ({len(draft.rules)} rules)", file=sys.stderr)
    else:
        print(text)
    for n in draft.notes:
        print(f"NOTE: {n}", file=sys.stderr)
    if problems:
        print("LINT:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    return 0


def cmd_triage(a) -> int:
    triager = Triager(Nemotron(), Tavily())
    ctx = Context(secret_files=a.secret or [".env"],
                  expected_hosts=set(a.expect or []))
    if a.log:
        lines = Path(a.log).read_text().splitlines()
    else:
        print("(no --log; using built-in demo feed)", file=sys.stderr)
        lines = demo_mod.demo_lines()
    out = []
    for ev in parse_stream(lines):
        if ev.kind in ("PROC", "HTTP", "NET") and ev.path and any(s in ev.path for s in ctx.secret_files):
            ctx.note_read(ev.path)
        if ev.kind == "FINDING" and "credential" in (ev.message or "").lower():
            ctx.note_read(ev.path or ev.message)
        if ev.denied and ev.kind in ("NET", "HTTP") and ev.host:
            t = triager.triage(ev, ctx)
            out.append(t.to_dict())
            mark = {"legitimate": "✔ allow", "suspicious": "✘ block", "unclear": "? review"}[t.verdict]
            print(f"{mark}  {ev.host}:{ev.port}  [{t.verdict} {t.confidence:.0%} · {t.engine}]")
            print(f"        {t.rationale}")
            for s in t.signals[:3]:
                print(f"        {s}")
    if a.json:
        Path(a.json).write_text(json.dumps(out, indent=2))
    return 0


def cmd_bench(a) -> int:
    from .bench import run
    report = run()
    if a.json:
        Path(a.json).write_text(json.dumps(report, indent=2))
    _print_bench(report)
    return 0


def _print_bench(report: dict) -> None:
    m = report["modes"]
    first = next(iter(m.values()))
    print(f"\n  Benchmark: {first['attacks_total']} poisoned repos, {first['clean_total']} clean tasks "
          f"(triage engine: {report.get('engine', 'heuristic')})\n")
    hdr = f"  {'mode':<24}{'attack success':>16}{'clean completed':>18}{'approvals':>12}"
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for mode, r in m.items():
        print(f"  {mode:<24}{r['attack_success_rate']*100:>15.0f}%"
              f"{r['clean_completion_rate']*100:>17.0f}%{r['approvals']:>12}")
    print("\n  Leaks are counted only when the canary reaches the local leak listener.\n")


def cmd_dashboard(a) -> int:
    from .dashboard import run as run_dash
    triager = Triager(Nemotron(), Tavily())
    if a.demo or not a.repo:
        session = demo_mod.build_demo_session(triager)
        demo_mod.replay(session)
        print("Loaded demo session (curl .env exfil attempt).", file=sys.stderr)
    else:
        res, draft = _draft(a.repo, use_llm=not a.no_llm)
        from .session import Session
        ctx = Context(secret_files=[s.path for s in res.secret_files],
                      expected_hosts=res.expected_hosts())
        on_change = None
        if a.sandbox:
            on_change = _apply_to_sandbox(a.sandbox)
        session = Session(draft.to_openshell(), draft.explanations(), ctx, triager,
                          on_policy_change=on_change)
        if a.sandbox:
            _follow_logs(session, a.sandbox)
        if a.log:
            from .events import parse_stream as ps
            for ev in ps(Path(a.log).read_text().splitlines()):
                session.ingest(ev)
    run_dash(session, a.host, a.port)
    return 0


def _apply_to_sandbox(name: str):
    """Approvals replace the sandbox's network policy via `openshell policy set`
    (OpenShell validates the change and hot-reloads network_policies)."""
    import tempfile
    from . import openshell as osh

    def apply(policy: dict, explanations: dict) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(render_yaml(policy, explanations))
        osh.run(osh.policy_set(name, f.name))
    return apply


def _follow_logs(session, name: str) -> None:
    import threading
    from . import openshell as osh
    from .events import parse_line

    def pump():
        for line in osh.stream(osh.logs(name, since="1m")):
            ev = parse_line(line)
            if ev:
                session.ingest(ev)
    threading.Thread(target=pump, daemon=True).start()


def cmd_run(a) -> int:
    from . import openshell as osh
    from .secrets import stage, write_profiles
    res, draft = _draft(a.repo, use_llm=not a.no_llm)
    out = Path(a.output or ".leash")
    out.mkdir(parents=True, exist_ok=True)
    policy_file = out / "policy.yaml"
    policy_file.write_text(render_yaml(draft.to_openshell(), draft.explanations()))
    plan = stage(a.repo, out / "workspace", res)
    write_profiles(plan, out / "profiles")

    print(f"Leash prepared {out}/")
    print(f"  policy.yaml   {len(draft.rules)} least-privilege rules (each explained in comments)")
    print(f"  workspace/    repo copy; {len(plan.rewritten)} secret file(s) rewritten to placeholders, "
          f"{len(plan.omitted)} left out")
    print(f"  profiles/     {len(plan.profiles)} provider profile(s), one per credential")
    if plan.unbound_keys:
        print(f"  unbound keys  {', '.join(plan.unbound_keys)} (no known host; placeholders never resolve)")
    for n in draft.notes:
        print(f"  note: {n}")

    name = a.name
    steps = [c.split() for c in plan.commands(str(out / "profiles"))]
    steps.append(osh.create_sandbox(name, a.image, str(policy_file), list(plan.providers)))
    steps.append(osh.upload(name, str(out / "workspace")))
    steps.append(osh.exec_agent(name, a.cmd or ["opencode"], workdir=None))
    print("\nCommands (load your real .env into this shell first so providers can read it):\n")
    for argv in steps:
        print("  " + osh.show(argv))
    print(f"\nWatch and approve:  leash dashboard {a.repo} --sandbox {name}")
    if a.execute:
        if not osh.available():
            print("openshell CLI not found; cannot --execute.", file=sys.stderr)
            return 2
        for argv in steps:
            osh.run(argv)
    return 0


def cmd_doctor(a) -> int:
    import shutil
    ok = shutil.which("openshell")
    print(f"openshell CLI:      {'found at '+ok if ok else 'NOT found (Leash still drafts policies & runs the benchmark)'}")
    prover = shutil.which("openshell-prover")
    print(f"openshell-prover:   {'found at '+prover if prover else 'not found (Leash uses its built-in boundary check)'}")
    llm = Nemotron()
    if llm.available:
        try:
            print(f"Nebius Token Factory: reachable; model = {llm.model}")
        except LLMError as e:
            print(f"Nebius Token Factory: key set but error: {e}")
    else:
        print("Nebius Token Factory: NEBIUS_API_KEY not set (LLM features fall back to heuristics)")
    tav = Tavily()
    print(f"Tavily:             {'TAVILY_API_KEY set' if tav.available else 'not set (reputation lookups disabled)'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="leash", description="Least-privilege autopilot for coding agents.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Scan a repo and print a drafted policy.")
    s.add_argument("repo"); s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("policy", help="Draft + tighten (Nemotron) a policy.")
    s.add_argument("repo"); s.add_argument("-o", "--output"); s.add_argument("--no-llm", action="store_true")
    s.set_defaults(fn=cmd_policy)

    s = sub.add_parser("triage", help="Triage blocked events from a log or the demo.")
    s.add_argument("--log"); s.add_argument("--json"); s.add_argument("--secret", action="append")
    s.add_argument("--expect", action="append"); s.set_defaults(fn=cmd_triage)

    s = sub.add_parser("bench", help="Run the attack/clean benchmark.")
    s.add_argument("--json"); s.set_defaults(fn=cmd_bench)

    s = sub.add_parser("dashboard", help="Launch the approval dashboard.")
    s.add_argument("repo", nargs="?"); s.add_argument("--demo", action="store_true")
    s.add_argument("--log"); s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787); s.add_argument("--no-llm", action="store_true")
    s.add_argument("--sandbox", help="stream `openshell logs` from this sandbox into the dashboard")
    s.set_defaults(fn=cmd_dashboard)

    s = sub.add_parser("run", help="Stage the repo, write policy + providers, run the agent in OpenShell.")
    s.add_argument("repo"); s.add_argument("-o", "--output"); s.add_argument("--name", default="leash-agent")
    s.add_argument("--execute", action="store_true", help="run the commands instead of printing them")
    s.add_argument("--image", default="ghcr.io/anomalyco/opencode:latest")
    s.add_argument("--provider", action="append"); s.add_argument("--no-llm", action="store_true")
    s.set_defaults(fn=cmd_run, cmd=[])

    s = sub.add_parser("doctor", help="Check the environment.")
    s.set_defaults(fn=cmd_doctor)
    return p


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    trailing: list[str] = []
    if "--" in argv:
        i = argv.index("--")
        argv, trailing = argv[:i], argv[i + 1:]
    args = build_parser().parse_args(argv)
    if trailing:
        args.cmd = trailing
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())

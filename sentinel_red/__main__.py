"""Runner: execute every attack against the sim and grade with the policy.

``python -m sentinel_red`` prints a JSON report, one entry per attack::

    [
      {
        "attack": "prompt_injection",
        "succeeded": true,
        "detected_by_policy": true,
        "verdict": "FLAG",
        "reasons": ["injection_marker[...] in web_fetch output"]
      },
      ...
    ]

The simulator is undefended, so every attack lands (``succeeded`` is true in
the offline sim). The point of the harness is that the *policy* catches the
ones that matter: DENY for banned commands and exfil, FLAG for injection and
poisoning.
"""
from __future__ import annotations

import json
import sys

from .attacks import Attack, build_attacks
from .policy import judge
from .sim import AgentSim


def run_attack(attack: Attack) -> dict:
    """Run one attack against a fresh sim, grade its log, return a report row."""
    agent = AgentSim()
    succeeded = attack.succeeds(agent)
    verdict = judge(agent.log)
    return {
        "attack": attack.name,
        "succeeded": succeeded,
        "detected_by_policy": verdict.verdict != "ALLOW",
        "verdict": verdict.verdict,
        "reasons": verdict.reasons,
    }


def run_all() -> list[dict]:
    """Run the full attack suite and return the report rows."""
    return [run_attack(a) for a in build_attacks()]


def main() -> int:
    report = run_all()
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    # Exit non-zero if any attack succeeded *and* was not caught by policy.
    # (In a hardened deployment you would alarm on that combination.)
    undefended = [
        r["attack"] for r in report
        if r["succeeded"] and not r["detected_by_policy"]
    ]
    return 1 if undefended else 0


if __name__ == "__main__":
    raise SystemExit(main())

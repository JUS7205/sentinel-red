"""sentinel-red: an autonomous red-team harness for AI agents.

Offline, deterministic, no live LLM. It attacks a simulated agent with
concrete primitives and grades every action against a static Sentinel-style
policy (ALLOW / DENY / FLAG).

Shared spine with the sibling `sentinel` project (runtime defense of
autonomous systems) — this repo is the *offensive* facet.
"""

__version__ = "0.1.0"

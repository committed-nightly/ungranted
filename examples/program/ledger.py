#!/usr/bin/env python3
"""A fixture, not a tool. The shape of a CLI whose workflow grants it scopes.

Every API call here is reached through one wrapper, which is the arrangement
that makes a `permissions:` block impossible to check from the workflow file:
the `subprocess.run` below names no endpoint, and the endpoints at the call
sites are f-strings over values that only exist at run time.

Copied in outline from committed-nightly/logbook's `ledger.py`, which is the
program this feature was built to read.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys


def gh_json(args: list[str], gh: str = "gh"):
    """Run gh and parse its JSON. The argv is assembled here; paths are not."""
    exe = shutil.which(gh)
    if exe is None:
        sys.exit(f"{gh} is not on PATH")
    proc = subprocess.run([exe, *args], capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit(proc.stderr.strip())
    return json.loads(proc.stdout or "null")


def repos(org: str) -> list[dict]:
    return gh_json(["repo", "list", org, "--limit", "200", "--json", "name"])


def workflow_states(org: str, repo: str) -> dict:
    """The call that needs `actions: read`, and the reason this fixture exists."""
    return gh_json(["api", f"repos/{org}/{repo}/actions/workflows"])


def newest_pr(org: str, repo: str):
    path = f"repos/{org}/{repo}/pulls"
    return gh_json(["api", "-X", "GET", path, "-f", "state=all", "-f", "per_page=1"])


def workflow_text(org: str, repo: str, path: str, ref: str) -> dict:
    return gh_json(["api", f"repos/{org}/{repo}/contents/{path}?ref={ref}"])


def main() -> int:
    org = sys.argv[1] if len(sys.argv) > 1 else "committed-nightly"
    for repo in repos(org):
        name = repo["name"]
        print(name, workflow_states(org, name), newest_pr(org, name))
        print(workflow_text(org, name, ".github/workflows/ci.yml", "main"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

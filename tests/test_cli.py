from __future__ import annotations

import json
import os
import textwrap

from ungranted.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main

TOKEN = "${{ secrets.GITHUB_TOKEN }}"

COVERED = f"""
'on': push
permissions:
  contents: read
jobs:
  j:
    steps:
      - env: {{ GH_TOKEN: '{TOKEN}' }}
        run: gh api repos/o/r/contents/README.md
"""

SHORT = f"""
'on': push
permissions:
  contents: read
jobs:
  j:
    steps:
      - env: {{ GH_TOKEN: '{TOKEN}' }}
        run: gh api repos/o/r/actions/runs
"""

UNREADABLE = f"""
'on': push
permissions:
  contents: read
jobs:
  j:
    steps:
      - env: {{ GH_TOKEN: '{TOKEN}' }}
        run: gh api "$ENDPOINT"
"""

OPAQUE = f"""
'on': push
permissions:
  contents: read
jobs:
  j:
    steps:
      - env: {{ GH_TOKEN: '{TOKEN}' }}
        run: ./my-tool
"""


def write(tmp_path, text, name="ci.yml"):
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(textwrap.dedent(text))
    return path


def test_a_covered_workflow_exits_zero(tmp_path, capsys):
    write(tmp_path, COVERED)
    assert main([str(tmp_path)]) == EXIT_OK
    assert "covered" in capsys.readouterr().out


def test_a_missing_scope_exits_one(tmp_path, capsys):
    write(tmp_path, SHORT)
    assert main([str(tmp_path)]) == EXIT_FINDINGS
    assert "actions: read" in capsys.readouterr().out


def test_an_unreadable_path_exits_two_and_still_prints(tmp_path, capsys):
    # 2 is "nobody looked", and it is deliberately not 1 and very deliberately
    # not 0.
    write(tmp_path, UNREADABLE)
    assert main([str(tmp_path)]) == EXIT_ERROR
    assert "unreadable" in capsys.readouterr().out


def test_a_path_with_no_workflows_exits_two(tmp_path, capsys):
    assert main([str(tmp_path)]) == EXIT_ERROR
    assert "no workflow files" in capsys.readouterr().err


def test_a_file_that_is_not_yaml_exits_two(tmp_path, capsys):
    write(tmp_path, "0x_\n")
    assert main([str(tmp_path)]) == EXIT_ERROR
    assert "not valid YAML" in capsys.readouterr().err


def test_a_single_file_can_be_checked_directly(tmp_path, capsys):
    path = write(tmp_path, SHORT)
    assert main([str(path)]) == EXIT_FINDINGS


def test_a_workflows_directory_can_be_checked_directly(tmp_path):
    write(tmp_path, SHORT)
    directory = os.path.join(str(tmp_path), ".github", "workflows")
    assert main([directory]) == EXIT_FINDINGS


def test_quiet_is_one_line_per_finding(tmp_path, capsys):
    write(tmp_path, SHORT)
    main([str(tmp_path), "-q"])
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    # The missing scope and, separately, contents: read being unused here.
    assert len(lines) == 2
    assert lines[0] == (
        ".github/workflows/ci.yml:j: ungranted: gh api repos/o/r/actions/runs "
        "needs actions: read; this job has actions: none"
    )
    assert all(ln.startswith(".github/workflows/ci.yml:j: ") for ln in lines)


def test_no_unused_drops_the_over_granting_half(tmp_path, capsys):
    write(
        tmp_path,
        f"""
        'on': push
        jobs:
          j:
            permissions:
              issues: write
            steps:
              - env: {{ GH_TOKEN: '{TOKEN}' }}
                run: echo nothing
        """,
    )
    assert main([str(tmp_path)]) == EXIT_FINDINGS
    capsys.readouterr()
    assert main([str(tmp_path), "--no-unused"]) == EXIT_OK


def test_strict_fails_on_a_job_it_could_not_read(tmp_path, capsys):
    write(tmp_path, OPAQUE)
    assert main([str(tmp_path)]) == EXIT_OK
    capsys.readouterr()
    assert main([str(tmp_path), "--strict"]) == EXIT_FINDINGS
    assert "cannot read" in capsys.readouterr().out


def test_json_is_parseable_and_says_whether_the_job_was_fully_read(tmp_path, capsys):
    write(tmp_path, OPAQUE)
    main([str(tmp_path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    job = payload["jobs"][0]
    assert job["job"] == "j"
    assert job["grant"]["scopes"] == {"contents": "read"}
    assert job["complete"] is False
    assert job["skipped"]


def test_json_carries_the_needs_it_worked_out(tmp_path, capsys):
    write(tmp_path, SHORT)
    main([str(tmp_path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    needs = payload["jobs"][0]["needs"]
    assert {"scope": "actions", "level": "read"} in needs
    assert payload["jobs"][0]["findings"][0]["kind"] == "missing"

from __future__ import annotations

import textwrap

import pytest

from ungranted.core import (
    MISSING,
    ONLY_VIA_ALL,
    OVERLEVEL,
    UNGRANTABLE_SCOPE,
    UNKNOWN_PATH,
    UNUSED,
    check,
)
from ungranted.grants import FROM_DEFAULT, FROM_JOB, FROM_WORKFLOW
from ungranted.scopes import Need
from ungranted.workflows import WorkflowError, parse

TOKEN = "${{ secrets.GITHUB_TOKEN }}"


def run(body: str):
    workflow = parse(textwrap.dedent(body), "ci.yml")
    return check([workflow])


def kinds(report) -> list[str]:
    return [f.kind for f in report.findings]


def scopes(report, kind) -> list[str]:
    return sorted(f.scope for f in report.findings if f.kind == kind)


# --------------------------------------------------------------------------
# The override rule, measured on a real runner: a job-level block replaces the
# top-level one rather than adding to it.
# --------------------------------------------------------------------------


def test_a_job_block_replaces_the_workflow_block():
    report = run(
        f"""
        name: ci
        'on': push
        permissions:
          contents: read
          actions: read
        jobs:
          narrowed:
            permissions:
              contents: read
            steps:
              - name: list
                env: {{ GH_TOKEN: '{TOKEN}' }}
                run: gh api repos/o/r/actions/runs
        """
    )
    job = report.jobs[0]
    assert job.grant.source == FROM_JOB
    assert job.grant.level("actions") == "none"
    missing = [f for f in job.findings if f.kind == MISSING]
    assert len(missing) == 1
    assert missing[0].scope == "actions"


def test_without_a_job_block_the_workflow_block_applies():
    report = run(
        f"""
        'on': push
        permissions:
          contents: read
          actions: read
        jobs:
          inherits:
            steps:
              - env: {{ GH_TOKEN: '{TOKEN}' }}
                run: gh api repos/o/r/actions/runs
        """
    )
    assert report.jobs[0].grant.source == FROM_WORKFLOW
    # The actions call is covered. contents: read is separately unused here,
    # which is a true statement about this job and not what this test is about.
    assert scopes(report, MISSING) == []


# --------------------------------------------------------------------------
# Absent is not the same as empty.
# --------------------------------------------------------------------------


def test_no_block_anywhere_is_never_a_finding():
    report = run(
        f"""
        'on': push
        jobs:
          whatever:
            steps:
              - env: {{ GH_TOKEN: '{TOKEN}' }}
                run: gh api -X DELETE repos/o/r/git/refs/heads/x
        """
    )
    assert report.jobs[0].grant.source == FROM_DEFAULT
    assert report.findings == []
    assert report.ok


def test_an_empty_block_grants_metadata_and_nothing_else():
    report = run(
        f"""
        'on': push
        jobs:
          locked:
            permissions: {{}}
            steps:
              - env: {{ GH_TOKEN: '{TOKEN}' }}
                run: gh api repos/o/r/contents/README.md
        """
    )
    assert kinds(report) == [MISSING]
    assert report.findings[0].scope == "contents"


def test_a_metadata_only_call_is_covered_by_an_empty_block():
    # permissions: {} resolves to exactly `Metadata: read`, so this works.
    report = run(
        f"""
        'on': push
        jobs:
          locked:
            permissions: {{}}
            steps:
              - env: {{ GH_TOKEN: '{TOKEN}' }}
                run: gh api repos/o/r/topics
        """
    )
    assert report.findings == []


# --------------------------------------------------------------------------
# Whose token is it
# --------------------------------------------------------------------------


def test_a_different_secret_is_not_this_block_s_problem():
    report = run(
        """
        'on': push
        jobs:
          mirror:
            permissions:
              contents: read
            steps:
              - env: { GH_TOKEN: '${{ secrets.RELEASE_PAT }}' }
                run: gh api -X POST repos/o/r/issues -f title=x
        """
    )
    assert [f.kind for f in report.findings if f.kind == MISSING] == []
    assert any("different secret" in s.reason for s in report.skipped)


def test_a_step_with_no_token_is_a_different_failure():
    report = run(
        """
        'on': push
        jobs:
          forgot:
            permissions:
              contents: read
            steps:
              - run: gh api repos/o/r/pulls
        """
    )
    assert [f.kind for f in report.findings if f.kind == MISSING] == []
    assert any("GH_TOKEN" in s.reason for s in report.skipped)


def test_a_token_set_at_workflow_level_reaches_the_step():
    report = run(
        f"""
        'on': push
        env:
          GH_TOKEN: '{TOKEN}'
        permissions:
          contents: read
        jobs:
          j:
            steps:
              - run: gh api repos/o/r/pulls
        """
    )
    assert scopes(report, MISSING) == ["pull-requests"]


# --------------------------------------------------------------------------
# Over-granting, and when we are allowed to claim it
# --------------------------------------------------------------------------


def test_a_scope_granted_for_nothing_is_reported():
    report = run(
        f"""
        'on': push
        jobs:
          j:
            permissions:
              contents: read
              issues: write
            steps:
              - env: {{ GH_TOKEN: '{TOKEN}' }}
                run: gh api repos/o/r/contents/README.md
        """
    )
    assert scopes(report, UNUSED) == ["issues"]


def test_write_granted_where_only_reads_happen():
    report = run(
        f"""
        'on': push
        jobs:
          j:
            permissions:
              contents: write
            steps:
              - env: {{ GH_TOKEN: '{TOKEN}' }}
                run: gh api repos/o/r/contents/README.md
        """
    )
    assert scopes(report, OVERLEVEL) == ["contents"]


def test_an_opaque_command_holding_the_token_stops_us_claiming_unused():
    # The case that made this rule: three of the four real workflows in this
    # org that have a block run a CLI of their own with GH_TOKEN set, and the
    # API calls are inside the CLI.
    report = run(
        f"""
        'on': push
        jobs:
          j:
            permissions:
              actions: read
            steps:
              - env: {{ GH_TOKEN: '{TOKEN}' }}
                run: ./my-tool --check
        """
    )
    assert UNUSED not in kinds(report)
    assert report.jobs[0].blind
    assert any("may call the API itself" in s.reason for s in report.skipped)


def test_an_inert_command_does_not_blind_the_job():
    report = run(
        f"""
        'on': push
        jobs:
          j:
            permissions:
              actions: read
            steps:
              - env: {{ GH_TOKEN: '{TOKEN}' }}
                run: |
                  echo starting
                  gh api repos/o/r/contents/README.md
        """
    )
    assert not report.jobs[0].blind
    assert scopes(report, UNUSED) == ["actions"]


def test_an_opaque_command_without_the_token_does_not_blind_the_job():
    report = run(
        """
        'on': push
        jobs:
          j:
            permissions:
              actions: read
            steps:
              - run: ./my-tool --check
        """
    )
    assert not report.jobs[0].blind
    assert scopes(report, UNUSED) == ["actions"]


def test_scopes_we_cannot_see_the_use_of_are_never_called_unused():
    # A docker push, an OIDC call in a library, an attestation: none of those
    # are visible here, so claiming the grant is dead would be a guess.
    report = run(
        """
        'on': push
        jobs:
          j:
            permissions:
              packages: write
              id-token: write
              attestations: write
            steps:
              - run: echo nothing at all
        """
    )
    assert UNUSED not in kinds(report)


def test_an_unknown_action_stops_us_claiming_unused():
    report = run(
        """
        'on': push
        jobs:
          j:
            permissions:
              pull-requests: write
            steps:
              - uses: some-vendor/mystery-action@v1
        """
    )
    assert UNUSED not in kinds(report)
    assert report.jobs[0].blind


def test_read_all_is_not_reported_as_over_granting():
    # read-all is a deliberate "I do not want to think about this", and
    # listing fourteen unused scopes back is not a useful answer.
    report = run(
        """
        'on': push
        jobs:
          j:
            permissions: read-all
            steps:
              - run: echo hi
        """
    )
    assert UNUSED not in kinds(report)


# --------------------------------------------------------------------------
# Scopes no block can grant
# --------------------------------------------------------------------------


def test_a_scope_no_block_can_grant_says_so():
    report = run(
        f"""
        'on': push
        jobs:
          j:
            permissions:
              contents: read
            steps:
              - env: {{ GH_TOKEN: '{TOKEN}' }}
                run: gh api repos/o/r/hooks
        """
    )
    assert kinds(report).count(UNGRANTABLE_SCOPE) == 1
    assert "different token" in report.findings[0].message


def test_read_all_covers_what_no_key_covers():
    missing = run(
        f"""
        'on': push
        jobs:
          j:
            permissions:
              contents: read
            steps:
              - env: {{ GH_TOKEN: '{TOKEN}' }}
                run: gh api repos/o/r/dependabot/alerts
        """
    )
    assert ONLY_VIA_ALL in kinds(missing)

    covered = run(
        f"""
        'on': push
        jobs:
          j:
            permissions: read-all
            steps:
              - env: {{ GH_TOKEN: '{TOKEN}' }}
                run: gh api repos/o/r/dependabot/alerts
        """
    )
    assert ONLY_VIA_ALL not in kinds(covered)


# --------------------------------------------------------------------------
# Not guessing
# --------------------------------------------------------------------------


def test_an_unreadable_path_is_a_finding_not_a_silence():
    report = run(
        f"""
        'on': push
        jobs:
          j:
            permissions:
              contents: read
            steps:
              - env: {{ GH_TOKEN: '{TOKEN}' }}
                run: gh api "$ENDPOINT"
        """
    )
    assert kinds(report) == [UNKNOWN_PATH]
    assert report.blind_findings


# --------------------------------------------------------------------------
# Actions
# --------------------------------------------------------------------------


def test_checkout_needs_contents_and_a_job_block_can_lose_it():
    report = run(
        """
        'on': push
        permissions:
          contents: read
        jobs:
          j:
            permissions:
              issues: write
            steps:
              - uses: actions/checkout@v4
        """
    )
    assert scopes(report, MISSING) == ["contents"]


def test_github_script_calls_are_read_out_of_the_script():
    report = run(
        """
        'on': push
        jobs:
          j:
            permissions:
              contents: read
            steps:
              - uses: actions/github-script@v7
                with:
                  script: |
                    await github.rest.issues.createComment({ body: 'x' })
        """
    )
    assert scopes(report, MISSING) == ["issues"]
    assert any(n.scope == "issues" and n.level == "write" for n in report.jobs[0].needs)


def test_a_github_script_request_call_is_not_guessed_at():
    report = run(
        """
        'on': push
        jobs:
          j:
            permissions:
              contents: read
            steps:
              - uses: actions/github-script@v7
                with:
                  script: |
                    await github.request('GET /repos/{owner}/{repo}/pulls')
        """
    )
    assert report.jobs[0].blind


def test_a_reusable_workflow_job_is_not_called_covered():
    report = run(
        """
        'on': push
        jobs:
          j:
            permissions:
              contents: read
            uses: ./.github/workflows/other.yml
        """
    )
    assert report.jobs[0].blind
    assert any("reusable workflow" in s.reason for s in report.jobs[0].skipped)


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def test_the_on_key_is_not_a_job():
    workflow = parse("'on': push\njobs:\n  only:\n    steps: []\n", "ci.yml")
    assert [j.name for j in workflow.jobs] == ["only"]


def test_yaml_that_raises_something_other_than_yamlerror():
    # yaml.safe_load('0x_') raises ValueError from the int constructor, and
    # `except yaml.YAMLError` walks straight past it.
    with pytest.raises(WorkflowError, match="not valid YAML"):
        parse("0x_", "ci.yml")


def test_a_bad_scope_value_is_reported_and_does_not_crash():
    report = run(
        """
        'on': push
        jobs:
          j:
            permissions:
              contents: raed
            steps: []
        """
    )
    assert "bad-block" in kinds(report)


def test_a_typo_in_a_scope_name_is_not_read_as_a_grant():
    report = run(
        """
        'on': push
        jobs:
          j:
            permissions:
              pull-request: write
            steps: []
        """
    )
    assert "bad-block" in kinds(report)


# --------------------------------------------------------------------------
# Reading the program a step runs. The job shape here is logbook's `org`
# workflow, which is the case the whole feature exists for: a step holding
# GITHUB_TOKEN runs a CLI in the same repository, and every API call the
# grant exists for is inside that CLI.
# --------------------------------------------------------------------------


def repo_with(tmp_path, workflow: str, program: str, name: str = "ledger.py"):
    (tmp_path / name).write_text(textwrap.dedent(program))
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True)
    path = directory / "org.yaml"
    path.write_text(textwrap.dedent(workflow))
    return check([parse(path.read_text(), str(path))])


LEDGER = """
    import shutil, subprocess

    def gh_json(args, gh="gh"):
        exe = shutil.which(gh)
        return subprocess.run([exe, *args], capture_output=True)

    def workflows(org, name):
        return gh_json(["api", f"repos/{org}/{name}/actions/workflows"])
"""

ORG_WORKFLOW = """
    name: org
    'on': {schedule: [{cron: '17 4 * * *'}]}
    permissions:
      contents: read
    jobs:
      org:
        runs-on: ubuntu-latest
        steps:
          - env: {GH_TOKEN: "%s"}
            run: ./ledger.py orphans
""" % TOKEN


def test_a_scope_a_program_needs_and_the_block_lacks_is_reported(tmp_path):
    """logbook#41, which happened: org.yaml was short of actions: read for a
    call inside ledger.py, and the 403 arrived on a scheduled run. Nothing
    static could see it, because the path is not in the workflow file."""
    report = repo_with(tmp_path, ORG_WORKFLOW, LEDGER)
    missing = [f for f in report.findings if f.kind == MISSING]
    assert [f.scope for f in missing] == ["actions"]
    assert "ledger.py: gh api repos/{}/{}/actions/workflows" in missing[0].message


def test_reading_the_program_stops_the_job_being_blind(tmp_path):
    """Before this, the step was opaque: the job could not be checked and no
    grant in it could be called unused. Now `contents: read` is granted,
    nothing in the program reads contents, and that is sayable."""
    report = repo_with(tmp_path, ORG_WORKFLOW, LEDGER)
    job = report.jobs[0]
    assert not job.blind
    assert [f.scope for f in report.findings if f.kind == UNUSED] == ["contents"]


def test_a_program_that_covers_its_grant_is_clean(tmp_path):
    workflow = ORG_WORKFLOW.replace("contents: read", "actions: read")
    report = repo_with(tmp_path, workflow, LEDGER)
    assert report.findings == []
    assert not report.jobs[0].blind
    assert report.jobs[0].needs == [Need("actions", "read")]


def test_a_command_that_resolves_to_nothing_leaves_the_job_blind(tmp_path):
    """The behaviour this replaced, kept for everything that is not Python in
    this repository -- `claude`, a compiled binary, a shell script."""
    workflow = ORG_WORKFLOW.replace("./ledger.py orphans", "claude -p 'do the shift'")
    report = repo_with(tmp_path, workflow, LEDGER)
    job = report.jobs[0]
    assert job.blind
    assert [s.shown for s in job.skipped] == ["claude"]
    # And so no unused finding, because nobody looked.
    assert [f.kind for f in report.findings] == []


def test_a_gap_inside_the_program_still_blinds_the_job(tmp_path):
    """Partly read is not read. If the program has a call site this cannot
    resolve, the job keeps its benefit of the doubt on unused scopes."""
    program = LEDGER + """
    def opaque(argv):
        return gh_json(argv)
"""
    report = repo_with(tmp_path, ORG_WORKFLOW, program)
    job = report.jobs[0]
    assert job.blind
    assert any("not a list written here" in s.shown for s in job.skipped)
    assert [f.kind for f in report.findings if f.kind == UNUSED] == []

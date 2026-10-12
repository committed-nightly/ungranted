"""Command line entry point.

Exit codes, because the main use for this is a CI gate:

    0  every job's block covers the calls its steps make
    1  at least one job's block does not, or grants a scope for nothing
    2  the check could not run, or could not finish

2 covers an unreadable workflow file, a path pointing at no workflows, and --
the case worth spelling out -- an API path the scope table does not recognise.
An unrecognised path is not "needs nothing". "Needs nothing" is wrong in the
direction that makes a workflow look covered until the morning the scheduled
job stops, so it is an error here and the findings alongside it are still
printed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .core import (
    BAD_BLOCK,
    MISSING,
    ONLY_VIA_ALL,
    OVERLEVEL,
    UNGRANTABLE_SCOPE,
    UNKNOWN_PATH,
    UNUSED,
    Report,
    check,
)
from .grants import FROM_DEFAULT, FROM_JOB, FROM_WORKFLOW
from .workflows import Workflow, WorkflowError, find_workflows, load

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

# Printed in this order, worst first.
ORDER = [
    MISSING,
    UNGRANTABLE_SCOPE,
    ONLY_VIA_ALL,
    BAD_BLOCK,
    UNKNOWN_PATH,
    OVERLEVEL,
    UNUSED,
]

LABELS = {
    MISSING: "ungranted",
    UNGRANTABLE_SCOPE: "no key for it",
    ONLY_VIA_ALL: "only via read-all",
    BAD_BLOCK: "bad block",
    UNKNOWN_PATH: "unreadable",
    OVERLEVEL: "over-level",
    UNUSED: "unused",
}

_SOURCE_TEXT = {
    FROM_JOB: "job",
    FROM_WORKFLOW: "workflow",
    FROM_DEFAULT: "no block -- the repository default applies",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ungranted",
        description=(
            "Say which scopes a workflow's permissions: block never granted for "
            "the API calls its steps actually make, and which it grants for nothing."
        ),
        epilog=(
            "A job with no permissions: block is never a finding: the default is "
            "set on the repository, not in the file. An empty block is not the same "
            "thing and is checked like any other."
        ),
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="a repository, a .github/workflows directory, or one workflow file "
        "(default: the current directory)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="one line per finding, for grepping",
    )
    parser.add_argument("--json", action="store_true", help="the whole report as JSON")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="also fail when a job holds the workflow token and runs something "
        "this cannot read, so 'covered' always means 'checked'",
    )
    parser.add_argument(
        "--no-unused",
        action="store_true",
        help="report only scopes that are missing, not scopes granted for nothing",
    )
    return parser


def collect(path: str) -> list[str]:
    if os.path.isfile(path):
        return [path]
    found = find_workflows(path)
    if not found:
        raise WorkflowError(
            f"{path}: no workflow files here. Point this at a repository, at a "
            ".github/workflows directory, or at one file."
        )
    return found


def _relative(path: str, root: str) -> str:
    if os.path.isdir(root):
        try:
            return os.path.relpath(path, root)
        except ValueError:  # pragma: no cover - different drives on Windows
            return path
    return path


def blind_jobs(report: Report) -> list[tuple[str, str]]:
    """Jobs where something unreadable sat next to the workflow's own token."""
    return [(j.workflow, j.job) for j in report.jobs if j.blind]


def render(report: Report, root: str, show_unused: bool) -> list[str]:
    lines: list[str] = []
    by_workflow: dict[str, list] = {}
    for job in report.jobs:
        by_workflow.setdefault(job.workflow, []).append(job)

    for workflow, jobs in by_workflow.items():
        lines.append(_relative(workflow, root))
        for job in jobs:
            grant = job.grant
            if grant.source == FROM_DEFAULT:
                summary = _SOURCE_TEXT[FROM_DEFAULT]
            elif grant.catch_all:
                summary = f"{grant.shorthand} ({_SOURCE_TEXT[grant.source]})"
            else:
                named = grant.named()
                body = ", ".join(f"{s}: {lv}" for s, lv in sorted(named.items()))
                summary = f"{body or 'every scope none'} ({_SOURCE_TEXT[grant.source]})"
            lines.append(f"  {job.job}")
            lines.append(f"    grant  {summary}")

            shown = [
                f
                for f in job.findings
                if show_unused or f.kind not in (UNUSED, OVERLEVEL)
            ]
            shown.sort(key=lambda f: ORDER.index(f.kind) if f.kind in ORDER else 99)
            for finding in shown:
                label = LABELS.get(finding.kind, finding.kind)
                lines.append(f"    {label:<17}  {finding.message}")
                if finding.step:
                    lines.append(f"    {'':<17}  in step: {finding.step}")
            if not shown and grant.source != FROM_DEFAULT:
                if job.needs:
                    lines.append("    covered")
                else:
                    lines.append("    covered  (no API calls found in this job)")
            lines.append("")

    if report.skipped:
        lines.append("Not governed by a permissions: block, or not read:")
        for item in report.skipped:
            where = f"{_relative(item.workflow, root)}  {item.job}"
            lines.append(f"  {where}  {item.shown}")
            lines.append(f"      {item.reason}")
        lines.append("")

    real = report.real_findings
    blind = report.blind_findings
    jobs_with = len({(f.workflow, f.job) for f in real})
    defaulted = sum(1 for j in report.jobs if j.grant.source == FROM_DEFAULT)
    if not show_unused:
        real = [f for f in real if f.kind not in (UNUSED, OVERLEVEL)]
        jobs_with = len({(f.workflow, f.job) for f in real})

    bits = [
        f"{len(real)} finding{'' if len(real) == 1 else 's'} "
        f"in {jobs_with} of {report.checked_jobs} job"
        f"{'' if report.checked_jobs == 1 else 's'}"
    ]
    if blind:
        bits.append(
            f"{len(blind)} call{'' if len(blind) == 1 else 's'} the scope table "
            "does not cover"
        )
    if defaulted:
        bits.append(f"{defaulted} with no block, not checked")
    unreadable = blind_jobs(report)
    if unreadable:
        bits.append(
            f"{len(unreadable)} job{' runs' if len(unreadable) == 1 else 's run'} "
            "something this cannot read, so no grant there is called unused"
        )
    lines.append(". ".join(bits) + ".")
    return lines


def render_quiet(report: Report, root: str, show_unused: bool) -> list[str]:
    lines = []
    for finding in report.findings:
        if not show_unused and finding.kind in (UNUSED, OVERLEVEL):
            continue
        lines.append(
            f"{_relative(finding.workflow, root)}:{finding.job}: "
            f"{LABELS.get(finding.kind, finding.kind)}: {finding.message}"
        )
    return lines


def as_json(report: Report, root: str) -> str:
    payload = {
        "jobs": [
            {
                "workflow": _relative(job.workflow, root),
                "job": job.job,
                "grant": {
                    "source": job.grant.source,
                    "shorthand": job.grant.shorthand,
                    "scopes": job.grant.named(),
                    "declared": job.grant.declared,
                },
                "needs": [{"scope": n.scope, "level": n.level} for n in job.needs],
                "complete": not job.blind,
                "findings": [
                    {
                        "kind": f.kind,
                        "scope": f.scope,
                        "step": f.step,
                        "message": f.message,
                    }
                    for f in job.findings
                ],
                "skipped": [
                    {"step": s.step, "call": s.shown, "reason": s.reason}
                    for s in job.skipped
                ],
            }
            for job in report.jobs
        ]
    }
    return json.dumps(payload, indent=2)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    show_unused = not args.no_unused

    try:
        paths = collect(args.path)
    except WorkflowError as exc:
        print(f"ungranted: {exc}", file=sys.stderr)
        return EXIT_ERROR

    loaded: list[Workflow] = []
    failed = False
    for path in paths:
        try:
            loaded.append(load(path))
        except WorkflowError as exc:
            print(f"ungranted: {exc}", file=sys.stderr)
            failed = True

    if not loaded:
        return EXIT_ERROR

    report = check(loaded)

    if args.json:
        print(as_json(report, args.path))
    elif args.quiet:
        for line in render_quiet(report, args.path, show_unused):
            print(line)
    else:
        for line in render(report, args.path, show_unused):
            print(line)

    if failed or report.blind_findings:
        return EXIT_ERROR
    visible = [
        f
        for f in report.real_findings
        if show_unused or f.kind not in (UNUSED, OVERLEVEL)
    ]
    if visible:
        return EXIT_FINDINGS
    if args.strict and blind_jobs(report):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

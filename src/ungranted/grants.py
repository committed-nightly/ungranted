"""What a job's token is actually granted.

Measured on a real runner, which prints the answer in its own log under
`##[group]GITHUB_TOKEN Permissions`:

    permissions: {}                     Metadata: read
    permissions: {contents: read}       Contents: read, Metadata: read
    no permissions: key anywhere        Contents: read, Metadata: read, Packages: read
    permissions: read-all               nineteen scopes, including five with no key

Two consequences the rest of this package depends on.

**A job-level block replaces the top-level one.** It does not merge with it.
Measured: a workflow granting `contents: read` + `actions: read` at the top
level, with a job naming only `contents: read`, gives that job
`Contents: read, Metadata: read` -- the `actions` grant is gone. So "which
grant applies to this step" needs the job structure, and a grep over the file
gets it wrong in the direction that reports a covered workflow as covered when
it is not.

**Absent is not `{}`.** An absent block means the repository or organisation
default applies, which is not in the file and is not ours to guess, so it is
never a finding. An empty block means every scope is `none`, which is the
strictest thing you can write and is very much a finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .scopes import (
    GRANTED_ONLY_BY_ALL,
    METADATA,
    READ,
    SETTABLE,
    WRITE,
    Need,
)
from .workflows import ABSENT, Job, Workflow

# How a grant came to be, for the report.
FROM_JOB = "job"
FROM_WORKFLOW = "workflow"
FROM_DEFAULT = "default"

_LEVELS = {"none": 0, READ: 1, WRITE: 2}


class GrantError(ValueError):
    """A permissions: block this cannot be read as a grant."""


@dataclass
class Grant:
    """The effective permissions for one job."""

    source: str  # FROM_JOB | FROM_WORKFLOW | FROM_DEFAULT
    scopes: dict[str, str]  # scope -> none | read | write
    shorthand: str | None = None  # "read-all" or "write-all", if that is what was written

    @property
    def declared(self) -> bool:
        """Is there a block in the file at all?"""
        return self.source != FROM_DEFAULT

    @property
    def catch_all(self) -> bool:
        return self.shorthand is not None

    def level(self, scope: str) -> str:
        if scope == METADATA:
            return READ  # always granted, never settable
        if self.catch_all and scope in GRANTED_ONLY_BY_ALL:
            return READ if self.shorthand == "read-all" else WRITE
        return self.scopes.get(scope, "none")

    def covers(self, need: Need) -> bool:
        return _LEVELS[self.level(need.scope)] >= _LEVELS[need.level]

    def named(self) -> dict[str, str]:
        """Only the scopes actually granted something, for over-grant reporting."""
        return {s: lv for s, lv in self.scopes.items() if lv != "none"}


def _from_value(value: Any, source: str) -> Grant:
    if isinstance(value, str):
        text = value.strip()
        if text == "read-all":
            return Grant(source, {s: READ for s in SETTABLE}, shorthand="read-all")
        if text == "write-all":
            return Grant(source, {s: WRITE for s in SETTABLE}, shorthand="write-all")
        raise GrantError(
            f"permissions: {text!r} is not a grant; the only bare words are "
            "read-all and write-all"
        )
    if value is None:
        # `permissions:` with nothing after it. YAML gives None, and GitHub
        # reads it as the empty block, i.e. every scope none.
        return Grant(source, {})
    if isinstance(value, dict):
        scopes: dict[str, str] = {}
        for key, level in value.items():
            name = str(key)
            text = str(level).strip() if level is not None else "none"
            if text not in _LEVELS:
                raise GrantError(
                    f"permissions: {name}: {text!r} is not one of read, write, none"
                )
            scopes[name] = text
        return Grant(source, scopes)
    raise GrantError(f"permissions: is a {type(value).__name__}, not a block")


def effective(workflow: Workflow, job: Job) -> Grant:
    """The grant that applies to this job's steps.

    Job level wins outright. This is the whole of the override rule and the
    reason a grep cannot answer the question.
    """
    if job.permissions is not ABSENT:
        return _from_value(job.permissions, FROM_JOB)
    if workflow.permissions is not ABSENT:
        return _from_value(workflow.permissions, FROM_WORKFLOW)
    return Grant(FROM_DEFAULT, {})


def unknown_keys(grant: Grant) -> list[str]:
    """Scope names in the block that GitHub does not accept.

    actionlint already reports these, and reports them better. Kept so that a
    typo does not quietly read as "this scope is granted none".
    """
    return sorted(k for k in grant.scopes if k not in SETTABLE)

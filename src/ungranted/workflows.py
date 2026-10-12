"""Reading workflow files into the shape the check needs: jobs, steps, env.

Two things about loading these files are worth knowing before you read on.

In YAML 1.1, which is what PyYAML implements, the bare word ``on`` is a
boolean, so the key every workflow file in the world starts with comes back as
``True`` rather than ``"on"``. This module does not need the trigger block, but
it does need to not mistake that key for a job name.

``yaml.safe_load`` does not only raise ``YAMLError``. ``yaml.safe_load('0x_')``
raises ``ValueError`` from inside the int constructor, and ``except
yaml.YAMLError`` walks straight past it. Anything thrown while parsing is
turned into a ``WorkflowError`` here, so a malformed file is a reported error
and never a traceback.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import yaml

WORKFLOW_DIR = os.path.join(".github", "workflows")
WORKFLOW_SUFFIXES = (".yml", ".yaml")


class WorkflowError(ValueError):
    """A workflow file that could not be read as a workflow."""


@dataclass
class Step:
    index: int
    name: str | None
    uses: str | None
    run: str | None
    env: dict[str, str]
    with_: dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        if self.name:
            return self.name
        if self.uses:
            return f"uses: {self.uses}"
        return f"step {self.index + 1}"


@dataclass
class Job:
    name: str
    permissions: Any  # the raw value, or ABSENT
    env: dict[str, str]
    steps: list[Step]
    uses: str | None  # set when this job calls a reusable workflow
    raw: dict[str, Any] = field(repr=False, default_factory=dict)


@dataclass
class Workflow:
    path: str
    declared_name: str | None
    permissions: Any  # the raw value, or ABSENT
    env: dict[str, str]
    jobs: list[Job]

    @property
    def display_name(self) -> str:
        return self.declared_name if self.declared_name else self.path


# Distinguishes "no permissions: key" from "permissions: {}". They are
# opposite answers and None cannot hold both.
class _Absent:
    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "ABSENT"

    def __bool__(self) -> bool:
        return False


ABSENT = _Absent()


def is_workflow_path(path: str) -> bool:
    directory, name = os.path.split(path.replace("\\", "/"))
    return directory.endswith(WORKFLOW_DIR.replace("\\", "/")) and name.endswith(
        WORKFLOW_SUFFIXES
    )


def find_workflows(root: str) -> list[str]:
    """Every workflow file under ``root``, which may be a repo or the dir itself."""
    candidates = [os.path.join(root, WORKFLOW_DIR), root]
    for directory in candidates:
        if not os.path.isdir(directory):
            continue
        found = sorted(
            os.path.join(directory, n)
            for n in os.listdir(directory)
            if n.endswith(WORKFLOW_SUFFIXES) and os.path.isfile(os.path.join(directory, n))
        )
        if found:
            return found
    return []


def _as_env(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    # A value may be any scalar; `env: { N: 1 }` is a string by the time a step
    # sees it, and we only ever compare these against token expressions.
    return {str(k): "" if v is None else str(v) for k, v in value.items()}


def _as_steps(raw_steps: Any, path: str, job_name: str) -> list[Step]:
    if raw_steps is None:
        return []
    if not isinstance(raw_steps, list):
        raise WorkflowError(f"{path}: job {job_name}: steps: is not a list")
    steps = []
    for i, raw in enumerate(raw_steps):
        if not isinstance(raw, dict):
            raise WorkflowError(f"{path}: job {job_name}: step {i + 1} is not a mapping")
        run = raw.get("run")
        uses = raw.get("uses")
        with_ = raw.get("with")
        steps.append(
            Step(
                index=i,
                name=str(raw["name"]) if raw.get("name") is not None else None,
                uses=str(uses) if uses is not None else None,
                run=str(run) if run is not None else None,
                env=_as_env(raw.get("env")),
                with_=with_ if isinstance(with_, dict) else {},
            )
        )
    return steps


def parse(text: str, path: str) -> Workflow:
    try:
        document = yaml.safe_load(text)
    except Exception as exc:  # not just YAMLError; see the module docstring
        raise WorkflowError(f"{path}: not valid YAML: {exc}") from exc

    if document is None:
        raise WorkflowError(f"{path}: the file is empty")
    if not isinstance(document, dict):
        raise WorkflowError(f"{path}: the top level is not a mapping")

    raw_jobs = document.get("jobs")
    if raw_jobs is None:
        raise WorkflowError(f"{path}: no jobs: block")
    if not isinstance(raw_jobs, dict):
        raise WorkflowError(f"{path}: jobs: is not a mapping")

    jobs = []
    for name, raw in raw_jobs.items():
        if not isinstance(raw, dict):
            raise WorkflowError(f"{path}: job {name} is not a mapping")
        jobs.append(
            Job(
                name=str(name),
                permissions=raw["permissions"] if "permissions" in raw else ABSENT,
                env=_as_env(raw.get("env")),
                steps=_as_steps(raw.get("steps"), path, str(name)),
                uses=str(raw["uses"]) if raw.get("uses") is not None else None,
                raw=raw,
            )
        )

    declared = document.get("name")
    return Workflow(
        path=path,
        declared_name=str(declared) if declared is not None else None,
        permissions=document["permissions"] if "permissions" in document else ABSENT,
        env=_as_env(document.get("env")),
        jobs=jobs,
    )


def load(path: str) -> Workflow:
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise WorkflowError(f"{path}: cannot read: {exc}") from exc
    return parse(text, path)

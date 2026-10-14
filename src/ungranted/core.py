"""The check: what each job's steps need against what its token is granted.

The asymmetry that shapes this module: a missing-scope finding comes from a
call we read, so it is sound even though the reader is incomplete. An
unused-scope finding is a claim about calls that are *not* there, so it is only
sound when we managed to read everything in the job. Anything unreadable --
an action not in the table, an API path not in the table, a reusable workflow,
a `gh` subcommand we do not know -- therefore switches over-grant reporting off
for that job and says so, rather than reporting a grant as unused on the
strength of a step nobody parsed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import actions as action_table
from . import calls as callscan
from . import programs
from .calls import TOKEN_NONE, TOKEN_OTHER, TOKEN_WORKFLOW, Call
from .grants import FROM_DEFAULT, Grant, GrantError, effective, unknown_keys
from .scopes import (
    AUDITABLE,
    GRANTED_ONLY_BY_ALL,
    METADATA,
    READ,
    UNGRANTABLE,
    WRITE,
    Need,
    UnknownPath,
    classify,
)
from .workflows import Job, Step, Workflow

# Finding kinds. MISSING and UNGRANTABLE are the point of the tool; the rest
# exist so that the point is trustworthy.
MISSING = "missing"
UNGRANTABLE_SCOPE = "ungrantable"
ONLY_VIA_ALL = "only-via-all"
UNUSED = "unused"
OVERLEVEL = "overlevel"
UNKNOWN_PATH = "unknown-path"
BAD_BLOCK = "bad-block"

# Kinds that mean the check could not see something, as opposed to seeing
# something wrong.
BLIND = (UNKNOWN_PATH,)

# Commands that cannot reach the API, however good a token is sitting in their
# environment. Everything else in a step that holds the workflow token is
# treated as able to call the API unseen -- `python3 scripts/thing.py` usually
# can, and three of the four real workflows this was first run against were
# exactly that. The list is shell builtins and the coreutils-shaped tools;
# anything that takes a script or a target (python, node, make, npm, bash,
# ./anything) is deliberately absent.
INERT = frozenset(
    {
        "[", "basename", "cat", "cd", "chmod", "cmp", "comm", "cp", "cut",
        "date", "diff", "dirname", "echo", "env", "exit", "export", "false",
        "find", "grep", "head", "jq", "ln", "ls", "mkdir", "mktemp", "mv",
        "od", "paste", "pip", "pip3", "printf", "pwd", "readlink", "rm",
        "rmdir", "sed", "seq", "set", "shellcheck", "shift", "sleep", "sort",
        "tail", "tee", "test", "touch", "tr", "true", "uname", "uniq",
        "unset", "wc", "which", "xxd", "yq",
    }
)


@dataclass
class Finding:
    kind: str
    workflow: str
    job: str
    message: str
    step: str | None = None
    scope: str | None = None

    @property
    def where(self) -> str:
        if self.step:
            return f"{self.workflow}: {self.job}: {self.step}"
        return f"{self.workflow}: {self.job}"


@dataclass
class Skipped:
    """A call or step that the block does not govern, or that we could not read."""

    workflow: str
    job: str
    step: str
    shown: str
    reason: str


@dataclass
class JobReport:
    workflow: str
    job: str
    grant: Grant
    needs: list[Need] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)
    blind: bool = False  # something in this job could not be read


@dataclass
class Report:
    jobs: list[JobReport] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        return [f for job in self.jobs for f in job.findings]

    @property
    def skipped(self) -> list[Skipped]:
        return [s for job in self.jobs for s in job.skipped]

    @property
    def blind_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.kind in BLIND]

    @property
    def real_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.kind not in BLIND]

    @property
    def checked_jobs(self) -> int:
        return len(self.jobs)

    @property
    def ok(self) -> bool:
        return not self.real_findings


def step_env(workflow: Workflow, job: Job, step: Step) -> dict[str, str]:
    """A step's environment, with the nearest declaration winning."""
    merged = dict(workflow.env)
    merged.update(job.env)
    merged.update(step.env)
    return merged


def _token_from_env(env: dict[str, str], names: tuple[str, ...]) -> tuple[str, str | None]:
    """(token kind, the variable it came from)."""
    for name in names:
        if name in env:
            return callscan.classify_token_value(env[name]), name
    return TOKEN_NONE, None


def _calls_in_run(
    script: str, env: dict[str, str]
) -> tuple[list[Call], list[callscan.Unreadable], list[list[str]]]:
    """(calls, unreadable constructs, commands that could call the API unseen).

    The opaque commands come back whole rather than as bare program names,
    because `programs.py` needs the arguments to find the file: `python3
    scripts/x.py` is only resolvable if `scripts/x.py` survives.
    """
    masked, mapping = callscan.mask_expressions(script)
    found: list[Call] = []
    unreadable: list[callscan.Unreadable] = []
    opaque: list[list[str]] = []

    gh_token, gh_var = _token_from_env(env, callscan.GH_TOKEN_VARS)

    for raw_tokens in callscan.commands(masked):
        tokens = callscan.command_words(raw_tokens)
        if not tokens:
            continue
        argv0 = tokens[0].rsplit("/", 1)[-1]
        accounted = False
        if argv0 == "gh":
            accounted = True
            if "api" in tokens[1:]:
                path, method, _ = callscan.parse_gh_api(tokens)
                shown = callscan.unmask(f"gh api {path or '?'}", mapping)
                if path is None:
                    unreadable.append(
                        callscan.Unreadable(shown, "gh api with no path argument")
                    )
                    continue
                found.append(
                    Call(
                        kind="gh-api",
                        shown=shown,
                        token=gh_token,
                        path=callscan.unmask(path, mapping) if "__GHEXPR" in path else path,
                        method=method,
                        note=None if gh_var else "nothing in scope sets GH_TOKEN",
                    )
                )
                continue
            needs, shown = callscan.parse_gh_command(tokens)
            if needs is None:
                unreadable.append(
                    callscan.Unreadable(
                        callscan.unmask(shown, mapping), "not a gh command this knows"
                    )
                )
                continue
            if needs:
                found.append(
                    Call(
                        kind="gh",
                        shown=callscan.unmask(shown, mapping),
                        token=gh_token,
                        needs=tuple(needs),
                        note=None if gh_var else "nothing in scope sets GH_TOKEN",
                    )
                )
            continue
        if argv0 == "curl":
            accounted = True
            url, method, headers = callscan.parse_curl(tokens)
            if url is None or not callscan._API_URL.search(url):
                continue
            auth = next(
                (h for h in headers if h.lower().startswith(("authorization", "auth"))), ""
            )
            token, _ = _curl_token(auth, env, mapping)
            accounted = True
            found.append(
                Call(
                    kind="curl",
                    shown=callscan.unmask(f"curl {url}", mapping),
                    token=token,
                    path=callscan.unmask(url, mapping) if "__GHEXPR" in url else url,
                    method=method,
                    note=None if auth else "no Authorization header",
                )
            )
            continue
        if not accounted and argv0 not in INERT:
            opaque.append([callscan.unmask(t, mapping) for t in tokens])

    for need in action_table.shell_extras(masked):
        registry = need.scope == "packages"
        found.append(
            Call(
                kind="registry" if registry else "oidc",
                shown="a ghcr.io push" if registry else "an OIDC token request",
                token=TOKEN_WORKFLOW,
                needs=(need,),
            )
        )
    return found, unreadable, opaque


def _curl_token(
    auth_header: str, env: dict[str, str], mapping: dict[str, str]
) -> tuple[str, str | None]:
    if not auth_header:
        return TOKEN_NONE, None
    restored = callscan.unmask(auth_header, mapping)
    direct = callscan.classify_token_value(restored)
    if direct != TOKEN_NONE:
        return direct, None
    # The header names a shell variable; resolve it through the environment.
    for name, value in env.items():
        if f"${name}" in auth_header or f"${{{name}}}" in auth_header:
            return callscan.classify_token_value(value), name
    return TOKEN_NONE, None


def _calls_in_uses(step: Step, env: dict[str, str]) -> tuple[list[Call], list[str]]:
    """(calls, reasons this step is unreadable) for a `uses:` step."""
    name = action_table.normalise_uses(step.uses or "")
    token_input = ""
    for key in ("github-token", "token", "repo-token"):
        if key in step.with_:
            token_input = str(step.with_[key])
            break
    if token_input:
        token = callscan.classify_token_value(token_input)
    elif "GITHUB_TOKEN" in env or "GH_TOKEN" in env:
        token, _ = _token_from_env(env, callscan.GH_TOKEN_VARS)
    else:
        # Every action in the table defaults to the workflow's own token.
        token = TOKEN_WORKFLOW

    if name == "actions/github-script":
        script = str(step.with_.get("script", ""))
        needs, unresolved = action_table.script_needs(script)
        calls = [
            Call(kind="github-script", shown="actions/github-script", token=token, needs=(need,))
            for need in needs
        ]
        return calls, [f"github-script: {u}" for u in unresolved]

    if name in action_table.ACTION_NEEDS:
        needs = action_table.ACTION_NEEDS[name]
        return (
            [
                Call(kind="action", shown=name, token=token, needs=(need,))
                for need in needs
            ],
            [],
        )

    if name.startswith("./") or name.startswith("docker://"):
        return [], [f"{step.uses}: a local or container action, which this does not read"]
    return [], [f"{step.uses}: not an action this knows the permissions for"]


def check_job(workflow: Workflow, job: Job) -> JobReport:
    try:
        grant = effective(workflow, job)
    except GrantError as exc:
        bad = Grant(FROM_DEFAULT, {})
        report = JobReport(workflow.path, job.name, bad, blind=True)
        report.findings.append(
            Finding(BAD_BLOCK, workflow.path, job.name, str(exc))
        )
        return report

    report = JobReport(workflow.path, job.name, grant)

    for key in unknown_keys(grant):
        report.findings.append(
            Finding(
                BAD_BLOCK,
                workflow.path,
                job.name,
                f"{key!r} is not a permission scope, so it grants nothing",
                scope=key,
            )
        )

    if job.uses:
        report.blind = True
        report.skipped.append(
            Skipped(
                workflow.path,
                job.name,
                "-",
                job.uses,
                "a reusable workflow: its steps are in another file",
            )
        )
        return report

    governed: list[tuple[Step, Call, Need]] = []

    for step in job.steps:
        env = step_env(workflow, job, step)
        found: list[Call] = []
        unreadable: list[str] = []

        if step.run:
            found, raw_unreadable, opaque = _calls_in_run(step.run, env)
            unreadable.extend(f"{u.shown}: {u.reason}" for u in raw_unreadable)
            # A step holding the workflow's own token can call the API through
            # anything it runs. If we could not account for every command in
            # it, this job's grants cannot be called unused -- one of those
            # commands may be the thing using them. This is what stops the
            # tool reporting `actions: read` as dead weight on a job whose
            # whole purpose is a CLI that reads the Actions API.
            token_kind, _ = _token_from_env(env, callscan.GH_TOKEN_VARS)
            if opaque and token_kind == TOKEN_WORKFLOW:
                # Before giving up on the step, try to read the programs it
                # runs. A command that resolves to Python source in this
                # repository stops being opaque: its API calls are folded in
                # here as if they had been written in the workflow file, which
                # is what they are.
                root = programs.repo_root(workflow.path)
                still_opaque: list[str] = []
                for command in opaque:
                    program = programs.read_program(command, root) if root else None
                    if program is None:
                        still_opaque.append(command[0].rsplit("/", 1)[-1])
                        continue
                    for pcall in program.calls:
                        found.append(
                            Call(
                                kind="program",
                                shown=f"{program.entry}: {pcall.shown}",
                                token=TOKEN_WORKFLOW,
                                needs=pcall.needs,
                            )
                        )
                    for gap in program.unreadable:
                        unreadable.append(f"{gap.where}: {gap.shown}: {gap.reason}")
                if still_opaque:
                    report.blind = True
                    report.skipped.append(
                        Skipped(
                            workflow.path,
                            job.name,
                            step.label,
                            ", ".join(sorted(set(still_opaque))),
                            "runs with the workflow token and may call the API itself, "
                            "so no grant in this job is reported as unused",
                        )
                    )
        if step.uses:
            uses_calls, uses_unreadable = _calls_in_uses(step, env)
            found.extend(uses_calls)
            unreadable.extend(uses_unreadable)

        # Deduplicated: a step that runs the same program twice, or two
        # programs from one package, otherwise reports the same gap twice.
        for note in dict.fromkeys(unreadable):
            report.blind = True
            report.skipped.append(
                Skipped(workflow.path, job.name, step.label, note, "not read")
            )

        for call in found:
            if call.token == TOKEN_OTHER:
                report.skipped.append(
                    Skipped(
                        workflow.path,
                        job.name,
                        step.label,
                        call.shown,
                        "authenticated with a different secret, so this block does not govern it",
                    )
                )
                continue
            if call.token == TOKEN_NONE:
                report.skipped.append(
                    Skipped(
                        workflow.path,
                        job.name,
                        step.label,
                        call.shown,
                        call.note or "no token in scope, so this fails before permissions apply",
                    )
                )
                continue

            needs: list[Need] = list(call.needs)
            if call.path is not None:
                try:
                    needs.append(classify(call.path, call.method))
                except UnknownPath as exc:
                    report.blind = True
                    report.findings.append(
                        Finding(
                            UNKNOWN_PATH,
                            workflow.path,
                            job.name,
                            f"{call.shown}: {exc.reason}",
                            step=step.label,
                        )
                    )
                    continue
            for need in needs:
                governed.append((step, call, need))

    report.needs = sorted({n for _, _, n in governed}, key=lambda n: (n.scope, n.level))

    # --- Missing scopes. Sound whatever we failed to read. ------------------
    if grant.source != FROM_DEFAULT:
        seen: set[tuple[str, str, str]] = set()
        for step, call, need in governed:
            if grant.covers(need):
                continue
            key = (step.label, need.scope, need.level)
            if key in seen:
                continue
            seen.add(key)
            if need.scope in UNGRANTABLE:
                if need.scope in GRANTED_ONLY_BY_ALL:
                    report.findings.append(
                        Finding(
                            ONLY_VIA_ALL,
                            workflow.path,
                            job.name,
                            f"{call.shown} reads {UNGRANTABLE[need.scope]}, which no "
                            f"permissions: key grants. Only read-all or write-all does.",
                            step=step.label,
                            scope=need.scope,
                        )
                    )
                else:
                    report.findings.append(
                        Finding(
                            UNGRANTABLE_SCOPE,
                            workflow.path,
                            job.name,
                            f"{call.shown} needs {UNGRANTABLE[need.scope]}, which no "
                            f"permissions: block can grant. This needs a different token.",
                            step=step.label,
                            scope=need.scope,
                        )
                    )
                continue
            held = grant.level(need.scope)
            report.findings.append(
                Finding(
                    MISSING,
                    workflow.path,
                    job.name,
                    f"{call.shown} needs {need}; this job has "
                    f"{need.scope}: {held}",
                    step=step.label,
                    scope=need.scope,
                )
            )

    # --- Unused scopes. Only when we read the whole job. --------------------
    if grant.source != FROM_DEFAULT and not report.blind and not grant.catch_all:
        used_at: dict[str, str] = {}
        for _, _, need in governed:
            if need.scope == METADATA:
                continue
            if used_at.get(need.scope) != WRITE:
                used_at[need.scope] = need.level
        for scope, level in sorted(grant.named().items()):
            if scope not in AUDITABLE:
                continue
            if scope not in used_at:
                report.findings.append(
                    Finding(
                        UNUSED,
                        workflow.path,
                        job.name,
                        f"{scope}: {level} is granted and no step in this job uses it",
                        scope=scope,
                    )
                )
            elif level == WRITE and used_at[scope] == READ:
                report.findings.append(
                    Finding(
                        OVERLEVEL,
                        workflow.path,
                        job.name,
                        f"{scope}: write is granted and every call here only reads",
                        scope=scope,
                    )
                )

    return report


def check(workflows: list[Workflow]) -> Report:
    report = Report()
    for workflow in workflows:
        for job in workflow.jobs:
            report.jobs.append(check_job(workflow, job))
    return report

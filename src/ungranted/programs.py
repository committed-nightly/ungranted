"""The API calls a program a step runs makes, read out of its own source.

`calls.py` answers "does this command name an API path". That only works when
the path is in the workflow file. The jobs whose `permissions:` block is
actually load bearing are the other kind: a step holds `GITHUB_TOKEN`, runs a
CLI of its own, and every call the grant exists for is inside the program.
`core.py` records those commands as opaque and refuses to call any grant in
such a job unused -- honest, and not a check. This module is the check.

It reads the program instead of running it, so the question it answers is
"which API paths appear in this source", not "which did this execution reach".
Those differ: a path behind a branch nobody takes is still reported, which is
the safe direction for a permissions question -- a grant you need on one code
path is a grant you need.

## What it can follow

Three shapes, chosen because they are what the org's own three unreadable
programs use, and in that order of directness:

    subprocess.run([gh, "api", f"repos/{org}/{name}/pulls"])     a direct argv
    gh_json(["api", f"orgs/{org}"])                              via a wrapper
    urllib.request.Request(f"{base}/repos/{r}/actions/runs/{i}/rerun", data=...)

The wrapper case is the one that matters. `ledger.py` has one function that
every API call in the file goes through, and the `subprocess.run` inside it
names no path at all -- the paths are at the nine call sites. So a first pass
finds functions that pass a parameter into a `gh` argv, and a second pass reads
the arguments their callers supply.

A wrapper is only believed to be a `gh` wrapper if the head of the argv can be
traced to the string "gh": a literal, a parameter whose default is `"gh"`, or a
local assignment from one of those (`exe = shutil.which(gh)`). Nothing is
assumed from the function's name.

## Unresolvable parts become `{}`, which is not a failure

An f-string's substitutions are unknowable here, so `f"repos/{org}/{name}/pulls"`
reads as `repos/{}/{}/pulls`. That is the same shape of answer `calls.py`
already produces for `${{ }}` in a workflow file, and `scopes.split_path`
already treats a segment containing `{` as unresolved: it matches a wildcard,
never a literal, and `classify` raises `UnknownPath` rather than guess when the
variable sits where the answer would change. So the imprecision is carried by
the existing scope table instead of being invented here.

What is *not* turned into `{}` is an argv this cannot see the shape of -- a
`*splat` of an unknown list, or a call site that passes a variable where the
argument list should be. Those are reported as unreadable, by file and line,
because "I read this program and could not account for part of it" and "I read
this program" must not print the same way.

## What it deliberately does not do

Method wrappers are identified and their call sites are not resolved. A
`def get(self, path)` that builds a `gh api` argv is found and named, but
`transport.get(...)` is an attribute call on a receiver whose class is not
known here, and `body.get("message")` is spelled identically. Guessing between
them would put dictionary keys into the scope table. The wrapper is reported as
an unresolved entry point instead, which keeps its job honest rather than
silently clean.
"""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field

from . import calls as callscan
from .scopes import Need, UnknownPath, classify, split_path

# What an expression this cannot evaluate becomes inside a string. Chosen to
# match `scopes._is_dyn`, which already treats a `{` as an unresolved segment.
UNRESOLVED = "{}"

_SUBPROCESS_RUNNERS = frozenset(
    {"run", "check_output", "Popen", "call", "check_call", "getoutput", "getstatusoutput"}
)

# The name a `gh` argv head has to trace back to.
_GH_BINARIES = frozenset({"gh", "/usr/bin/gh", "/usr/local/bin/gh"})

# Calls that pass their argument through unchanged, so tracing can look inside
# them when it is looking for a binary name.
_PASSTHROUGH = frozenset({"which", "str", "fspath", "abspath", "realpath", "resolve"})

@dataclass(frozen=True)
class ProgramCall:
    """One API call found in a program's source."""

    shown: str
    where: str
    needs: tuple[Need, ...] = ()
    path: str | None = None
    method: str = "GET"


@dataclass(frozen=True)
class ProgramUnreadable:
    """Something in the program that looks like an API call and was not read."""

    shown: str
    where: str
    reason: str


@dataclass
class Program:
    """The result of reading one program."""

    entry: str
    modules: list[str] = field(default_factory=list)
    calls: list[ProgramCall] = field(default_factory=list)
    unreadable: list[ProgramUnreadable] = field(default_factory=list)

    @property
    def read(self) -> bool:
        """Was every API-shaped construct in it accounted for?"""
        return not self.unreadable


# --------------------------------------------------------------------------
# resolving a command to a file
# --------------------------------------------------------------------------

# `[project.scripts]` entries, read with a line parser rather than a TOML one:
# `tomllib` is 3.11+ and this supports 3.10. The shape is narrow enough that
# the two disagree only on files that would not install either way.
_SCRIPT_LINE = re.compile(
    r"""^\s*(?P<name>[A-Za-z0-9_.-]+)\s*=\s*["'](?P<target>[^"':]+):[^"']+["']"""
)
_SECTION = re.compile(r"^\s*\[(?P<name>[^\]]+)\]")


def console_scripts(root: str) -> dict[str, str]:
    """Console script name -> the module path its entry point names."""
    path = os.path.join(root, "pyproject.toml")
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        return {}
    out: dict[str, str] = {}
    section = ""
    for line in text.splitlines():
        found = _SECTION.match(line)
        if found:
            section = found.group("name").strip()
            continue
        if section not in ("project.scripts", "project.gui-scripts"):
            continue
        entry = _SCRIPT_LINE.match(line)
        if entry:
            out[entry.group("name")] = entry.group("target")
    return out


def repo_root(workflow_path: str) -> str | None:
    """The repository a workflow file belongs to: the directory above `.github`.

    Derived from the workflow's own path rather than from the argument the user
    gave, so `ungranted one/file.yml` and `ungranted .` resolve a step's
    `./ledger.py` to the same file. A workflow file that is not under a
    `.github` directory -- which is every fixture in `examples/` -- has no
    repository to resolve against, and gets None.
    """
    parts = os.path.abspath(workflow_path).split(os.sep)
    if ".github" not in parts:
        return None
    above = parts[: len(parts) - 1 - parts[::-1].index(".github")]
    return os.sep.join(above) or os.sep


def _module_file(root: str, dotted: str) -> str | None:
    """Where a dotted module name's source is, under src/ or at the top level."""
    rel = dotted.replace(".", os.sep)
    for base in (os.path.join(root, "src"), root):
        for candidate in (f"{rel}.py", os.path.join(rel, "__init__.py")):
            full = os.path.join(base, candidate)
            if os.path.isfile(full):
                return full
    return None


def _is_python(path: str) -> bool:
    if path.endswith(".py"):
        return True
    try:  # a shebang, for an extensionless script
        with open(path, "rb") as handle:
            return b"python" in handle.readline()
    except OSError:
        return False


def resolve_command(tokens: list[str], root: str) -> str | None:
    """The Python file a step's command runs, if it is one in this repository.

    Handles the three spellings that occur: a script named directly
    (`./ledger.py`), a script given to an interpreter (`python3 scripts/x.py`),
    and an installed console script (`greenwash`), which is resolved through
    `pyproject.toml` because the built entry point does not exist in a checkout.
    """
    if not tokens:
        return None
    argv0 = tokens[0]
    name = argv0.rsplit("/", 1)[-1]

    if name.startswith("python"):
        # The first argument that is not a flag, and not `-m`'s module.
        rest = tokens[1:]
        if rest and rest[0] == "-m":
            return _module_file(root, rest[1]) if len(rest) > 1 else None
        target = next((t for t in rest if not t.startswith("-")), None)
        if target is None:
            return None
        full = os.path.join(root, target)
        return full if os.path.isfile(full) else None

    if "/" in argv0 or argv0.endswith(".py"):
        full = os.path.join(root, argv0.lstrip("./"))
        if os.path.isfile(full) and _is_python(full):
            return full
        return None

    target = console_scripts(root).get(name)
    if target:
        return _module_file(root, target)
    return None


def package_modules(entry: str) -> list[str]:
    """Every module read for an entry point.

    A file that sits in a package is read together with the rest of that
    package, rather than by following its imports. Crude and predictable: the
    alternative is resolving imports, and the thing being looked for is "does
    any of this code reach the API", which does not depend on the import graph.
    A loose script is read on its own.
    """
    directory = os.path.dirname(entry)
    if not os.path.isfile(os.path.join(directory, "__init__.py")):
        return [entry]
    found = [
        os.path.join(directory, name)
        for name in sorted(os.listdir(directory))
        if name.endswith(".py")
    ]
    return found or [entry]


# --------------------------------------------------------------------------
# rendering an expression as a string
# --------------------------------------------------------------------------

_PERCENT = re.compile(r"%[-#0-9. +]*[sdrifgx]")


class _Scope:
    """Local string assignments in one function, for one level of tracing.

    Only names assigned exactly once are traced. A name assigned twice has two
    answers and tracing it would pick whichever came last in the file, which is
    not a fact about anything.
    """

    def __init__(self, node: ast.AST | None = None, parent: _Scope | None = None):
        self.names: dict[str, ast.expr | None] = {}
        self.parent = parent
        if node is not None:
            self._collect(node)

    def _collect(self, node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args
            positional = list(args.posonlyargs) + list(args.args)
            for arg, default in zip(
                positional[len(positional) - len(args.defaults) :], args.defaults
            ):
                self._bind(arg.arg, default)
            for arg, default in zip(args.kwonlyargs, args.kw_defaults):
                if default is not None:
                    self._bind(arg.arg, default)
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        self._bind(target.id, child.value)
            elif isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
                self._bind(child.target.id, child.value)

    def _bind(self, name: str, value: ast.expr | None) -> None:
        if name in self.names:
            self.names[name] = None  # assigned more than once: no single answer
        else:
            self.names[name] = value

    def get(self, name: str) -> ast.expr | None:
        if name in self.names:
            return self.names[name]
        return self.parent.get(name) if self.parent else None


def render(node: ast.expr, scope: _Scope | None = None, depth: int = 0) -> str:
    """The string an expression produces, with unknowable parts as `{}`.

    Never fails and never returns None: an expression this cannot read is
    `{}`, which the scope table already treats as an unresolved segment. The
    caller decides whether a path that is entirely `{}` is worth reporting.
    """
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else UNRESOLVED
    if isinstance(node, ast.JoinedStr):
        return "".join(
            part.value
            if isinstance(part, ast.Constant) and isinstance(part.value, str)
            else UNRESOLVED
            for part in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return render(node.left, scope, depth) + render(node.right, scope, depth)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        # "repos/%s/pulls" % owner
        return _PERCENT.sub(UNRESOLVED, render(node.left, scope, depth))
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in ("format", "join"):
            # `"repos/{}/pulls".format(x)` already carries its own braces.
            return render(func.value, scope, depth)
        if isinstance(func, ast.Attribute) and func.attr in ("lstrip", "rstrip", "strip"):
            return render(func.value, scope, depth)
        return UNRESOLVED
    if isinstance(node, ast.Name) and scope is not None and depth < 4:
        bound = scope.get(node.id)
        if bound is not None:
            return render(bound, scope, depth + 1)
    return UNRESOLVED


def _binary_name(node: ast.expr, scope: _Scope, depth: int = 0) -> str | None:
    """Trace the head of an argv to a binary name, through `shutil.which` etc."""
    if depth > 4:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Call):
        name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(
            node.func, "id", ""
        )
        if name in _PASSTHROUGH and node.args:
            return _binary_name(node.args[0], scope, depth + 1)
        return None
    if isinstance(node, ast.Name):
        bound = scope.get(node.id)
        if bound is not None:
            return _binary_name(bound, scope, depth + 1)
        return None
    if isinstance(node, ast.Attribute):
        # `self.gh` -- resolved from the class body by the caller's scope.
        bound = scope.get(node.attr)
        if bound is not None:
            return _binary_name(bound, scope, depth + 1)
    return None


def _is_gh(name: str | None) -> bool:
    if not name:
        return False
    return name in _GH_BINARIES or name.rsplit("/", 1)[-1] == "gh"


# --------------------------------------------------------------------------
# gh argvs, directly and through a wrapper
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Wrapper:
    """A function that builds a `gh` argv out of one of its parameters.

    `tail` is the parameter splatted into the argv (`[exe, *args]`), so a
    caller's list is the whole gh command line. `path` is a parameter sitting in
    the endpoint position of an argv that already says `api`, so a caller's
    argument is just the path.
    """

    name: str
    qualname: str
    tail: str | None = None
    path: str | None = None
    method: str = "GET"
    is_method: bool = False
    where: str = ""


def _argv_elements(node: ast.expr) -> list[ast.expr] | None:
    if isinstance(node, (ast.List, ast.Tuple)):
        return list(node.elts)
    return None


def _subprocess_argv(call: ast.Call) -> list[ast.expr] | None:
    """The argv list of a `subprocess.*` call, if it is one with a literal list."""
    func = call.func
    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
    if name not in _SUBPROCESS_RUNNERS or not call.args:
        return None
    return _argv_elements(call.args[0])


def _gh_api_method(words: list[str]) -> str:
    """`-X POST` out of a rendered gh argv."""
    for i, word in enumerate(words):
        if word in ("-X", "--method") and i + 1 < len(words):
            return words[i + 1].upper()
    return "GET"


def find_wrappers(tree: ast.Module, module: str) -> list[Wrapper]:
    """Functions that put one of their parameters into a `gh` argv."""
    found: list[Wrapper] = []
    module_scope = _Scope(tree)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        parent_class = _enclosing_class(tree, node)
        scope = _Scope(node, parent=_class_scope(parent_class, module_scope))
        params = {
            arg.arg
            for arg in list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
        }
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            argv = _subprocess_argv(call)
            if not argv:
                continue
            if not _is_gh(_binary_name(argv[0], scope)):
                continue
            qualname = f"{parent_class.name}.{node.name}" if parent_class else node.name
            where = f"{module}:{node.lineno}"

            splat = next(
                (
                    el.value.id
                    for el in argv[1:]
                    if isinstance(el, ast.Starred)
                    and isinstance(el.value, ast.Name)
                    and el.value.id in params
                ),
                None,
            )
            if splat:
                found.append(
                    Wrapper(node.name, qualname, tail=splat,
                            is_method=parent_class is not None, where=where)
                )
                continue

            plain = [el for el in argv[1:] if not isinstance(el, ast.Starred)]
            words = [render(el, scope) for el in plain]
            if "api" not in words:
                continue
            # The endpoint is the first parameter named after `api`, skipping
            # the flags and the values they consume -- `["api", "-H", h, path]`.
            endpoint = None
            for el, word in list(zip(plain, words))[words.index("api") + 1 :]:
                if isinstance(el, ast.Name) and el.id in params and not word.startswith("-"):
                    endpoint = el.id
                    break
            if endpoint:
                found.append(
                    Wrapper(node.name, qualname, path=endpoint, method=_gh_api_method(words),
                            is_method=parent_class is not None, where=where)
                )
    return found


def _enclosing_class(tree: ast.Module, target: ast.AST) -> ast.ClassDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and any(child is target for child in node.body):
            return node
    return None


def _class_scope(klass: ast.ClassDef | None, parent: _Scope) -> _Scope:
    """Class-body assignments, so a dataclass field `gh: str = "gh"` resolves."""
    if klass is None:
        return parent
    scope = _Scope(parent=parent)
    for child in klass.body:
        if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
            scope._bind(child.target.id, child.value)
        elif isinstance(child, ast.Assign):
            for target in child.targets:
                if isinstance(target, ast.Name):
                    scope._bind(target.id, child.value)
    return scope


# --------------------------------------------------------------------------
# urllib and the requests-shaped libraries
# --------------------------------------------------------------------------

_HTTP_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})


def _url_is_github(url: str) -> str | None:
    """The API path in a URL, or None if it is not a GitHub API URL.

    A URL built on a variable base -- `f"{api_base}/repos/{r}/..."` -- is read
    as GitHub only when what follows the base is a path the scope table
    recognises. The same program that calls GitHub this way also calls Slack
    this way (`f"{api_base}/chat.postMessage"`), and the base is the only thing
    that tells them apart; it is not knowable here, so the shape of the rest is
    what decides. `chat.postMessage` matches no rule and is left alone.

    A URL that does name a host is judged on the host, parsed -- not on
    containing the string `api.github.com` somewhere. Both
    `https://api.github.com.evil.test/repos/o/r/pulls` and
    `https://evil.test/?x=api.github.com` contain it, and reading either as
    GitHub would report a scope the workflow does not need. `split_path`
    already rejects a host that is not GitHub's, so the test is delegated to it
    rather than written a second time here.
    """
    text = url.strip()
    if "//" in text.split("?", 1)[0]:
        try:
            split_path(text)  # raises unless the host is a GitHub API host
        except UnknownPath:
            return None
        return text
    head, _, rest = text.partition("/")
    if UNRESOLVED in head and rest:
        try:
            classify(rest.split("?", 1)[0])
        except UnknownPath:
            return None
        return rest
    return None


def _request_method(call: ast.Call, scope: _Scope) -> str:
    """urllib's method: explicit if given, POST when there is a body, else GET."""
    for keyword in call.keywords:  # an explicit method wins over a body
        if keyword.arg == "method":
            rendered = render(keyword.value, scope)
            if rendered and UNRESOLVED not in rendered:
                return rendered.upper()
    for keyword in call.keywords:
        if keyword.arg == "data" and not _is_none(keyword.value):
            return "POST"
    if len(call.args) > 1 and not _is_none(call.args[1]):
        return "POST"
    return "GET"


def _is_none(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


# --------------------------------------------------------------------------
# reading one module
# --------------------------------------------------------------------------


def _needs_for(path: str, method: str) -> tuple[tuple[Need, ...] | None, str | None]:
    """(needs, reason it could not be classified)."""
    try:
        need = classify(path, method)
    except UnknownPath as exc:
        return None, exc.args[1] if len(exc.args) > 1 else "no rule for this path"
    return (need,), None


def _gh_call(words: list[str], where: str, out: Program) -> None:
    """Record a rendered `gh ...` argv, which may or may not be `gh api`."""
    tokens = ["gh"] + words
    if "api" in words:
        path, method, _ = callscan.parse_gh_api(tokens)
        shown = f"gh api {path or '?'}"
        if path is None:
            out.unreadable.append(ProgramUnreadable(shown, where, "gh api with no path"))
            return
        if path.strip("{}/") == "":
            out.unreadable.append(
                ProgramUnreadable(
                    f"gh api {path}", where, "the endpoint is a variable this could not trace"
                )
            )
            return
        needs, why = _needs_for(path, method)
        if needs is None:
            out.unreadable.append(ProgramUnreadable(shown, where, why or "unknown path"))
            return
        out.calls.append(ProgramCall(shown, where, needs, path=path, method=method))
        return
    needs, shown = callscan.parse_gh_command(tokens)
    if needs is None:
        out.unreadable.append(ProgramUnreadable(shown, where, "not a gh command this knows"))
        return
    if needs:
        out.calls.append(ProgramCall(shown, where, tuple(needs)))


def scan_module(source: str, module: str, out: Program, wrappers: list[Wrapper]) -> None:
    """Read one module's API calls into `out`."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        out.unreadable.append(
            ProgramUnreadable(module, f"{module}:{exc.lineno or 0}", f"will not parse: {exc.msg}")
        )
        return

    module_scope = _Scope(tree)
    by_name = {w.name: w for w in wrappers}
    functions = [
        n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    scopes = {
        id(fn): _Scope(fn, parent=_class_scope(_enclosing_class(tree, fn), module_scope))
        for fn in functions
    }
    owner: dict[int, ast.AST] = {}
    for fn in functions:
        for child in ast.walk(fn):
            owner.setdefault(id(child), fn)

    for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call)]:
        scope = scopes.get(id(owner.get(id(call))), module_scope)
        where = f"{module}:{call.lineno}"
        func = call.func
        attr = func.attr if isinstance(func, ast.Attribute) else None
        plain_name = getattr(func, "id", None)

        # 1. a direct subprocess argv naming gh
        argv = _subprocess_argv(call)
        if argv and _is_gh(_binary_name(argv[0], scope)):
            enclosing = owner.get(id(call))
            inside_wrapper = enclosing is not None and any(
                w.where == f"{module}:{enclosing.lineno}" for w in wrappers
            )
            if inside_wrapper:
                # This argv is the wrapper's own. Its endpoint is whatever its
                # callers pass, so reading it here would report the parameter
                # as an untraceable path and say nothing true. Tail wrappers
                # are read at their call sites below; method wrappers are
                # reported by read_program.
                continue
            if any(isinstance(el, ast.Starred) for el in argv[1:]):
                out.unreadable.append(
                    ProgramUnreadable("a gh argv", where, "built from a list this cannot see")
                )
                continue
            _gh_call([render(el, scope) for el in argv[1:]], where, out)
            continue

        # 2. a call to a wrapper found in pass one
        wrapper = by_name.get(plain_name or "")
        if wrapper and wrapper.tail and not wrapper.is_method:
            if not call.args:
                continue
            elements = _argv_elements(call.args[0])
            if elements is None:
                out.unreadable.append(
                    ProgramUnreadable(
                        f"{wrapper.name}(...)", where,
                        f"its {wrapper.tail} argument is not a list written here",
                    )
                )
                continue
            if any(isinstance(el, ast.Starred) for el in elements):
                out.unreadable.append(
                    ProgramUnreadable(
                        f"{wrapper.name}(...)", where, "its argument list is partly spliced"
                    )
                )
                continue
            _gh_call([render(el, scope) for el in elements], where, out)
            continue

        # 3. urllib / requests
        if attr == "Request" or plain_name == "Request" or attr == "urlopen":
            if not call.args:
                continue
            url = render(call.args[0], scope)
            path = _url_is_github(url)
            if path is None:
                continue
            method = _request_method(call, scope)
            needs, why = _needs_for(path, method)
            shown = f"{method} {path}"
            if needs is None:
                out.unreadable.append(ProgramUnreadable(shown, where, why or "unknown path"))
                continue
            out.calls.append(ProgramCall(shown, where, needs, path=path, method=method))
            continue

        if attr in _HTTP_VERBS and call.args:
            url = render(call.args[0], scope)
            path = _url_is_github(url)
            if path is None:
                continue
            method = attr.upper()
            needs, why = _needs_for(path, method)
            shown = f"{method} {path}"
            if needs is None:
                out.unreadable.append(ProgramUnreadable(shown, where, why or "unknown path"))
                continue
            out.calls.append(ProgramCall(shown, where, needs, path=path, method=method))


def read_program(tokens: list[str], root: str) -> Program | None:
    """Read the API calls made by the program a step's command runs.

    None when the command does not resolve to Python source in this repository,
    which is the honest answer for `claude`, `node build.js` or a binary: the
    step stays opaque and its job stays blind, exactly as before.
    """
    entry = resolve_command(tokens, root)
    if entry is None:
        return None
    modules = package_modules(entry)
    out = Program(entry=os.path.relpath(entry, root))

    sources: list[tuple[str, str]] = []
    for path in modules:
        try:
            with open(path, encoding="utf-8") as handle:
                sources.append((os.path.relpath(path, root), handle.read()))
        except OSError as exc:
            out.unreadable.append(
                ProgramUnreadable(os.path.relpath(path, root), "", f"could not read it: {exc}")
            )
    out.modules = [name for name, _ in sources]

    wrappers: list[Wrapper] = []
    trees: list[tuple[str, ast.Module]] = []
    for name, source in sources:
        try:
            trees.append((name, ast.parse(source)))
        except SyntaxError:
            continue
    for name, tree in trees:
        wrappers.extend(find_wrappers(tree, name))

    for name, source in sources:
        scan_module(source, name, out, wrappers)

    for wrapper in wrappers:
        if wrapper.is_method:
            out.unreadable.append(
                ProgramUnreadable(
                    f"{wrapper.qualname}()",
                    wrapper.where,
                    "builds a gh api call from an argument; its callers are attribute "
                    "calls this does not attribute to it",
                )
            )
    return out

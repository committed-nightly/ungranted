"""Finding the API calls a job's steps make, and which token they make them with.

The token part matters as much as the path. A step calling the API with a
personal access token out of `secrets.RELEASE_PAT` is not governed by the
workflow's `permissions:` block at all, and reporting a missing scope for it
would be a plain false positive. So every call carries how it is authenticated:

    workflow   secrets.GITHUB_TOKEN or github.token -- the block governs it
    other      some other secret -- the block is irrelevant
    none       nothing in scope sets a token

`none` is its own answer because `GITHUB_TOKEN` is not in a step's environment
unless the workflow puts it there. `run: gh api ...` with no `env:` fails with
`gh: To use GitHub CLI in a GitHub Actions workflow, set the GH_TOKEN
environment variable`, which is not a permissions problem and must not be
reported as one.

Shell parsing here is deliberately shallow: commands are split on newlines and
on the operators that separate them, then each is tokenised with `shlex`. It
does not know about `if` blocks, functions or loops, and it does not need to --
the question is only ever "does this command name an API path".
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from .scopes import READ, WRITE, Need

# `${{ ... }}` is replaced before anything tries to parse the line, because the
# expression may contain quotes of its own -- `${{ fromJSON('[1]') }}` -- and
# every quote-aware parser gets that wrong. The placeholder keeps a `$` so that
# path normalisation still sees it as an unresolvable segment.
_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
_PLACEHOLDER = re.compile(r"\$__GHEXPR(\d+)__")

# The two things that mean "this is the workflow's own token".
_WORKFLOW_TOKEN = re.compile(r"secrets\s*\.\s*GITHUB_TOKEN|github\s*\.\s*token", re.I)
_ANY_SECRET = re.compile(r"secrets\s*\.\s*([A-Za-z_][A-Za-z0-9_-]*)")

TOKEN_WORKFLOW = "workflow"
TOKEN_OTHER = "other"
TOKEN_NONE = "none"

# Variables gh reads for its token, in the order gh reads them.
GH_TOKEN_VARS = ("GH_TOKEN", "GITHUB_TOKEN")

_SEPARATORS = ("&&", "||", ";", "|", "\n", "(", ")", "{", "}", "&")


@dataclass(frozen=True)
class Call:
    """One API call found in a step."""

    kind: str  # gh-api | gh | curl | github-script | action | oidc | registry
    shown: str  # what to print in the report
    token: str  # TOKEN_WORKFLOW | TOKEN_OTHER | TOKEN_NONE
    path: str | None = None
    method: str = "GET"
    needs: tuple[Need, ...] = ()
    note: str | None = None


@dataclass
class Unreadable:
    """Something in a step we could not resolve, that must not read as clean."""

    shown: str
    reason: str


@dataclass
class StepFindings:
    calls: list[Call] = field(default_factory=list)
    unreadable: list[Unreadable] = field(default_factory=list)


def mask_expressions(text: str) -> tuple[str, dict[str, str]]:
    """Replace every `${{ ... }}` with a single opaque shell word."""
    mapping: dict[str, str] = {}

    def swap(match: re.Match[str]) -> str:
        name = f"$__GHEXPR{len(mapping)}__"
        mapping[name] = match.group(1).strip()
        return name

    return _EXPRESSION.sub(swap, text), mapping


def unmask(text: str, mapping: dict[str, str]) -> str:
    return _PLACEHOLDER.sub(lambda m: "${{ " + mapping.get(m.group(0), "?") + " }}", text)


def classify_token_value(value: str) -> str:
    if _WORKFLOW_TOKEN.search(value):
        return TOKEN_WORKFLOW
    if _ANY_SECRET.search(value):
        return TOKEN_OTHER
    return TOKEN_NONE


def commands(script: str) -> list[list[str]]:
    """Split a `run:` body into tokenised commands.

    Operators are split on only outside quotes. A command that `shlex` cannot
    tokenise at all -- an unbalanced quote, usually inside a heredoc -- is
    dropped rather than raised on: a heredoc body is data, not a command.
    """
    joined = re.sub(r"\\\n", " ", script)
    pieces: list[str] = []
    current: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(joined):
        char = joined[i]
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            i += 1
            continue
        if char in "'\"":
            quote = char
            current.append(char)
            i += 1
            continue
        for separator in _SEPARATORS:
            if joined.startswith(separator, i):
                pieces.append("".join(current))
                current = []
                i += len(separator)
                break
        else:
            current.append(char)
            i += 1
    pieces.append("".join(current))

    out = []
    for piece in pieces:
        piece = piece.strip()
        if not piece:
            continue
        try:
            tokens = shlex.split(piece)
        except ValueError:
            continue
        if tokens:
            out.append(tokens)
    return out


# --------------------------------------------------------------------------
# gh api
# --------------------------------------------------------------------------

# Flags that consume the next argument, so the argument after them is never
# the path.
_GH_API_VALUE_FLAGS = {
    "-X", "--method", "-f", "--raw-field", "-F", "--field", "-H", "--header",
    "-q", "--jq", "-t", "--template", "--input", "--cache", "-p", "--preview",
    "--hostname",
}
# Flags that imply a request body, and so a method of POST unless -X says
# otherwise. This is gh's own rule and it catches people out: `gh api X -f a=b`
# is a POST with no -X anywhere on the line.
_GH_API_BODY_FLAGS = {"-f", "--raw-field", "-F", "--field", "--input"}


def parse_gh_api(tokens: list[str]) -> tuple[str | None, str, bool]:
    """(path, method, saw_body) for a `gh api` command."""
    rest = tokens[tokens.index("api") + 1 :]
    path = None
    method = None
    saw_body = False
    i = 0
    while i < len(rest):
        token = rest[i]
        if "=" in token and token.startswith("--"):
            flag, _, value = token.partition("=")
            if flag in ("--method",):
                method = value
            if flag in _GH_API_BODY_FLAGS:
                saw_body = True
            i += 1
            continue
        if token in _GH_API_VALUE_FLAGS:
            if token in ("-X", "--method") and i + 1 < len(rest):
                method = rest[i + 1]
            if token in _GH_API_BODY_FLAGS:
                saw_body = True
            i += 2
            continue
        if token.startswith("-"):
            i += 1
            continue
        if path is None:
            path = token
        i += 1
    if method is None:
        method = "POST" if saw_body else "GET"
    return path, method.upper(), saw_body


# --------------------------------------------------------------------------
# gh subcommands other than api
# --------------------------------------------------------------------------

# Verbs that only read. Anything else under a known noun is a write.
_READ_VERBS = frozenset(
    {"list", "view", "status", "download", "diff", "ls", "checks", "watch", "cat"}
)

# noun -> scope. Nouns absent from here are not recognised and are reported as
# such rather than assumed harmless.
_GH_NOUNS = {
    "pr": "pull-requests",
    "issue": "issues",
    "run": "actions",
    "workflow": "actions",
    "cache": "actions",
    "release": "contents",
    "label": "issues",
    "secret": "secrets",
    "variable": "variables",
    "ruleset": "administration",
    "project": "administration",
}

# Commands whose needs are not just their noun.
_GH_SPECIAL: dict[tuple[str, ...], tuple[Need, ...]] = {
    ("pr", "checks"): (Need("checks", READ), Need("pull-requests", READ)),
    ("pr", "merge"): (Need("contents", WRITE), Need("pull-requests", WRITE)),
    ("repo", "view"): (Need("metadata", READ),),
    ("repo", "clone"): (Need("contents", READ),),
    ("repo", "list"): (Need("metadata", READ),),
    ("run", "download"): (Need("actions", READ),),
    ("workflow", "run"): (Need("actions", WRITE),),
}


def parse_gh_command(tokens: list[str]) -> tuple[tuple[Need, ...] | None, str]:
    """(needs, shown) for a `gh <noun> <verb>` command, or (None, shown)."""
    rest = [t for t in tokens[1:] if not t.startswith("-")]
    if not rest:
        return None, "gh"
    noun = rest[0]
    verb = rest[1] if len(rest) > 1 else ""
    shown = "gh " + " ".join(rest[:2]).strip()
    if (noun, verb) in _GH_SPECIAL:
        return _GH_SPECIAL[(noun, verb)], shown
    if noun in _GH_NOUNS:
        level = READ if verb in _READ_VERBS else WRITE
        return (Need(_GH_NOUNS[noun], level),), shown
    if noun in ("auth", "config", "help", "version", "completion", "alias", "extension"):
        return (), shown  # talks to no repository API
    return None, shown


# --------------------------------------------------------------------------
# curl
# --------------------------------------------------------------------------

_CURL_VALUE_FLAGS = {
    "-H", "--header", "-d", "--data", "--data-raw", "--data-binary",
    "--data-urlencode", "-X", "--request", "-o", "--output", "-u", "--user",
    "-w", "--write-out", "-A", "--user-agent", "-b", "--cookie", "-e",
    "--referer", "--url", "-T", "--upload-file",
}
_CURL_BODY_FLAGS = {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
                    "-T", "--upload-file"}
_API_URL = re.compile(r"(?:https?://)?(?:api\.github\.com|__GHEXPR\d+__)/|api\.github\.com")


def parse_curl(tokens: list[str]) -> tuple[str | None, str, list[str]]:
    """(url, method, header values) for a curl command."""
    url = None
    method = None
    saw_body = False
    headers: list[str] = []
    i = 1
    while i < len(tokens):
        token = tokens[i]
        if token in _CURL_VALUE_FLAGS:
            value = tokens[i + 1] if i + 1 < len(tokens) else ""
            if token in ("-X", "--request"):
                method = value
            elif token in ("-H", "--header"):
                headers.append(value)
            elif token == "--url":
                url = value
            if token in _CURL_BODY_FLAGS:
                saw_body = True
            i += 2
            continue
        if token.startswith("-"):
            i += 1
            continue
        if url is None and ("://" in token or token.startswith("api.github.com")):
            url = token
        i += 1
    if method is None:
        method = "POST" if saw_body else "GET"
    return url, method.upper(), headers

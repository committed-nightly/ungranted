"""Which permission scope an API path needs.

Three sets of scope names matter here and they are not the same set.

`SETTABLE` is what a `permissions:` block may name. It is short and fixed, and
it is the only list GitHub will accept.

`UNGRANTABLE` is the scopes real endpoints require that a workflow's
`permissions:` block has no key for. Repository administration is the big one.
A step that calls `/repos/o/r/hooks` cannot be fixed by editing the block; it
needs a different token. Reporting that as "add administration: read" would
send someone to a key actionlint rejects, so it gets its own finding.

`AUDITABLE` is the scopes this module can see the *need* for by reading a
workflow file. It is the smallest of the three and it is the one that limits
what we may say about over-granting. `packages: write` is used by a `docker
push`, `id-token: write` by a library call three repositories away; a tool that
cannot see those must not call the grant unused. Missing-scope findings are
sound whatever is in here -- they come from a call we did see. Unused-scope
findings are only sound for scopes in this set.

The table is curated, because GitHub publishes no machine-readable map from
endpoint to required scope: its OpenAPI description carries
`category`/`subcategory`, which is close enough to mislead and not close enough
to use. It is curated from measurement rather than from the docs -- see
`tests/measured.tsv`. Anything the table does not recognise is an error, never
"needs nothing"; see `UnknownPath`.
"""

from __future__ import annotations

from dataclasses import dataclass

# What a permissions: block may name. GitHub rejects anything else, and
# actionlint catches it before the run.
SETTABLE = (
    "actions",
    "artifact-metadata",
    "attestations",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "id-token",
    "issues",
    "models",
    "packages",
    "pages",
    "pull-requests",
    "repository-projects",
    "security-events",
    "statuses",
)

# Always granted read, never settable, so a need for it is always satisfied.
# `permissions: {}` resolves to exactly `Metadata: read` and nothing else.
METADATA = "metadata"

# Scopes endpoints require that no permissions: block has a key for. The value
# is how to describe it in a finding.
UNGRANTABLE = {
    "administration": "repository administration",
    "organization-administration": "organisation administration",
    "secrets": "Actions secrets",
    "variables": "Actions variables",
    "dependabot-alerts": "Dependabot alerts",
    "secret-scanning-alerts": "secret scanning alerts",
    "starring": "stars and watchers",
    "user": "the authenticated user",
}

# Scopes whose need this module can see in a workflow file well enough to claim
# a grant for them is unused. Deliberately excludes attestations, id-token,
# models, packages and pages: their consumers are SDK calls and registry
# pushes, and we would be guessing.
AUDITABLE = frozenset(
    {
        "actions",
        "checks",
        "contents",
        "deployments",
        "discussions",
        "issues",
        "pull-requests",
        "security-events",
        "statuses",
    }
)

# Scopes no key grants, but `read-all` and `write-all` do. The runner resolves
# `read-all` to nineteen scopes. `Metadata` is implicit, and three of the rest
# -- CodeQuality, Drives and VulnerabilityAlerts -- have no key you can name.
# So `read-all` is not the union of SETTABLE in either direction: it reaches
# endpoints that naming scopes cannot, and it does not grant `id-token`, which
# is settable and only meaningful as a write.
GRANTED_ONLY_BY_ALL = frozenset({"dependabot-alerts"})

READ = "read"
WRITE = "write"

# Methods that only read. Everything else needs write.
READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# A path segment we could not resolve: $VAR, ${VAR}, ${{ expr }}, {owner}.
DYN = "\x00dyn"


class UnknownPath(Exception):
    """The table does not cover this path, so we do not know what it needs.

    Raised rather than returning "nothing", because "nothing" is wrong in the
    direction that makes a workflow look fine right up until it runs.
    """

    def __init__(self, path: str, reason: str = "no rule for this path") -> None:
        super().__init__(f"{path}: {reason}")
        self.path = path
        self.reason = reason


@dataclass(frozen=True)
class Need:
    scope: str
    level: str

    @property
    def settable(self) -> bool:
        return self.scope in SETTABLE

    def __str__(self) -> str:
        return f"{self.scope}: {self.level}"


# Ordered. First match wins, so narrow rules come before broad ones. A pattern
# element is a literal, "*" for exactly one segment, or "**" for the rest of
# the path (zero or more segments, only valid last).
#
# A dynamic segment matches "*" and "**" and never a literal, which is what
# makes `gh api "repos/o/r/$KIND"` an UnknownPath instead of a guess.
#
# Each rule is (pattern, scope) or (pattern, write_scope, read_scope). The two
# differ more often than you would expect: listing a repository's collaborators
# needs metadata alone, adding one needs administration.
#
# Every /repos rule here was measured against the real API rather than read off
# a documentation page. tests/measured.tsv holds the results and
# tests/test_measured.py asserts this table still agrees with them. Two came
# out the other way from what the docs imply: /repos/{o}/{r}/tags is readable
# with metadata alone while /repos/{o}/{r}/releases is not, and
# /repos/{o}/{r}/environments needs `actions`, not anything environment-shaped.
_RULES: tuple[tuple, ...] = (
    # --- Actions, minus the parts of it that are not the actions scope -------
    (("actions", "permissions", "**"), "administration"),
    (("actions", "runners", "**"), "administration"),
    (("actions", "runner-groups", "**"), "administration"),
    (("actions", "oidc", "**"), "administration"),
    (("actions", "secrets", "**"), "secrets"),
    (("actions", "variables", "**"), "variables"),
    (("actions", "**"), "actions"),
    # Measured: readable with contents+actions, not with contents alone.
    (("environments", "**"), "administration", "actions"),
    # --- Pull requests ------------------------------------------------------
    (("pulls", "**"), "pull-requests"),
    # --- Issues. Labels and milestones are the issues scope too. ------------
    (("issues", "**"), "issues"),
    (("labels", "**"), "issues"),
    (("milestones", "**"), "issues"),
    # --- Checks -------------------------------------------------------------
    (("check-runs", "**"), "checks"),
    (("check-suites", "**"), "checks"),
    (("commits", "*", "check-runs"), "checks"),
    (("commits", "*", "check-suites"), "checks"),
    # --- Commit statuses. Same path prefix as checks, different scope. ------
    (("commits", "*", "statuses"), "statuses"),
    (("commits", "*", "status"), "statuses"),
    (("statuses", "**"), "statuses"),
    # --- The rest of the settable scopes ------------------------------------
    (("deployments", "**"), "deployments"),
    (("pages", "**"), "pages"),
    (("code-scanning", "**"), "security-events"),
    (("discussions", "**"), "discussions"),
    (("attestations", "**"), "attestations"),
    # Dependency submission is contents: write, despite the path.
    (("dependency-graph", "**"), "contents"),
    # --- Not settable by any block ------------------------------------------
    (("dependabot", "secrets", "**"), "secrets"),
    (("dependabot", "alerts", "**"), "dependabot-alerts"),
    (("secret-scanning", "**"), "secret-scanning-alerts"),
    (("hooks", "**"), "administration"),
    (("invitations", "**"), "administration"),
    (("vulnerability-alerts",), "administration"),
    (("automated-security-fixes",), "administration"),
    (("rulesets", "**"), "administration"),
    (("autolinks", "**"), "administration"),
    (("traffic", "**"), "administration"),
    (("import", "**"), "administration"),
    (("transfer",), "administration"),
    (("branches", "*", "protection", "**"), "administration"),
    (("branches", "*", "rename"), "administration"),
    (("tags", "protection", "**"), "administration"),
    (("stargazers", "**"), "starring"),
    # --- Split: cheap to read, administrative to change ---------------------
    (("collaborators", "**"), "administration", METADATA),
    # Bare /tags lists git tags and is readable with metadata; creating one
    # goes through /git/refs, which is contents.
    (("tags",), "contents", METADATA),
    # /comments is commit comments, not issue comments.
    (("comments", "**"), "contents", METADATA),
    # --- Contents -----------------------------------------------------------
    (("contents", "**"), "contents"),
    (("git", "**"), "contents"),
    (("branches", "**"), "contents"),
    (("commits", "**"), "contents"),
    (("compare", "**"), "contents"),
    (("tags", "**"), "contents"),
    (("releases", "**"), "contents"),
    (("readme", "**"), "contents"),
    (("merges",), "contents"),
    (("merge-upstream",), "contents"),
    (("zipball", "**"), "contents"),
    (("tarball", "**"), "contents"),
    # Creating a fork is contents: write; listing them needs metadata.
    (("forks", "**"), "contents", METADATA),
    # --- Metadata: readable with any block, including an empty one ----------
    ((), METADATA),
    (("topics",), METADATA),
    (("languages",), METADATA),
    (("license",), METADATA),
    (("events", "**"), METADATA),
    (("contributors",), METADATA),
)

# The literal first segments of every repo-scoped rule above. Used to tell
# `repos/$GITHUB_REPOSITORY/actions/workflows` -- where one variable stands for
# two segments -- from `repos/$OWNER/$NAME/actions/workflows`.
REPO_SUBRESOURCES = frozenset(
    rule[0][0] for rule in _RULES if rule[0] and rule[0][0] not in ("*", "**")
)

_API_HOSTS = ("api.github.com", "api.github.localhost")


def _is_dyn(segment: str) -> bool:
    return segment == DYN or "$" in segment or "{" in segment or segment == "*"


def split_path(raw: str) -> tuple[str, ...]:
    """Normalise an API path or URL into comparable segments.

    Unresolvable segments become DYN, which matches a wildcard and never a
    literal.
    """
    text = raw.strip().strip("'\"")
    for scheme in ("https://", "http://"):
        if text.startswith(scheme):
            text = text[len(scheme) :]
            host, _, rest = text.partition("/")
            if host in _API_HOSTS:
                text = rest
            elif rest.startswith("api/v3/"):  # GitHub Enterprise Server
                text = rest[len("api/v3/") :]
            elif _is_dyn(host):
                text = rest[len("api/v3/") :] if rest.startswith("api/v3/") else rest
            else:
                raise UnknownPath(raw, "not a GitHub API host")
            break
    text = text.split("?", 1)[0].split("#", 1)[0]
    segments = [s for s in text.strip("/").split("/") if s]
    return tuple(DYN if _is_dyn(s) else s for s in segments)


def _match(
    segments: tuple[str, ...], pattern: tuple[str, ...], loose: bool = False
) -> bool:
    """Does this path match this pattern?

    With ``loose``, an unresolved segment also matches a literal -- it asks
    "could this path match, for some value of the variable?" rather than "does
    it". The gap between the two answers is where the guessing would be, and
    `classify` refuses rather than guess.
    """
    i = 0
    for j, element in enumerate(pattern):
        if element == "**":
            return j == len(pattern) - 1
        if i >= len(segments):
            return False
        if element == "*":
            i += 1
            continue
        if segments[i] != element:
            if not (loose and segments[i] == DYN):
                return False
        i += 1
    return i == len(segments)


def _strip_repo(segments: tuple[str, ...], raw: str) -> tuple[str, ...]:
    """Drop `repos/owner/name`, allowing one variable to stand for `owner/name`."""
    rest = segments[1:]
    if len(rest) >= 2 and rest[0] == DYN and rest[1] in REPO_SUBRESOURCES:
        # repos/$GITHUB_REPOSITORY/actions/workflows
        return rest[1:]
    if len(rest) >= 2:
        return rest[2:]
    if len(rest) == 1 and rest[0] == DYN:
        # repos/$GITHUB_REPOSITORY -- the repository itself
        return ()
    raise UnknownPath(raw, "a repos/ path with no owner and name")


def _scope_for(rule: tuple, level: str) -> str:
    if len(rule) == 3:
        return rule[1] if level == WRITE else rule[2]
    return rule[1]


def classify(raw: str, method: str = "GET") -> Need:
    """The scope and level an API call needs. Raises UnknownPath if unsure."""
    level = READ if method.upper() in READ_METHODS else WRITE
    segments = split_path(raw)
    if not segments:
        raise UnknownPath(raw, "empty path")
    head = segments[0]

    if head == DYN:
        raise UnknownPath(raw, "the path is a variable, so nothing here can read it")

    if head == "repos":
        rest = _strip_repo(segments, raw)
        strict = next((i for i, r in enumerate(_RULES) if _match(rest, r[0])), None)
        loose = next(
            (i for i, r in enumerate(_RULES) if _match(rest, r[0], loose=True)), None
        )
        if loose is None:
            raise UnknownPath(raw, "no rule for this /repos path")
        if strict is None or loose < strict:
            # A variable sits where an earlier, narrower rule has a literal, so
            # the answer depends on what the variable holds. `actions/$X/...`
            # is the actions scope unless $X is `secrets` or `variables`, and
            # the difference is between a scope you can grant and one you
            # cannot. Answering the common case would be wrong exactly when it
            # matters.
            narrow = "/".join(_RULES[loose][0])
            raise UnknownPath(
                raw,
                f"a variable in the path could make this {narrow!r}, which needs "
                f"a different scope, so this cannot be read without running it",
            )
        rule = _RULES[strict]
        scope = _scope_for(rule, level)
        # A metadata-only read is always satisfied; a metadata "write" is not a
        # thing, so those rules always name a real scope.
        return Need(scope, READ if scope == METADATA else level)

    # Paths outside /repos. Short list on purpose: a workflow token is scoped
    # to one repository and most of these have the same answer every time.
    if head in ("rate_limit", "meta", "versions", "octocat", "zen", "installation"):
        return Need(METADATA, READ)
    if head in ("user", "users"):
        raise UnknownPath(
            raw, "a workflow token has no user, so no scope makes this call work"
        )
    if head == "orgs":
        rest = segments[1:]
        if len(rest) >= 2 and rest[1] == "packages":
            return Need("packages", level)
        return Need("organization-administration", level)
    if head == "graphql":
        raise UnknownPath(
            raw, "a GraphQL query's scopes are in the query body, which this does not read"
        )
    if head == "search":
        raise UnknownPath(raw, "search needs read on whatever it searches, which varies")
    raise UnknownPath(raw, "no rule for this path")

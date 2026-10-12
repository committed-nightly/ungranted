"""What a `uses:` step needs, for the actions whose answer is known.

The table is short and it is meant to stay short. An action not in it is not
assumed to need nothing -- it is reported as unrecognised, and it suppresses
every unused-scope finding for its job. That second part is the important one:
if a job grants `pull-requests: write` and runs an action we cannot read, the
honest answer is "we do not know whether that grant is used", not "it isn't".

`actions/github-script` is the exception, because its API calls are in the
workflow file. The script body is JavaScript and is not parsed as such; the
two shapes that account for nearly all real use are matched textually:

    github.rest.<namespace>.<method>(...)
    github.request('<METHOD> /<path>')

A namespace maps to a scope. A method name's prefix decides read or write.
"""

from __future__ import annotations

import re

from .scopes import READ, WRITE, Need

# action (without a version) -> the scopes it needs.
#
# Sourced from each action's own README. Where an action documents a
# permissions block, that block is what is recorded; where it documents none
# and calls no API, it is the empty tuple, which is a real answer and not the
# same as being absent from this table.
ACTION_NEEDS: dict[str, tuple[Need, ...]] = {
    "actions/checkout": (Need("contents", READ),),
    "actions/setup-python": (),
    "actions/setup-node": (),
    "actions/setup-go": (),
    "actions/setup-java": (),
    "actions/cache": (),
    "actions/cache/restore": (),
    "actions/cache/save": (),
    "actions/upload-pages-artifact": (),
    "actions/configure-pages": (Need("pages", WRITE),),
    "actions/deploy-pages": (Need("pages", WRITE), Need("id-token", WRITE)),
    "actions/attest-build-provenance": (
        Need("attestations", WRITE),
        Need("id-token", WRITE),
        Need("contents", READ),
    ),
    "actions/stale": (Need("issues", WRITE), Need("pull-requests", WRITE)),
    "actions/labeler": (Need("contents", READ), Need("pull-requests", WRITE)),
    "actions/dependency-review-action": (Need("contents", READ),),
    "actions/create-github-app-token": (),  # uses an app key, not GITHUB_TOKEN
    "github/codeql-action/init": (Need("security-events", WRITE), Need("contents", READ)),
    "github/codeql-action/analyze": (
        Need("security-events", WRITE),
        Need("contents", READ),
        Need("actions", READ),
    ),
    "github/codeql-action/upload-sarif": (Need("security-events", WRITE),),
    "peter-evans/create-pull-request": (Need("contents", WRITE), Need("pull-requests", WRITE)),
    "softprops/action-gh-release": (Need("contents", WRITE),),
    "dependabot/fetch-metadata": (Need("pull-requests", READ),),
    "docker/login-action": (),
    "docker/build-push-action": (),
}

# actions/github-script namespace -> scope.
_SCRIPT_NAMESPACES = {
    "actions": "actions",
    "pulls": "pull-requests",
    "issues": "issues",
    "checks": "checks",
    "repos": "contents",
    "git": "contents",
    "reactions": "issues",
    "codeScanning": "security-events",
    "dependabot": "dependabot-alerts",
    "orgs": "organization-administration",
}

# github.rest.repos.* methods whose scope is not contents.
_REPOS_OVERRIDES = {
    "createcommitstatus": "statuses",
    "listcommitstatusesforref": "statuses",
    "getcombinedstatusforref": "statuses",
    "createdeployment": "deployments",
    "createdeploymentstatus": "deployments",
    "listdeployments": "deployments",
    "getdeployment": "deployments",
    "createorupdateenvironment": "administration",
    "getallenvironments": "actions",
    "createwebhook": "administration",
    "listcollaborators": "metadata",
    "getpages": "pages",
    "createpagessite": "pages",
}

_WRITE_PREFIXES = (
    "create", "update", "delete", "add", "remove", "set", "merge", "lock",
    "unlock", "replace", "upload", "dismiss", "enable", "disable", "rerun",
    "cancel", "approve", "request", "transfer", "rename", "generate", "submit",
)

_REST_CALL = re.compile(r"github\s*\.\s*rest\s*\.\s*(\w+)\s*\.\s*(\w+)\s*\(")
_REQUEST_CALL = re.compile(
    r"""github\s*\.\s*request\s*\(\s*(['"`])\s*([A-Z]+)\s+([^'"`]+)\1""", re.S
)
_GRAPHQL_CALL = re.compile(r"github\s*\.\s*graphql\s*\(")

# OIDC. Not an api.github.com path, so nothing else here would see it.
_OIDC = re.compile(
    r"getIDToken|ACTIONS_ID_TOKEN_REQUEST_(?:URL|TOKEN)|core\.getIDToken", re.I
)
# Container registry pushes, which are the packages scope and nothing else.
_GHCR_PUSH = re.compile(r"(?:docker|podman|buildah)\s+push\s+\S*ghcr\.io", re.I)
_GHCR_PULL = re.compile(r"(?:docker|podman)\s+(?:pull|login)\s+\S*ghcr\.io", re.I)


def normalise_uses(uses: str) -> str:
    """`actions/checkout@v4` -> `actions/checkout`. Leaves local and docker refs."""
    return uses.split("@", 1)[0].strip()


def level_for_method_name(name: str) -> str:
    lowered = name.lower()
    return WRITE if lowered.startswith(_WRITE_PREFIXES) else READ


def script_needs(script: str) -> tuple[list[Need], list[str]]:
    """(needs, unresolved) for an `actions/github-script` body."""
    needs: list[Need] = []
    unresolved: list[str] = []

    for namespace, method in _REST_CALL.findall(script):
        level = level_for_method_name(method)
        if namespace == "repos" and method.lower() in _REPOS_OVERRIDES:
            needs.append(Need(_REPOS_OVERRIDES[method.lower()], level))
            continue
        scope = _SCRIPT_NAMESPACES.get(namespace)
        if scope is None:
            unresolved.append(f"github.rest.{namespace}.{method}")
            continue
        needs.append(Need(scope, level))

    for _, method, path in _REQUEST_CALL.findall(script):
        unresolved.append(f"request:{method} {path.strip()}")

    if _GRAPHQL_CALL.search(script):
        unresolved.append("github.graphql")

    if _OIDC.search(script):
        needs.append(Need("id-token", WRITE))

    return needs, unresolved


def shell_extras(script: str) -> list[Need]:
    """Needs visible in a shell script that are not API paths."""
    needs = []
    if _OIDC.search(script):
        needs.append(Need("id-token", WRITE))
    if _GHCR_PUSH.search(script):
        needs.append(Need("packages", WRITE))
    elif _GHCR_PULL.search(script):
        needs.append(Need("packages", READ))
    return needs

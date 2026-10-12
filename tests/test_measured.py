"""The scope table against what the API actually did.

`measured.tsv` is a status-code matrix taken off a real runner. This turns each
row back into a claim about `classify` and checks it. If someone adds a rule
from a documentation page and the docs are wrong, or GitHub changes what a
scope covers, this is the test that notices.

The matrix pins a path down to a scope family rather than to one scope, which
is all four columns can do. That is still enough to catch the mistakes worth
catching: calling something metadata when it needs contents, calling something
grantable when no key grants it, and the two paths in this table whose answer
is the opposite of the obvious one.
"""

from __future__ import annotations

import os

import pytest

from ungranted.scopes import (
    GRANTED_ONLY_BY_ALL,
    METADATA,
    SETTABLE,
    UNGRANTABLE,
    classify,
)

MATRIX = os.path.join(os.path.dirname(__file__), "measured.tsv")

# metadata, contents:read, contents+actions, read-all
COLUMNS = ("metadata", "contents", "actions", "all")


def rows():
    out = []
    with open(MATRIX, encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("#") or not line.strip("\t\n"):
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 5:
                continue
            path, *codes = parts
            out.append((path, dict(zip(COLUMNS, codes))))
    return out


def reached(code: str) -> bool:
    """Did the request get past authorisation?

    404 counts. `/repos/o/r/pages` under read-all is a 404 because this
    repository has no Pages site, which means the token was allowed to ask.
    """
    return code in ("200", "404")


def expected_family(codes: dict[str, str]) -> str:
    if codes["metadata"] != "-" and reached(codes["metadata"]):
        return METADATA
    if reached(codes["contents"]):
        return "contents"
    if reached(codes["actions"]):
        return "actions"
    if reached(codes["all"]):
        return "settable-or-all"
    return "ungrantable"


@pytest.mark.parametrize("path,codes", rows(), ids=lambda v: v if isinstance(v, str) else "")
def test_table_agrees_with_the_api(path, codes):
    full = f"repos/committed-nightly/ungranted/{path}".rstrip("/")
    need = classify(full, "GET")
    family = expected_family(codes)

    if family == METADATA:
        assert need.scope == METADATA, (
            f"{path} was readable with permissions: {{}}, so the table should say "
            f"metadata, not {need.scope}"
        )
    elif family in ("contents", "actions"):
        assert need.scope == family, (
            f"{path} first became readable under {family}, but the table says "
            f"{need.scope}"
        )
    elif family == "settable-or-all":
        assert need.scope != METADATA, f"{path} needed more than metadata"
        assert need.scope in SETTABLE or need.scope in GRANTED_ONLY_BY_ALL, (
            f"{path} was reachable under read-all, so the table must name a "
            f"scope a block can grant, or one read-all covers; it says {need.scope}"
        )
    else:
        assert need.scope in UNGRANTABLE, (
            f"{path} was still 403 under read-all, so no block grants it; the "
            f"table says {need.scope}, which would send someone to a key that "
            "cannot help"
        )
        assert need.scope not in GRANTED_ONLY_BY_ALL, (
            f"{path} is 403 under read-all, so it is not one of the scopes "
            "read-all covers"
        )


def test_the_matrix_was_actually_loaded():
    # A parametrised suite over an empty file passes silently, which is the
    # one way this test file could report green while checking nothing.
    assert len(rows()) >= 35


def test_the_two_surprising_rows_are_in_the_matrix():
    """The rows where the measurement contradicted the obvious reading."""
    table = dict(rows())
    # Listing git tags needs only metadata; listing releases does not.
    assert reached(table["tags"]["metadata"])
    assert not reached(table["releases"]["metadata"])
    assert classify("repos/o/r/tags").scope == METADATA
    assert classify("repos/o/r/releases").scope == "contents"
    # Environments are the actions scope, not an environment-shaped one.
    assert not reached(table["environments"]["contents"])
    assert reached(table["environments"]["actions"])
    assert classify("repos/o/r/environments").scope == "actions"

from __future__ import annotations

import pytest

from ungranted.scopes import METADATA, UnknownPath, classify, split_path


def test_a_full_url_is_the_same_as_a_path():
    assert classify("https://api.github.com/repos/o/r/pulls").scope == "pull-requests"
    assert classify("repos/o/r/pulls").scope == "pull-requests"
    assert classify("/repos/o/r/pulls/").scope == "pull-requests"


def test_a_query_string_is_not_part_of_the_path():
    assert classify("repos/o/r/issues?state=open&per_page=100").scope == "issues"


def test_the_method_decides_the_level():
    assert classify("repos/o/r/issues", "GET").level == "read"
    assert classify("repos/o/r/issues", "POST").level == "write"
    assert classify("repos/o/r/issues", "patch").level == "write"
    assert classify("repos/o/r/issues", "DELETE").level == "write"


def test_one_variable_can_stand_for_owner_and_name():
    # `repos/$GITHUB_REPOSITORY/actions/workflows` has four segments where the
    # real path has five. Splitting on / and counting gets this wrong.
    assert classify("repos/$GITHUB_REPOSITORY/actions/workflows").scope == "actions"
    assert classify("repos/${{ github.repository }}/pulls").scope == "pull-requests"
    assert classify("repos/$OWNER/$NAME/actions/workflows").scope == "actions"
    assert classify("repos/$GITHUB_REPOSITORY").scope == METADATA


def test_a_variable_in_the_resource_position_is_not_a_guess():
    # We cannot know what `$KIND` is, and the flattering answer is the one
    # that makes a workflow look fine until it runs.
    with pytest.raises(UnknownPath):
        classify("repos/o/r/$KIND")
    with pytest.raises(UnknownPath):
        classify("$ENDPOINT")
    with pytest.raises(UnknownPath):
        classify("repos/o/r/actions/$THING/extra")


def test_checks_and_statuses_share_a_prefix_and_not_a_scope():
    assert classify("repos/o/r/commits/abc123/check-runs").scope == "checks"
    assert classify("repos/o/r/commits/abc123/statuses").scope == "statuses"
    assert classify("repos/o/r/commits/abc123/status").scope == "statuses"
    # Anything else under commits/ is contents.
    assert classify("repos/o/r/commits/abc123").scope == "contents"


def test_read_and_write_can_want_different_scopes():
    assert classify("repos/o/r/collaborators", "GET").scope == METADATA
    assert classify("repos/o/r/collaborators/someone", "PUT").scope == "administration"
    assert classify("repos/o/r/forks", "GET").scope == METADATA
    assert classify("repos/o/r/forks", "POST").scope == "contents"


def test_the_parts_of_actions_that_are_not_the_actions_scope():
    assert classify("repos/o/r/actions/runs").scope == "actions"
    assert classify("repos/o/r/actions/variables").scope == "variables"
    assert classify("repos/o/r/actions/secrets/NAME").scope == "secrets"
    assert classify("repos/o/r/actions/permissions").scope == "administration"


def test_branch_protection_is_not_contents():
    assert classify("repos/o/r/branches").scope == "contents"
    assert classify("repos/o/r/branches/main").scope == "contents"
    assert classify("repos/o/r/branches/main/protection", "PUT").scope == "administration"


def test_graphql_and_search_say_why_they_cannot_be_read():
    with pytest.raises(UnknownPath, match="query body"):
        classify("graphql", "POST")
    with pytest.raises(UnknownPath, match="search"):
        classify("search/issues")


def test_a_workflow_token_has_no_user():
    with pytest.raises(UnknownPath, match="no user"):
        classify("user")


def test_a_host_that_is_not_the_api_is_not_an_api_path():
    with pytest.raises(UnknownPath, match="not a GitHub API host"):
        classify("https://example.com/repos/o/r/pulls")


def test_split_path_marks_unresolvable_segments():
    segments = split_path("repos/o/$R/contents/file")
    assert segments[0] == "repos"
    assert segments[2] != "$R"  # normalised, not left as text
    assert segments[-1] == "file"


def test_the_settable_list_matches_actionlint():
    """The one list that has a second authority to check against.

    actionlint 1.7.12 prints every scope it will accept when it rejects one.
    If these two disagree, one of us is telling people to write a key GitHub
    will not take, or rejecting one it will. The first draft of this table was
    missing `artifact-metadata` and `repository-projects`, which actionlint
    caught.
    """
    from ungranted.scopes import SETTABLE

    actionlint = {
        "actions", "artifact-metadata", "attestations", "checks", "contents",
        "deployments", "discussions", "id-token", "issues", "models",
        "packages", "pages", "pull-requests", "repository-projects",
        "security-events", "statuses",
    }
    assert set(SETTABLE) == actionlint
    assert METADATA not in SETTABLE  # implicit, and GitHub rejects the key


def test_reading_an_organisation_is_metadata_not_organisation_administration():
    """Measured, because the first version of this table got it backwards.

    `organization-administration` is in UNGRANTABLE, so classifying
    `GET /orgs/{org}` as needing it told anybody making this very ordinary
    call that no `permissions:` block could help and they needed a different
    token. `committed-nightly/logbook` makes exactly this call from a
    scheduled workflow and it has worked every day.

    The measurement is probe run 38191167921, where `orgs/committed-nightly`
    answered 200 under `permissions: actions: read` and again under
    `permissions: contents: read`. A block replaces the default grant rather
    than extending it, and metadata is the only scope a block cannot remove,
    so a 200 under a block that names an unrelated scope means metadata was
    sufficient.
    """
    assert classify("orgs/committed-nightly", "GET").scope == METADATA
    assert classify("https://api.github.com/orgs/x", "GET").scope == METADATA

    # Still not a licence for the rest of the org API. Changing the
    # organisation, and its sub-resources, were not measured and stay as they
    # were -- the fix is to one path, not to a family.
    assert classify("orgs/x", "PATCH").scope == "organization-administration"
    assert classify("orgs/x/members", "GET").scope == "organization-administration"
    assert classify("orgs/x/packages", "GET").scope == "packages"

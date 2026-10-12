from __future__ import annotations

from ungranted.calls import (
    TOKEN_NONE,
    TOKEN_OTHER,
    TOKEN_WORKFLOW,
    classify_token_value,
    command_words,
    commands,
    mask_expressions,
    parse_curl,
    parse_gh_api,
    strip_heredocs,
)


def argv(line: str) -> list[str]:
    masked, _ = mask_expressions(line)
    return commands(masked)[0]


def test_a_field_makes_it_a_post_with_no_dash_x_anywhere():
    # gh switches method as soon as a parameter is given. This is the one that
    # turns a read grant into a 403 without anything in the line looking like
    # a write.
    path, method, _ = parse_gh_api(argv("gh api repos/o/r/statuses/abc -f state=success"))
    assert (path, method) == ("repos/o/r/statuses/abc", "POST")
    path, method, _ = parse_gh_api(argv("gh api repos/o/r/issues -F number=1"))
    assert method == "POST"
    path, method, _ = parse_gh_api(argv("gh api repos/o/r/issues --input body.json"))
    assert method == "POST"


def test_an_explicit_method_beats_the_body_flag():
    _, method, _ = parse_gh_api(argv("gh api repos/o/r/issues -X GET -f a=b"))
    assert method == "GET"
    _, method, _ = parse_gh_api(argv("gh api repos/o/r/issues --method=PATCH"))
    assert method == "PATCH"


def test_the_path_is_not_the_first_argument():
    # `gh api -X GET <path>`: argv[2] is "GET".
    path, method, _ = parse_gh_api(argv("gh api -X GET repos/o/r/pulls"))
    assert (path, method) == ("repos/o/r/pulls", "GET")
    path, _, _ = parse_gh_api(argv("gh api --paginate -H 'Accept: x' repos/o/r/pulls"))
    assert path == "repos/o/r/pulls"
    path, _, _ = parse_gh_api(argv("gh api -q .total_count repos/o/r/actions/workflows"))
    assert path == "repos/o/r/actions/workflows"


def test_a_jq_filter_is_not_mistaken_for_the_path():
    path, _, _ = parse_gh_api(argv("gh api repos/o/r/pulls --jq '.[].number'"))
    assert path == "repos/o/r/pulls"


def test_expressions_survive_quoting_of_their_own():
    masked, mapping = mask_expressions("echo ${{ fromJSON('[\"a\"]')[0] }} done")
    assert "fromJSON" not in masked
    assert len(mapping) == 1
    # And the masked text is still one shell word, so shlex can tokenise it.
    assert len(commands(masked)[0]) == 3


def test_comments_are_not_commands():
    found = [c[0] for c in commands("# gh api repos/o/r/pulls\necho hi")]
    assert found == ["echo"]
    # A # inside a word is not a comment.
    assert commands("echo a#b")[0] == ["echo", "a#b"]


def test_heredoc_bodies_are_data():
    script = """python - <<'PY'
gh api repos/o/r/pulls
import json
PY
echo after
"""
    stripped = strip_heredocs(script)
    assert "import json" not in stripped
    assert "echo after" in stripped
    assert "python" in stripped
    found = [c[0] for c in commands(stripped)]
    assert "gh" not in found
    assert found == ["python", "echo"]


def test_leading_assignments_and_keywords_are_stripped():
    assert command_words(["CODE=0", "gh", "pr", "list"])[0] == "gh"
    assert command_words(["if", "gh", "pr", "list"])[0] == "gh"
    assert command_words(["sudo", "CODE=1", "curl", "x"])[0] == "curl"
    assert command_words(["CODE=0"]) == []


def test_operators_separate_commands():
    found = [c[0] for c in commands("echo a && gh pr list | wc -l; curl x")]
    assert found == ["echo", "gh", "wc", "curl"]


def test_a_quoted_operator_is_not_an_operator():
    assert commands("echo 'a && b'")[0] == ["echo", "a && b"]


def test_curl_finds_the_url_the_method_and_the_headers():
    url, method, headers = parse_curl(
        argv(
            "curl -sS -X POST -H 'Authorization: Bearer $GITHUB_TOKEN' "
            "-H 'Accept: application/vnd.github+json' "
            "https://api.github.com/repos/o/r/issues -d '{}'"
        )
    )
    assert url == "https://api.github.com/repos/o/r/issues"
    assert method == "POST"
    assert any(h.startswith("Authorization") for h in headers)


def test_curl_data_implies_post():
    _, method, _ = parse_curl(argv("curl -d name=x https://api.github.com/repos/o/r/labels"))
    assert method == "POST"


def test_a_url_after_a_value_flag_is_not_the_url():
    url, _, _ = parse_curl(
        argv("curl -o https://decoy.example/out https://api.github.com/repos/o/r/pulls")
    )
    assert url == "https://api.github.com/repos/o/r/pulls"


def test_token_values_are_told_apart():
    assert classify_token_value("${{ secrets.GITHUB_TOKEN }}") == TOKEN_WORKFLOW
    assert classify_token_value("${{ github.token }}") == TOKEN_WORKFLOW
    assert classify_token_value("${{ secrets.RELEASE_PAT }}") == TOKEN_OTHER
    assert classify_token_value("") == TOKEN_NONE
    assert classify_token_value("hunter2") == TOKEN_NONE

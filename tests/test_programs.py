"""Reading the API calls out of a program a step runs.

The cases that earn their keep are the indirect ones. A program whose
`subprocess.run` names a literal path is the easy half and is tested here for
completeness; the half that matters is `ledger.py`'s shape, where the argv is
assembled in one wrapper function and every path lives at its call sites, and
`rerun-dead-shift.py`'s shape, where the URL is an f-string over a base that
only exists at runtime.
"""

from __future__ import annotations

import textwrap

from ungranted.programs import (
    Program,
    console_scripts,
    find_wrappers,
    read_program,
    render,
    repo_root,
    resolve_command,
    scan_module,
)

import ast


def scan(source: str, module: str = "prog.py") -> Program:
    source = textwrap.dedent(source)
    tree = ast.parse(source)
    out = Program(entry=module)
    wrappers = find_wrappers(tree, module)
    scan_module(source, module, out, wrappers)
    return out


def needs(program: Program) -> list[tuple[str, str]]:
    return sorted({(n.scope, n.level) for call in program.calls for n in call.needs})


def shown(program: Program) -> list[str]:
    return [call.shown for call in program.calls]


# --------------------------------------------------------------------------
# direct argvs
# --------------------------------------------------------------------------


def test_a_literal_gh_api_argv_is_read():
    out = scan(
        """
        import subprocess
        subprocess.run(["gh", "api", "repos/o/r/actions/workflows"])
        """
    )
    assert needs(out) == [("actions", "read")]
    assert out.read


def test_a_write_method_is_taken_from_the_flag():
    out = scan(
        """
        import subprocess
        subprocess.run(["gh", "api", "-X", "POST", "repos/o/r/issues/1/comments"])
        """
    )
    assert needs(out) == [("issues", "write")]


def test_an_argv_whose_head_is_not_gh_is_not_an_api_call():
    """The binary is traced, not guessed from the shape of the list."""
    out = scan(
        """
        import subprocess
        subprocess.run(["git", "api", "repos/o/r/actions/workflows"])
        """
    )
    assert out.calls == []
    assert out.read


def test_the_binary_is_traced_through_shutil_which():
    """`exe = shutil.which(gh)` with `gh="gh"` is how ledger.py spells it."""
    out = scan(
        """
        import shutil, subprocess
        def call(args, gh="gh"):
            exe = shutil.which(gh)
            subprocess.run([exe, *args])
        call(["api", "repos/o/r/branches/main"])
        """
    )
    assert needs(out) == [("contents", "read")]


def test_a_gh_subcommand_is_read_as_well_as_gh_api():
    out = scan(
        """
        import subprocess
        subprocess.run(["gh", "run", "rerun", "12"])
        """
    )
    assert needs(out) == [("actions", "write")]


# --------------------------------------------------------------------------
# wrappers: the shape that matters
# --------------------------------------------------------------------------

LEDGER_SHAPE = """
    import shutil, subprocess

    def gh_json(args, gh="gh"):
        exe = shutil.which(gh)
        return subprocess.run([exe, *args], capture_output=True)

    def workflows(org, name):
        return gh_json(["api", f"repos/{org}/{name}/actions/workflows"])

    def pulls(org, name):
        path = f"repos/{org}/{name}/pulls"
        return gh_json(["api", "-X", "GET", path, "-f", "state=all"])
"""


def test_a_wrapper_is_found_and_its_call_sites_are_read():
    out = scan(LEDGER_SHAPE)
    assert needs(out) == [("actions", "read"), ("pull-requests", "read")]
    assert out.read


def test_an_f_string_path_keeps_its_literal_segments():
    """The substitutions are unknowable; the segments around them are not."""
    out = scan(LEDGER_SHAPE)
    assert "gh api repos/{}/{}/actions/workflows" in shown(out)


def test_a_path_held_in_a_local_variable_is_traced():
    """`path = f"..."` one line above the call. Without this, pulls() is unread."""
    out = scan(LEDGER_SHAPE)
    assert "gh api repos/{}/{}/pulls" in shown(out)


def test_a_name_assigned_twice_is_not_traced():
    """Two assignments have two answers, and the last one is not a fact."""
    out = scan(
        """
        import subprocess
        def gh_json(args, gh="gh"):
            subprocess.run([gh, *args])
        def go(flag):
            path = "repos/o/r/pulls"
            path = "repos/o/r/actions/workflows"
            gh_json(["api", path])
        """
    )
    assert out.calls == []
    assert [u.reason for u in out.unreadable] == [
        "the endpoint is a variable this could not trace"
    ]


def test_a_spliced_argument_list_is_reported_not_guessed():
    out = scan(
        """
        import subprocess
        def gh_json(args, gh="gh"):
            subprocess.run([gh, *args])
        def go(extra):
            gh_json(["api", "repos/o/r/pulls", *extra])
        """
    )
    assert out.calls == []
    assert not out.read
    assert "partly spliced" in out.unreadable[0].reason


def test_a_call_site_passing_a_variable_list_is_reported():
    out = scan(
        """
        import subprocess
        def gh_json(args, gh="gh"):
            subprocess.run([gh, *args])
        def go(argv):
            gh_json(argv)
        """
    )
    assert not out.read
    assert "not a list written here" in out.unreadable[0].reason


def test_a_method_wrapper_is_named_rather_than_silently_skipped(tmp_path):
    """greenwash's shape. `transport.get(...)` and `body.get(...)` are spelled
    the same, so the callers are not attributed -- but the entry point is.

    Goes through read_program because naming the wrapper is its job: the
    module scan cannot know whether a later module resolves the callers.
    """
    (tmp_path / "t.py").write_text(
        textwrap.dedent(
            """
            import subprocess
            from dataclasses import dataclass

            @dataclass
            class GhTransport:
                gh: str = "gh"

                def get(self, path):
                    return subprocess.run([self.gh, "api", "-H", "Accept: x", path])
            """
        )
    )
    out = read_program(["./t.py"], str(tmp_path))
    assert out is not None and not out.read
    gap = out.unreadable[0]
    assert gap.shown == "GhTransport.get()"
    assert "callers" in gap.reason


def test_a_wrappers_own_argv_is_not_read_as_a_call_site():
    """The `subprocess.run` inside gh_json names no path. Reporting its
    `*args` as an unreadable endpoint would make every wrapper-shaped program
    blind for a reason that is not true of it."""
    out = scan(LEDGER_SHAPE)
    assert out.read
    assert out.unreadable == []


# --------------------------------------------------------------------------
# urllib
# --------------------------------------------------------------------------


def test_a_urllib_post_over_a_variable_base_is_read_as_a_write():
    """rerun-dead-shift.py's shape. No method= anywhere: urllib turns a request
    with a body into a POST, and that is the difference between actions: read
    and actions: write."""
    out = scan(
        """
        import urllib.request
        def rerun(api_base, token, repository, run_id):
            return urllib.request.Request(
                f"{api_base}/repos/{repository}/actions/runs/{run_id}/rerun",
                data=b"{}",
                headers={"Authorization": f"Bearer {token}"},
            )
        """
    )
    assert needs(out) == [("actions", "write")]


def test_an_explicit_method_beats_the_presence_of_a_body():
    out = scan(
        """
        import urllib.request
        def go(base, repo):
            return urllib.request.Request(
                f"{base}/repos/{repo}/pulls", data=b"{}", method="GET"
            )
        """
    )
    assert needs(out) == [("pull-requests", "read")]


def test_another_api_on_a_variable_base_is_not_read_as_github():
    """The same function in the same file posts to Slack over the same kind of
    base. The base cannot be known here, so the shape of what follows decides,
    and `chat.postMessage` matches no rule in the scope table."""
    out = scan(
        """
        import urllib.request
        def post(api_base, channel):
            return urllib.request.Request(
                f"{api_base}/chat.postMessage", data=b"{}"
            )
        """
    )
    assert out.calls == []
    assert out.read


def test_an_absolute_github_url_is_read():
    out = scan(
        """
        import urllib.request
        urllib.request.urlopen("https://api.github.com/repos/o/r/releases")
        """
    )
    assert needs(out) == [("contents", "read")]


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------


def test_render_turns_what_it_cannot_evaluate_into_a_brace():
    def rendered(expression: str) -> str:
        return render(ast.parse(expression, mode="eval").body)

    assert rendered('"repos/o/r/pulls"') == "repos/o/r/pulls"
    assert rendered('f"repos/{org}/{name}/pulls"') == "repos/{}/{}/pulls"
    assert rendered('"repos/" + owner + "/r"') == "repos/{}/r"
    assert rendered('"repos/%s/pulls" % owner') == "repos/{}/pulls"
    assert rendered('"repos/{}/pulls".format(owner)') == "repos/{}/pulls"
    assert rendered("something(1)") == "{}"


# --------------------------------------------------------------------------
# resolving a command to a file
# --------------------------------------------------------------------------


def test_resolve_finds_a_script_named_directly(tmp_path):
    (tmp_path / "ledger.py").write_text("x = 1\n")
    assert resolve_command(["./ledger.py", "orphans"], str(tmp_path)) == str(
        tmp_path / "ledger.py"
    )


def test_resolve_finds_a_script_given_to_an_interpreter(tmp_path):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "x.py").write_text("x = 1\n")
    found = resolve_command(["python3", "scripts/x.py", "--flag"], str(tmp_path))
    assert found == str(tmp_path / "scripts" / "x.py")


def test_resolve_finds_a_console_script_through_pyproject(tmp_path):
    """The entry point does not exist as a file in a checkout, so the name has
    to come back through [project.scripts]."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "greenwash"\n\n'
        '[project.scripts]\ngreenwash = "greenwash.cli:main"\n'
    )
    pkg = tmp_path / "src" / "greenwash"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "cli.py").write_text("x = 1\n")
    assert console_scripts(str(tmp_path)) == {"greenwash": "greenwash.cli"}
    assert resolve_command(["greenwash", "--all"], str(tmp_path)) == str(pkg / "cli.py")


def test_resolve_declines_anything_it_cannot_find(tmp_path):
    """The honest answer for `claude` or `node build.js`: the step stays
    opaque and its job stays blind, which is the behaviour this replaced."""
    assert resolve_command(["claude", "-p", "go"], str(tmp_path)) is None
    assert resolve_command(["node", "build.js"], str(tmp_path)) is None
    assert resolve_command([], str(tmp_path)) is None


def test_a_package_is_read_whole_rather_than_by_following_imports(tmp_path):
    """The entry point here calls nothing; the API call is in a sibling."""
    (tmp_path / "pyproject.toml").write_text(
        '[project.scripts]\nt = "t.cli:main"\n'
    )
    pkg = tmp_path / "src" / "t"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "cli.py").write_text("from . import api\n")
    (pkg / "api.py").write_text(
        "import subprocess\n"
        'subprocess.run(["gh", "api", "repos/o/r/actions/workflows"])\n'
    )
    program = read_program(["t"], str(tmp_path))
    assert program is not None
    assert needs(program) == [("actions", "read")]


def test_repo_root_is_the_directory_above_dot_github():
    assert repo_root("/w/repo/.github/workflows/ci.yml") == "/w/repo"
    assert repo_root("/w/repo/examples/under.yaml") is None


def test_a_file_that_will_not_parse_is_reported(tmp_path):
    (tmp_path / "bad.py").write_text("def (:\n")
    program = read_program(["./bad.py"], str(tmp_path))
    assert program is not None
    assert not program.read
    assert "will not parse" in program.unreadable[0].reason

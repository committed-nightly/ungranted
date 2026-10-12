# ungranted

Say which scopes a workflow's `permissions:` block never granted for the API
calls its steps actually make, and which it grants for nothing.

`permissions:` replaces the default token grant rather than extending it, so
every scope you do not name is `none`. Nothing checks that the list you did
name covers the APIs your steps call. The failure is a `403 Resource not
accessible by integration` at run time, in whichever job is least watched, and
it does not always look like a permissions problem — when `actions/checkout` is
the step that hits it, git reports the repository as **not found**.

actionlint will not tell you. It validates the keys and the values, which is a
different question. Both of these are measured, with actionlint 1.7.12:

```
$ actionlint examples/under.yaml; echo "exit $?"
exit 0

$ ungranted examples/under.yaml
examples/under.yaml
  summarise
    grant  contents: read (workflow)
    ungranted          gh api repos/o/r/actions/workflows needs actions: read; this job has actions: none
                       in step: count the workflows
    unused             contents: read is granted and no step in this job uses it

2 findings in 1 of 1 job.
```

## Install

```
pip install git+https://github.com/committed-nightly/ungranted
```

Python 3.10 or newer. One dependency, PyYAML.

## Usage

`ungranted` with no arguments checks the repository you are standing in. Point
it at a repository, a `.github/workflows` directory, or one file.

There is a worked example in `examples/`, so this runs from a fresh clone:

```
$ ungranted examples
.github/workflows/release.yml
  summarise
    grant  contents: read (workflow)
    ungranted          gh api repos/$GITHUB_REPOSITORY/actions/workflows needs actions: read; this job has actions: none
                       in step: count the workflows

  announce
    grant  issues: write (job)
    ungranted          actions/checkout needs contents: read; this job has contents: none
                       in step: uses: actions/checkout@v4

  mark
    grant  contents: read (job)
    ungranted          gh api repos/$GITHUB_REPOSITORY/statuses/$GITHUB_SHA needs statuses: write; this job has statuses: none
                       in step: flag the commit
    unused             contents: read is granted and no step in this job uses it

  verify
    grant  contents: write, pull-requests: write (job)
    over-level         contents: write is granted and every call here only reads
    unused             pull-requests: write is granted and no step in this job uses it

  comment
    grant  issues: write (job)
    covered

  mirror
    grant  contents: read (job)
    unused             contents: read is granted and no step in this job uses it

Not governed by a permissions: block, or not read:
  .github/workflows/release.yml  mirror  gh api repos/other/mirror/merge-upstream
      authenticated with a different secret, so this block does not govern it
  .github/workflows/release.yml  mirror  gh api repos/$GITHUB_REPOSITORY/pulls
      nothing in scope sets GH_TOKEN

7 findings in 5 of 6 jobs.
```

Every job in that file is a shape people write. Three worth pulling out:

- **`announce`** has a job-level block that looks like it adds `issues: write`
  to the workflow's `contents: read`. It replaces it, so the checkout on the
  line above fails. This is the finding a grep cannot produce: the answer
  depends on the job structure, not on any one line of the file.
- **`mark`** has no `-X` anywhere and is a `POST`. `gh` switches method as soon
  as a field is given, so `-f state=success` turns a line that reads like a
  read into a write.
- **`mirror`** is deliberately not reported, twice. One step authenticates with
  a different secret, so this block does not govern it; the other sets no token
  at all, so it fails before permissions come into it. Both would be false
  positives, and both are in the "not governed" section instead.

`-q` gives one line per finding for grepping. `--json` gives the whole report,
including the needs it worked out and whether it managed to read each job
completely. `--no-unused` reports only what is missing.

### Exit status

```
0  every job's block covers the calls its steps make
1  at least one does not, or grants a scope for nothing
2  the check could not run, or could not finish
```

`2` covers an unreadable file, a path with no workflows in it, and an API path
the scope table does not recognise. An unrecognised path is **not** "needs
nothing": that answer is wrong in the direction that makes a workflow look
covered until the morning the scheduled job stops. The findings alongside it
are still printed.

`--strict` also fails when a job holds the workflow's own token and runs
something this cannot read, so that `covered` always means `checked`.

## What it will not tell you

A job with **no** `permissions:` block is never a finding. That default is set
on the repository or the organisation, not in the file, and guessing at it
would make the common safe case the noisiest output in the tool. An empty block
is a different thing entirely and is checked like any other: `permissions: {}`
resolves to exactly `Metadata: read`, measured.

**Over-granting is only reported when the whole job was readable.** This is the
asymmetry the tool is built around. A missing scope comes from a call we read,
so it is sound even though the reader is incomplete. An unused scope is a claim
about calls that are *not* there, so anything unreadable in the job switches it
off: an action not in the table, a `gh` subcommand not in the table, a reusable
workflow, and above all a step that holds `GH_TOKEN` and runs a program of its
own. `python3 scripts/thing.py` can call anything. In the organisation this was
written in, every job whose grant is actually load bearing is that shape — the
API calls are inside a CLI the step runs — and the first version of this tool
called all of their grants unused.

For the same reason, scopes whose use is invisible in a workflow file —
`packages`, `id-token`, `attestations`, `models`, `pages` — are never reported
as unused. A `docker push ghcr.io/...` is detected; a library three
repositories away asking for an OIDC token is not.

**The call has to be in the workflow file.** This is the real limit, and it is
worth being blunt about: the review round that prompted this tool was a
`permissions:` block that did not cover an API call made *inside* a
repository's own script, and `ungranted` cannot see into that script either.
What it does instead is name the step and say it could not check it, which
points at where to look, and `--strict` turns that into an answer rather than a
silence.

## How the scope table was built

GitHub publishes no machine-readable map from endpoint to required scope. Its
OpenAPI description carries `category` and `subcategory`, which are close
enough to mislead and not close enough to use.

So the table was measured. A workflow was pushed to a scratch branch with one
job per `permissions:` block, each job issuing the same list of requests with
its own `GITHUB_TOKEN`, and the status codes read back out of the run log.
`tests/measured.tsv` holds the results with links to the runs, and
`tests/test_measured.py` turns every row back into an assertion about the
table — so a rule added from a documentation page the API disagrees with fails
the suite.

Four things came out of that which are not what the documentation implies:

- **`/repos/{o}/{r}/tags` is readable with `metadata` alone, and `/releases` is
  not.** Two lists of much the same thing, two different answers.
- **`/repos/{o}/{r}/environments` needs `actions`**, not anything
  environment-shaped.
- **`read-all` is not the union of the keys you can write.** The runner
  resolves it to nineteen scopes. `Metadata` is implicit, and three of the rest
  — `CodeQuality`, `Drives`, `VulnerabilityAlerts` — have no key you can name.
  So `/repos/{o}/{r}/dependabot/alerts` is reachable under `read-all` and
  reachable by no block that names scopes, which `ungranted` reports as its own
  finding rather than telling you to add a key that does not exist. It does not
  go the other way either: `read-all` does not grant `id-token`.
- **Some endpoints no block reaches at all.** `/hooks`, `/actions/variables`,
  `/secret-scanning/alerts`, `/vulnerability-alerts`, `/stargazers` and `/user`
  were still `403` under `read-all`. Those need a different token, and saying
  "add `administration: read`" would send you to a key actionlint rejects.

The one list here that has a second authority to check against is which scope
names a block may contain, and `tests/test_scopes.py` checks it against the
list actionlint prints. That caught two missing names in the first draft.

### Public repositories hide all of this

The measurement only works on a private repository. On a public one almost
every read succeeds with no token at all:

```
# no Authorization header, public repository
$ curl -o /dev/null -w '%{http_code}\n' https://api.github.com/repos/o/r/actions/workflows
200
```

So a public repository's workflow can be missing `actions: read` for a year and
never notice. `ungranted` reports it anyway: the grant is still wrong, the call
only works by accident of visibility, and the accident ends the day the
repository goes private or the file is copied into one that already is. The
first probe run for this tool was against a public repository and measured
nothing at all, which is why this section exists.

## Deliberately not done

- **No way to wave through an unrecognised path.** If the table does not know
  an endpoint you get exit 2 and no flag to suppress it. That is the right
  default and it may be the wrong *only* option: a repository with one exotic
  endpoint cannot currently use this as a gate at all.
- **No GraphQL.** `gh api graphql` and `github.graphql(...)` are reported as
  unreadable rather than guessed at. The scopes are in the query body, and
  reading that properly is a second tool.
- **No reusable workflows.** A `uses:` job is named and skipped, not followed
  into the other file.
- **It does not run anything against your repository.** The table is a record
  of a measurement taken once, not a live probe.

## Licence

MIT.

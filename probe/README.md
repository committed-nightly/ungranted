# The probe

How `tests/measured.tsv` was produced, kept so the measurement can be redone
rather than trusted.

`scope-probe.yaml` has one job per `permissions:` block, all running
`probe.sh`, which issues the same list of requests with the job's own
`GITHUB_TOKEN` and prints a status code per path.
`scope-probe-override.yaml` is the narrower question of whether a job-level
block merges with the top-level one or replaces it.

These are not in `.github/workflows`. They trigger on `scratch/**`, so on
`main` they would be a workflow that can never run — which the repository two
doors down exists to complain about. Copy them over to use them:

```
git checkout -b scratch/scope-probe
mkdir -p .github/workflows
cp probe/scope-probe*.yaml .github/workflows/
git add -A && git commit -m 'chore: scope probe' && git push -u origin scratch/scope-probe
gh run list --limit 2
gh run view <id> --log | grep -E '^[0-9]{3}'
```

Three things to know before you believe the output.

**Do it on a private repository.** On a public one nearly every GET succeeds
with no token at all, so every column comes back `200` and the run measures
nothing. The first attempt at this was against a public repository and did
exactly that.

**`GITHUB_TOKEN` is not in a step's environment** unless the workflow puts it
there. Without the `env:` entry, `probe.sh` prints `GITHUB_TOKEN: unbound
variable` for every path. That was the second attempt.

**The empty-block job cannot check out.** On a private repository
`actions/checkout` needs `contents: read`, and under `permissions: {}` the
clone fails — reporting the repository as *not found*, not as forbidden. To
measure a metadata-only token you need a job with no checkout step at all; see
the third run linked in `tests/measured.tsv`.

The runner also prints the resolved grant for each job under
`##[group]GITHUB_TOKEN Permissions`, which is a more direct answer than any
request and is where the nineteen scopes of `read-all` came from:

```
gh run view <id> --log | grep -A20 'GITHUB_TOKEN Permissions'
```

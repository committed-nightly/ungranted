#!/usr/bin/env bash
# Ask the real API what this job's token can reach. One line per endpoint:
#   <http status> <tab> <path> <tab> <first line of any message>
set -uo pipefail
R="$GITHUB_REPOSITORY"
S="$GITHUB_SHA"
PATHS=(
  "repos/$R"
  "repos/$R/readme"
  "repos/$R/license"
  "repos/$R/languages"
  "repos/$R/topics"
  "repos/$R/contents/README.md"
  "repos/$R/commits"
  "repos/$R/commits/$S"
  "repos/$R/compare/$S...$S"
  "repos/$R/branches"
  "repos/$R/git/ref/heads/main"
  "repos/$R/git/trees/$S"
  "repos/$R/tags"
  "repos/$R/releases"
  "repos/$R/actions/workflows"
  "repos/$R/actions/runs"
  "repos/$R/actions/artifacts"
  "repos/$R/actions/caches"
  "repos/$R/actions/variables"
  "repos/$R/pulls"
  "repos/$R/issues"
  "repos/$R/issues/comments"
  "repos/$R/labels"
  "repos/$R/milestones"
  "repos/$R/commits/$S/check-runs"
  "repos/$R/commits/$S/check-suites"
  "repos/$R/commits/$S/statuses"
  "repos/$R/commits/$S/status"
  "repos/$R/deployments"
  "repos/$R/environments"
  "repos/$R/pages"
  "repos/$R/code-scanning/alerts"
  "repos/$R/dependabot/alerts"
  "repos/$R/secret-scanning/alerts"
  "repos/$R/vulnerability-alerts"
  "repos/$R/collaborators"
  "repos/$R/stargazers"
  "repos/$R/forks"
  "repos/$R/events"
  "repos/$R/hooks"
  "repos/$R/discussions"
  "orgs/committed-nightly"
  "user"
  "rate_limit"
)
echo "### $PROBE_LABEL"
for p in "${PATHS[@]}"; do
  body=$(mktemp)
  code=$(curl -sS -o "$body" -w '%{http_code}' \
    -H "Authorization: Bearer $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/$p")
  msg=$(jq -r '.message // ""' "$body" 2>/dev/null | head -1)
  # Collapse the commit sha so the lines are comparable between jobs.
  printf '%s\t%s\t%s\n' "$code" "${p//$S/SHA}" "$msg"
  rm -f "$body"
done

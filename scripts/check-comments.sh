#!/bin/sh
# check-comments.sh — block mechanically-forbidden Go comments on staged files.
#
# Enforces the subset of the comment policy (AGENTS.md) that can be detected
# without semantic analysis: decorative banner dividers and commented-out code.
# Doc comments, "why" comments, license headers, tooling directives and Swagger
# annotations (// @...) are intentionally NOT flagged.
#
# Scope: only staged *.go files (excluding generated code), so pre-existing
# debt in untouched files never blocks a commit.

set -eu

staged=$(git diff --cached --name-only --diff-filter=ACM \
  | grep -E '\.go$' \
  | grep -Ev '(\.pb\.go$|_gen\.go$|_mock\.go$|/mocks/)' || true)

[ -z "$staged" ] && exit 0

status=0
for file in $staged; do
  [ -f "$file" ] || continue

  # Banner / divider comments: a comment line made only of = or - runs.
  banners=$(grep -nE '^[[:space:]]*//[[:space:]]*[=-]{4,}[[:space:]]*$' "$file" || true)
  if [ -n "$banners" ]; then
    echo "FORBIDDEN banner divider in $file:"
    echo "$banners"
    status=1
  fi

  # Commented-out code heuristic: a // comment whose body looks like a Go
  # statement (assignment, call, or block close). Excludes directives and
  # Swagger annotations.
  codeish=$(grep -nE '^[[:space:]]*//[[:space:]]+([a-zA-Z_][a-zA-Z0-9_.]*[[:space:]]*(:=|=[^=])|[a-zA-Z_][a-zA-Z0-9_.]*\(|return |if |for |\}|func )' "$file" \
    | grep -Ev '//[[:space:]]*(@|go:|nolint|\+build|export |TODO|FIXME|NOTE|XXX|Deprecated)' || true)
  if [ -n "$codeish" ]; then
    echo "LIKELY commented-out code in $file (delete it — git remembers):"
    echo "$codeish"
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  echo ""
  echo "Comment policy violations found (see AGENTS.md 'Code comments policy')."
fi

exit "$status"

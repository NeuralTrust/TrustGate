#!/usr/bin/env bash
#
# Unit tests for the pure bump helpers in next-metrics-version.sh.
# Run: bash .github/scripts/next-metrics-version.test.sh
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=next-metrics-version.sh
source "$DIR/next-metrics-version.sh"

fail=0
assert_eq() {
	if [ "$1" != "$2" ]; then
		echo "FAIL: $3 — expected '$2', got '$1'"
		fail=1
	else
		echo "ok: $3"
	fi
}

assert_eq "$(compute_next 1.2.3 major)" "2.0.0" "major resets minor/patch"
assert_eq "$(compute_next 1.2.3 minor)" "1.3.0" "minor resets patch"
assert_eq "$(compute_next 1.2.3 patch)" "1.2.4" "patch increments"
assert_eq "$(compute_next v0.1.0 minor)" "0.2.0" "leading v is tolerated"

assert_eq "$(printf 'feat: add exporter\n' | detect_level)" "minor" "feat -> minor"
assert_eq "$(printf 'feat(metrics): scope\n' | detect_level)" "minor" "scoped feat -> minor"
assert_eq "$(printf 'fix: bug\n' | detect_level)" "patch" "fix -> patch"
assert_eq "$(printf 'chore: deps\n' | detect_level)" "patch" "chore -> patch"
assert_eq "$(printf 'feat!: drop column\n' | detect_level)" "major" "type! -> major"
assert_eq "$(printf 'refactor(metrics)!: rename\n' | detect_level)" "major" "scoped type! -> major"
assert_eq "$(printf 'fix: x\n\nBREAKING CHANGE: drops table\n' | detect_level)" "major" "breaking footer -> major"

if [ "$fail" -ne 0 ]; then
	echo "TESTS FAILED"
	exit 1
fi
echo "ALL TESTS PASSED"

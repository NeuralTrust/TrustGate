#!/usr/bin/env bash
#
# Unit tests for the pure helpers in metrics-compat-lib.sh (ENG-1033).
# Run: bash .github/scripts/metrics-compat-lib.test.sh
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=metrics-compat-lib.sh
source "$DIR/metrics-compat-lib.sh"

fail=0
assert_eq() {
	if [ "$1" != "$2" ]; then
		echo "FAIL: $3 — expected '$2', got '$1'"
		fail=1
	else
		echo "ok: $3"
	fi
}

# mc_select_latest_tag
assert_eq "$(printf 'pkg/metrics/v0.1.0\npkg/metrics/v0.10.0\npkg/metrics/v0.2.0\n' | mc_select_latest_tag)" \
	"pkg/metrics/v0.10.0" "select_latest_tag picks highest semver"
assert_eq "$(printf '' | mc_select_latest_tag)" "" "select_latest_tag empty list -> empty"

# mc_apidiff_incompatible
assert_eq "$(printf '' | mc_apidiff_incompatible)" "false" "apidiff empty -> false"
assert_eq "$(printf '\n  \n' | mc_apidiff_incompatible)" "false" "apidiff whitespace -> false"
assert_eq "$(printf -- '- Metadata: removed\n' | mc_apidiff_incompatible)" "true" "apidiff entry -> true"

# mc_parse_schema_version
assert_eq "$(printf 'package metrics\n\nconst SchemaVersion = 1\n' | mc_parse_schema_version)" \
	"1" "parse_schema_version reads constant"
assert_eq "$(printf 'const SchemaVersion = 42\n' | mc_parse_schema_version)" "42" "parse_schema_version multi-digit"
assert_eq "$(printf 'package metrics\n' | mc_parse_schema_version)" "" "parse_schema_version missing -> empty"

# mc_has_breaking_marker
assert_eq "$(printf 'feat: add field\n' | mc_has_breaking_marker)" "false" "marker feat -> false"
assert_eq "$(printf 'fix!: drop column\n' | mc_has_breaking_marker)" "true" "marker type! -> true"
assert_eq "$(printf 'refactor(metrics)!: rename\n' | mc_has_breaking_marker)" "true" "marker scoped type! -> true"
assert_eq "$(printf 'fix: x\n\nBREAKING CHANGE: drops table\n' | mc_has_breaking_marker)" "true" "marker footer -> true"

# mc_gomod_dependency_light
assert_eq "$(printf 'module m\n\ngo 1.26\n' | mc_gomod_dependency_light)" "true" "gomod bare -> true"
assert_eq "$(printf 'module m\n\ngo 1.26\n\nrequire foo v1.0.0\n' | mc_gomod_dependency_light)" "false" "gomod single require -> false"
assert_eq "$(printf 'module m\n\nrequire (\n\tfoo v1.0.0\n)\n' | mc_gomod_dependency_light)" "false" "gomod require block -> false"
assert_eq "$(printf 'module m\n\nreplace a => b v1.0.0\n' | mc_gomod_dependency_light)" "false" "gomod replace -> false"
assert_eq "$(printf 'module m\n\nrequire (\n\tfoo v1.0.0 // indirect\n)\n' | mc_gomod_dependency_light)" "false" "gomod indirect -> false"

# mc_changed_touches_metrics
assert_eq "$(printf 'README.md\npkg/metrics/version.go\n' | mc_changed_touches_metrics)" "true" "changed touches metrics -> true"
assert_eq "$(printf 'README.md\npkg/app/foo.go\n' | mc_changed_touches_metrics)" "false" "changed elsewhere -> false"
assert_eq "$(printf '' | mc_changed_touches_metrics)" "false" "changed empty -> false"

# mc_gate_decision
assert_eq "$(mc_gate_decision false __bootstrap__ 1 false)" "pass" "gate bootstrap -> pass"
assert_eq "$(mc_gate_decision false 1 '' false)" "fail:cannot parse SchemaVersion at HEAD" "gate unparseable head -> fail"
assert_eq "$(mc_gate_decision true '' 1 false)" "pass" "gate unknown base -> pass"
assert_eq "$(mc_gate_decision false 2 1 false)" "fail:SchemaVersion decreased (2 -> 1)" "gate decrease -> fail"
assert_eq "$(mc_gate_decision true 1 1 false)" "fail:incompatible API change without a SchemaVersion bump or breaking-change marker" "gate silent break -> fail"
assert_eq "$(mc_gate_decision true 1 2 false)" "pass" "gate break with version bump -> pass"
assert_eq "$(mc_gate_decision true 1 1 true)" "pass" "gate break with marker -> pass"
assert_eq "$(mc_gate_decision false 1 1 false)" "pass" "gate compatible same version -> pass"

# mc_gate_decision exit codes
mc_gate_decision false 1 2 false >/dev/null
assert_eq "$?" "0" "gate pass exit 0"
mc_gate_decision true 1 1 false >/dev/null
assert_eq "$?" "1" "gate fail exit 1"

if [ "$fail" -ne 0 ]; then
	echo "TESTS FAILED"
	exit 1
fi
echo "ALL TESTS PASSED"

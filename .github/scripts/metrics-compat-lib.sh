# shellcheck shell=bash
#
# Pure helpers for the pkg/metrics compatibility gate (ENG-1033). Every function
# reads from stdin or arguments and writes a decision to stdout; none touch git,
# the filesystem, or apidiff. The orchestrator (metrics-compat-gate.sh) wires
# these to real inputs; the unit tests (metrics-compat-lib.test.sh) exercise them
# in isolation. Source this file; it defines functions only and has no main.

# mc_select_latest_tag reads a newline-separated list of tags on stdin and prints
# the highest by version order, or nothing when the list is empty.
mc_select_latest_tag() {
	sort -V | tail -1
}

# mc_apidiff_incompatible reads the output of `apidiff -incompatible` on stdin and
# prints "true" when it contains any change entry, "false" otherwise.
mc_apidiff_incompatible() {
	if grep -qE '[^[:space:]]'; then
		echo true
	else
		echo false
	fi
}

# mc_parse_schema_version reads a version.go on stdin and prints the integer value
# of the SchemaVersion constant. It returns non-zero when the constant is absent.
mc_parse_schema_version() {
	local line
	line="$(grep -E '^const SchemaVersion = [0-9]+' || true)"
	if [ -z "$line" ]; then
		return 1
	fi
	printf '%s\n' "$line" | grep -oE '[0-9]+' | head -1
}

# mc_has_breaking_marker reads commit messages on stdin and prints "true" when any
# carries a Conventional Commit breaking marker (a "type!:" subject or a
# BREAKING CHANGE footer), "false" otherwise.
mc_has_breaking_marker() {
	local msgs
	msgs="$(cat)"
	if grep -qE '(^|[[:space:]])BREAKING[ -]CHANGE' <<<"$msgs" \
		|| grep -qE '^[a-z]+(\([^)]+\))?!:' <<<"$msgs"; then
		echo true
	else
		echo false
	fi
}

# mc_gomod_dependency_light reads a go.mod on stdin and prints "true" when the
# module declares no external dependencies (no require/replace/exclude directives
# and no indirect markers), "false" otherwise.
mc_gomod_dependency_light() {
	local mod
	mod="$(cat)"
	if grep -qE '^[[:space:]]*require([[:space:]]|\()' <<<"$mod" \
		|| grep -qE '^[[:space:]]*replace[[:space:]]' <<<"$mod" \
		|| grep -qE '^[[:space:]]*exclude[[:space:]]' <<<"$mod" \
		|| grep -qE '//[[:space:]]*indirect' <<<"$mod"; then
		echo false
	else
		echo true
	fi
}

# mc_changed_touches_metrics reads a newline-separated list of changed paths on
# stdin and prints "true" when any path is under pkg/metrics/, "false" otherwise.
mc_changed_touches_metrics() {
	if grep -qE '^pkg/metrics/'; then
		echo true
	else
		echo false
	fi
}

# mc_gate_decision applies the compatibility policy to already-computed inputs and
# prints "pass" or "fail:<reason>". It returns non-zero on a fail so callers can
# branch on the exit code. Arguments:
#   $1 incompatible  "true" when apidiff reported incompatible changes
#   $2 base_ver      SchemaVersion at the baseline, or "__bootstrap__" when there
#                    is no baseline to compare against, or empty when unknown
#   $3 head_ver      SchemaVersion at HEAD
#   $4 marker        "true" when the diff carries a breaking-change marker
mc_gate_decision() {
	local incompatible="$1" base_ver="$2" head_ver="$3" marker="$4"

	if [ "$base_ver" = "__bootstrap__" ]; then
		echo pass
		return 0
	fi
	if [ -z "$head_ver" ]; then
		echo "fail:cannot parse SchemaVersion at HEAD"
		return 1
	fi
	if [ -z "$base_ver" ]; then
		echo pass
		return 0
	fi
	if [ "$head_ver" -lt "$base_ver" ]; then
		echo "fail:SchemaVersion decreased ($base_ver -> $head_ver)"
		return 1
	fi
	if [ "$incompatible" = "true" ] && [ "$head_ver" = "$base_ver" ] && [ "$marker" != "true" ]; then
		echo "fail:incompatible API change without a SchemaVersion bump or breaking-change marker"
		return 1
	fi
	echo pass
	return 0
}

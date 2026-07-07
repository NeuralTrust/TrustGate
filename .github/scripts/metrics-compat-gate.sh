#!/usr/bin/env bash
#
# Compatibility gate for the nested pkg/metrics Go module (ENG-1033). It fails a
# PR that changes the producer schema in a way consumers (DataCore/DataAgent)
# cannot absorb: an apidiff-incompatible change that neither bumps SchemaVersion
# nor carries a Conventional Commit breaking-change marker, a SchemaVersion that
# goes backwards, or a go.mod that stops being dependency-light. It self-skips
# when the PR does not touch pkg/metrics, so it can be a required status on every
# PR. The pure policy helpers live in metrics-compat-lib.sh (unit-tested); this
# file only wires them to git and apidiff.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=metrics-compat-lib.sh
source "$SCRIPT_DIR/metrics-compat-lib.sh"

TAG_PREFIX="${TAG_PREFIX:-pkg/metrics/v}"
MODULE_DIR="${MODULE_DIR:-pkg/metrics}"
MODULE_PATH="${MODULE_PATH:-github.com/NeuralTrust/TrustGate/pkg/metrics}"
BASE_REF="${BASE_REF:-}"
APIDIFF_BIN="${APIDIFF_BIN:-apidiff}"

diff_base() {
	local mb=""
	if [ -n "$BASE_REF" ]; then
		mb="$(git merge-base "$BASE_REF" HEAD 2>/dev/null || true)"
	fi
	if [ -n "$mb" ]; then
		printf '%s\n' "$mb"
	else
		printf '%s\n' "HEAD~1"
	fi
}

resolve_baseline() {
	local tag
	tag="$(git tag -l "${TAG_PREFIX}*" | mc_select_latest_tag)"
	if [ -n "$tag" ]; then
		printf '%s\n' "$tag"
		return 0
	fi
	local mb=""
	if [ -n "$BASE_REF" ]; then
		mb="$(git merge-base "$BASE_REF" HEAD 2>/dev/null || true)"
	fi
	if [ -n "$mb" ]; then
		printf '%s\n' "$mb"
	else
		printf '%s\n' "__bootstrap__"
	fi
}

schema_version_at() {
	git show "$1:${MODULE_DIR}/version.go" 2>/dev/null | mc_parse_schema_version || true
}

scoped_msgs() {
	git log --format='%B' "$1..HEAD" -- "$MODULE_DIR" 2>/dev/null || true
}

run_apidiff() {
	local baseline="$1"
	if ! git cat-file -e "${baseline}:${MODULE_DIR}/go.mod" 2>/dev/null; then
		echo "false"
		return 0
	fi

	local wt base_api head_api
	wt="$(mktemp -d)"
	base_api="$(mktemp)"
	head_api="$(mktemp)"
	# shellcheck disable=SC2329,SC2317 # invoked indirectly via the RETURN trap
	cleanup() {
		git worktree remove --force "$wt" >/dev/null 2>&1 || true
		rm -rf "$wt" "$base_api" "$head_api"
	}
	trap cleanup RETURN

	if ! git worktree add -q --detach "$wt" "$baseline" >/dev/null 2>&1; then
		echo "compat gate: cannot check out baseline ${baseline}; skipping apidiff" >&2
		echo "false"
		return 0
	fi
	if ! (cd "$wt/$MODULE_DIR" && "$APIDIFF_BIN" -m -w "$base_api" "$MODULE_PATH") >/dev/null 2>&1; then
		echo "compat gate: apidiff could not export baseline API; skipping apidiff" >&2
		echo "false"
		return 0
	fi
	if ! (cd "$MODULE_DIR" && "$APIDIFF_BIN" -m -w "$head_api" "$MODULE_PATH") >/dev/null 2>&1; then
		echo "compat gate: apidiff could not export HEAD API; skipping apidiff" >&2
		echo "false"
		return 0
	fi
	"$APIDIFF_BIN" -m -incompatible "$base_api" "$head_api" 2>/dev/null | mc_apidiff_incompatible
}

main() {
	cd "$(git rev-parse --show-toplevel)"

	local dbase changed
	dbase="$(diff_base)"
	changed="$(git diff --name-only "$dbase" HEAD 2>/dev/null || true)"
	if [ "$(printf '%s\n' "$changed" | mc_changed_touches_metrics)" != "true" ]; then
		echo "compat gate: no ${MODULE_DIR} changes vs ${dbase}; skipping"
		return 0
	fi

	if [ "$(mc_gomod_dependency_light <"$MODULE_DIR/go.mod")" != "true" ]; then
		echo "compat gate FAILED: ${MODULE_DIR}/go.mod must stay dependency-light (no require/replace/exclude directives)" >&2
		return 1
	fi

	local baseline
	baseline="$(resolve_baseline)"
	if [ "$baseline" = "__bootstrap__" ]; then
		echo "compat gate: no baseline tag or merge-base; bootstrap pass"
		return 0
	fi
	echo "compat gate: baseline=${baseline}" >&2

	local incompatible base_ver head_ver marker decision
	incompatible="$(run_apidiff "$baseline")"
	base_ver="$(schema_version_at "$baseline")"
	head_ver="$(schema_version_at HEAD)"
	marker="$(scoped_msgs "$baseline" | mc_has_breaking_marker)"

	echo "compat gate: incompatible=${incompatible} base_ver=${base_ver:-<none>} head_ver=${head_ver:-<none>} breaking_marker=${marker}" >&2

	if decision="$(mc_gate_decision "$incompatible" "${base_ver:-}" "${head_ver:-}" "$marker")"; then
		echo "compat gate: ${decision}"
		return 0
	fi
	echo "compat gate FAILED: ${decision}" >&2
	return 1
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
	main "$@"
fi

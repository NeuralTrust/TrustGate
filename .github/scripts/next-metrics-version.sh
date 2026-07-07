#!/usr/bin/env bash
#
# Computes the next semantic version for the nested pkg/metrics Go module from
# the latest path-prefixed tag (pkg/metrics/vX.Y.Z) and the conventional-commit
# messages that touched the module since that tag. It is side-effect free: it
# only writes version/tag/bump to GITHUB_OUTPUT (or stdout when run locally).
# The workflow (.github/workflows/metrics-module-release.yml) creates the tag.
#
# Bump rules (ENG-1034; breaking → major per the expand-contract policy in ENG-1033):
#   - BREAKING CHANGE footer or a "type!:" subject → major
#   - feat: subject                                → minor
#   - anything else                                → patch
#   - no prior tag                                 → 0.1.0 (initial release)
set -euo pipefail

TAG_PREFIX="${TAG_PREFIX:-pkg/metrics/v}"
MODULE_PATH="${MODULE_PATH:-pkg/metrics}"

detect_level() {
	local msgs
	msgs="$(cat)"
	if grep -qE '(^|[[:space:]])BREAKING[ -]CHANGE' <<<"$msgs" \
		|| grep -qE '^[a-z]+(\([^)]+\))?!:' <<<"$msgs"; then
		echo major
		return
	fi
	if grep -qE '^feat(\([^)]+\))?:' <<<"$msgs"; then
		echo minor
		return
	fi
	echo patch
}

compute_next() {
	local prev="${1#v}" level="$2"
	local x y z
	IFS=. read -r x y z <<<"$prev"
	case "$level" in
	major) echo "$((x + 1)).0.0" ;;
	minor) echo "$x.$((y + 1)).0" ;;
	patch) echo "$x.$y.$((z + 1))" ;;
	*)
		echo "unknown bump level: $level" >&2
		return 1
		;;
	esac
}

emit() {
	local out="${GITHUB_OUTPUT:-/dev/stdout}"
	{ printf '%s\n' "$@"; } >>"$out"
}

main() {
	local latest
	latest="$(git tag -l "${TAG_PREFIX}*" | sort -V | tail -1)"

	if [ -z "$latest" ]; then
		local version="0.1.0"
		echo "no ${TAG_PREFIX}* tag found; seeding initial ${TAG_PREFIX}${version}" >&2
		emit "changed=true" "version=${version}" "tag=${TAG_PREFIX}${version}" "bump=initial"
		return 0
	fi

	local msgs
	msgs="$(git log --format='%B' "${latest}..HEAD" -- "$MODULE_PATH" 2>/dev/null || true)"
	if [ -z "${msgs//[[:space:]]/}" ]; then
		echo "no ${MODULE_PATH} changes since ${latest}; nothing to release" >&2
		emit "changed=false"
		return 0
	fi

	local bump version
	bump="$(detect_level <<<"$msgs")"
	version="$(compute_next "${latest#"$TAG_PREFIX"}" "$bump")"
	echo "next module version: ${TAG_PREFIX}${version} (bump=${bump}, from ${latest})" >&2
	emit "changed=true" "version=${version}" "tag=${TAG_PREFIX}${version}" "bump=${bump}"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
	main "$@"
fi

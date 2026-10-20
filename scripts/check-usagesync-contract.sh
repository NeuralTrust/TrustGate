#!/usr/bin/env bash
# Copyright 2026 NeuralTrust
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# check-usagesync-contract.sh — fail when TrustGate's copy of usage.v1
# (pkg/infra/usagesync/proto) drifts from the private event-schemas source.
#
# TrustGate is public and cannot depend on the private event-schemas module, so
# it carries a copy. Both are compared on the wire, in both directions, with
# buf's WIRE_JSON rules: file names and go_package may differ; packages,
# message and field names, numbers and types may not. Only billing.v1.Plan is
# copied from billing.v1 and only state.proto and sync.proto from usage.v1, so
# the source is checked against the same subset: its Plan enum is cut out of
# its billing.proto.
# It needs read access to event-schemas, so it is not part of the public build.
#
#   EVENT_SCHEMAS_DIR  a local event-schemas checkout (skips the clone)
#   EVENT_SCHEMAS_REF  branch or tag to clone (default: main; usage.v1 is on
#                      feat/run-1915-usage-system-contracts until it merges)

set -euo pipefail

BUF="go run github.com/bufbuild/buf/cmd/buf@v1.50.0"
CONFIG='{"version":"v2","breaking":{"use":["WIRE_JSON"]}}'
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

source_dir="${EVENT_SCHEMAS_DIR:-}"
if [ -z "$source_dir" ]; then
  source_dir="$work/event-schemas"
  git clone --quiet --depth 1 --branch "${EVENT_SCHEMAS_REF:-main}" \
    https://github.com/NeuralTrust/event-schemas.git "$source_dir"
fi

copy="$root/pkg/infra/usagesync/proto"
mkdir -p "$work/copy/usage/v1" "$work/copy/billing/v1" "$work/source/billing/v1"
cp "$copy"/usage/v1/*.proto "$work/copy/usage/v1/"
cp "$copy"/billing/v1/plan.proto "$work/copy/billing/v1/"
mkdir -p "$work/source/usage/v1"
cp "$source_dir"/proto/usage/v1/state.proto "$source_dir"/proto/usage/v1/sync.proto "$work/source/usage/v1/"
{
  printf 'syntax = "proto3";\n\npackage billing.v1;\n\n'
  awk '/^enum Plan \{/{p=1} p{print} p&&/^\}/{exit}' "$source_dir/proto/billing/v1/billing.proto"
} > "$work/source/billing/v1/billing.proto"

(cd "$work/copy" && $BUF breaking . --config "$CONFIG" --against ../source --against-config "$CONFIG")
(cd "$work/source" && $BUF breaking . --config "$CONFIG" --against ../copy --against-config "$CONFIG")
echo "usage.v1 copy matches event-schemas"

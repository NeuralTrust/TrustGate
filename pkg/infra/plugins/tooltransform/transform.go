// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tooltransform

import (
	"path"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func applyTransforms(tools []adapter.CanonicalTool, entries []transformDef) (changed bool) {
	for i := range tools {
		for j := range entries {
			if !matchToolPattern(entries[j].Tool, tools[i].Name) {
				continue
			}
			if len(entries[j].SchemaPatch) > 0 {
				tools[i].Schema = mergePatch(tools[i].Schema, entries[j].SchemaPatch)
				changed = true
			}
			if entries[j].DescriptionOverride != nil {
				tools[i].Description = *entries[j].DescriptionOverride
				changed = true
			}
		}
	}
	return changed
}

func matchToolPattern(pattern, name string) bool {
	const sentinel = "\x00"
	p := strings.ReplaceAll(pattern, "/", sentinel)
	n := strings.ReplaceAll(name, "/", sentinel)
	ok, err := path.Match(p, n)
	return err == nil && ok
}

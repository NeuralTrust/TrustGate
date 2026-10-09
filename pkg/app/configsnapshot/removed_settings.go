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

package configsnapshot

import (
	"maps"
	"strings"

	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// removedSettings lists, per plugin, the stored settings that no longer exist
// because the guardrails always fail open. A data plane that still honours one
// of them (a hybrid data plane on an older release) would turn a stored
// fail_closed, a block or a 1ms timeout back into behaviour the console no longer
// offers, so the published snapshot never carries them. Settings are removed by
// dotted path.
//
// regex_replace keeps its streaming.on_error: it is a rewriter, not a guardrail,
// and its stream leg still fails closed. "timeout" is removed from trustguard
// only: no other plugin stores a per-policy key of that name.
var removedSettings = map[string][]string{
	"trustguard": {
		"on_error", "on_timeout", "timeout", "on_mask_failure",
		"streaming.on_error", "streaming.guard_timeout",
	},
	"bedrock_guardrail": {
		"on_error", "on_mask_failure",
		"streaming.on_error", "streaming.guard_timeout",
	},
	"google_model_armor": {
		"on_error", "on_mask_failure",
		"streaming.on_error", "streaming.guard_timeout",
	},
	"openai_moderation": {
		"on_error",
		"streaming.on_error", "streaming.guard_timeout",
	},
	"azure_content_safety": {"on_error"},
	"regex_replace":        {"on_mask_failure"},
}

// withoutRemovedSettings returns p with the removed settings of its plugin
// dropped. The stored settings are never edited: they are copied before the first
// key goes, and a policy with nothing to drop is returned as it is.
func withoutRemovedSettings(p policydomain.Policy) policydomain.Policy {
	paths := removedSettings[p.Slug]
	if len(paths) == 0 || len(p.Settings) == 0 {
		return p
	}
	cleaned := maps.Clone(p.Settings)
	copied := map[string]bool{}
	changed := false
	for _, path := range paths {
		parent, key, nested := strings.Cut(path, ".")
		if !nested {
			if _, present := cleaned[path]; present {
				delete(cleaned, path)
				changed = true
			}
			continue
		}
		block, ok := cleaned[parent].(map[string]any)
		if !ok {
			continue
		}
		if _, present := block[key]; !present {
			continue
		}
		if !copied[parent] {
			block = maps.Clone(block)
			cleaned[parent] = block
			copied[parent] = true
		}
		delete(block, key)
		changed = true
	}
	if changed {
		p.Settings = cleaned
	}
	return p
}

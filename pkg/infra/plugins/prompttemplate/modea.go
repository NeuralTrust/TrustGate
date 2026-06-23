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

package prompttemplate

import "sort"

type modeAOutcome struct {
	changed    bool
	injected   []string
	skipped    []string
	unresolved []string
}

func applyModeA(cfg *config, rb *requestBody, ctxVars map[string]string) modeAOutcome {
	var out modeAOutcome
	escape := cfg.EscapeJSONControlChars == nil || *cfg.EscapeJSONControlChars
	for i := range cfg.InjectTemplates {
		it := cfg.InjectTemplates[i]
		rendered, missing := renderTemplate(it.Content, ctxVars)
		if len(missing) > 0 {
			switch cfg.OnMissingContextVariable {
			case onMissingContextError:
				out.unresolved = append(out.unresolved, missing...)
				continue
			case onMissingContextSkip:
				out.skipped = append(out.skipped, it.ID)
				continue
			case onMissingContextEmptyString:
			default:
			}
		}
		if escape {
			rendered = escapeControlChars(rendered)
		}
		rb.injectSystem(it.OnExistingSystem, it.Role, rendered)
		out.changed = true
		out.injected = append(out.injected, it.ID)
	}
	out.unresolved = dedupeSorted(out.unresolved)
	return out
}

func dedupeSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		unique = append(unique, v)
	}
	sort.Strings(unique)
	return unique
}

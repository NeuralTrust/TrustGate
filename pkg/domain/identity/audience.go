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

package identity

import "strings"

func AudienceMatches(have, want []string) bool {
	for _, h := range have {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		for _, w := range want {
			w = strings.TrimSpace(w)
			if w == "" {
				continue
			}
			if h == w || h == strings.TrimPrefix(w, "api://") || w == strings.TrimPrefix(h, "api://") {
				return true
			}
		}
	}
	return false
}

func AudiencesFromClaim(aud any) []string {
	switch a := aud.(type) {
	case string:
		if a == "" {
			return nil
		}
		return []string{a}
	case []string:
		out := make([]string, 0, len(a))
		for _, s := range a {
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(a))
		for _, item := range a {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func (p *Principal) HasAudience(expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" || p == nil {
		return false
	}
	return AudienceMatches(AudiencesFromClaim(p.Claims["aud"]), []string{expected})
}

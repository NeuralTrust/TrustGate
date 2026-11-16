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

package registry

import (
	"encoding/json"
	"strings"
)

// SkillVerdict is TrustGuard's indirect prompt injection verdict on one skill
// of a pinned card: the skill's text as a model calling the agent reads it.
type SkillVerdict struct {
	SkillID string  `json:"skill_id"`
	Flagged bool    `json:"flagged"`
	Score   float64 `json:"score"`
}

type cardSkill struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Examples    []string `json:"examples"`
}

// SkillTexts returns, for each skill of card with an id, the id and its name,
// description and examples as one text.
func SkillTexts(card []byte) (ids, texts []string) {
	var v struct {
		Skills []json.RawMessage `json:"skills"`
	}
	_ = json.Unmarshal(card, &v)
	for _, raw := range v.Skills {
		var s cardSkill
		// A skill with a field of another type is read for what it has.
		_ = json.Unmarshal(raw, &s)
		if s.ID == "" {
			continue
		}
		parts := append([]string{s.Name, s.Description}, s.Examples...)
		text := strings.TrimSpace(strings.Join(nonEmpty(parts), "\n"))
		if text == "" {
			continue
		}
		ids = append(ids, s.ID)
		texts = append(texts, text)
	}
	return ids, texts
}

func nonEmpty(in []string) []string {
	out := in[:0:0]
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

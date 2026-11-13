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

package response

import (
	"encoding/json"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// PreviewAgentCardResponse is an agent card read without registering it.
type PreviewAgentCardResponse struct {
	ResolvedCardURL string          `json:"resolved_card_url"`
	Card            json.RawMessage `json:"card" swaggertype:"object"`
	CardDigest      string          `json:"card_digest"`
	Versions        []string        `json:"versions"`
	DefaultVersion  string          `json:"default_version,omitempty"`
	// SkillScan is TrustGuard's verdict on each skill; absent when not scanned.
	SkillScan []domain.SkillVerdict `json:"skill_scan,omitempty"`
}

func FromAgentCardPreview(p *appregistry.AgentCardPreview) PreviewAgentCardResponse {
	versions := make([]string, 0, len(p.Versions))
	for _, v := range p.Versions {
		versions = append(versions, string(v))
	}
	return PreviewAgentCardResponse{
		ResolvedCardURL: p.ResolvedCardURL,
		Card:            p.Card,
		CardDigest:      p.CardDigest,
		Versions:        versions,
		DefaultVersion:  string(p.DefaultVersion),
		SkillScan:       p.SkillScan,
	}
}

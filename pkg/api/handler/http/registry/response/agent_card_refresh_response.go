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
)

// AgentCardRefreshResponse compares a registry's live card with the pinned one.
type AgentCardRefreshResponse struct {
	Changed       bool            `json:"changed"`
	PinnedDigest  string          `json:"pinned_digest"`
	FetchedDigest string          `json:"fetched_digest"`
	ChangedFields []string        `json:"changed_fields"`
	SkillsAdded   []string        `json:"skills_added"`
	SkillsRemoved []string        `json:"skills_removed"`
	FetchedCard   json.RawMessage `json:"fetched_card" swaggertype:"object"`
}

func FromAgentCardRefresh(r *appregistry.AgentCardRefresh) AgentCardRefreshResponse {
	return AgentCardRefreshResponse{
		Changed:       r.Changed,
		PinnedDigest:  r.PinnedDigest,
		FetchedDigest: r.FetchedDigest,
		ChangedFields: nonNil(r.ChangedFields),
		SkillsAdded:   nonNil(r.SkillsAdded),
		SkillsRemoved: nonNil(r.SkillsRemoved),
		FetchedCard:   r.FetchedCard,
	}
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

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
	"time"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
)

// PinnedToolsResponse is the list of tool definitions a registry has recorded.
// Each (name, fingerprint) is one definition with its own decision: a server
// that changes a tool's description or schema shows up as a new pending item
// next to the approved one.
type PinnedToolsResponse struct {
	// ToolPolicy is "auto" or "pinned". Decisions only take effect when pinned.
	ToolPolicy string           `json:"tool_policy"`
	Items      []PinnedToolItem `json:"items"`
	Total      int              `json:"total"`
}

type PinnedToolItem struct {
	Name        string          `json:"name"`
	Fingerprint string          `json:"fingerprint"`
	Status      string          `json:"status"`
	Definition  json.RawMessage `json:"definition"`
	FirstSeenAt time.Time       `json:"first_seen_at"`
	DecidedAt   *time.Time      `json:"decided_at,omitempty"`
	DecidedBy   string          `json:"decided_by,omitempty"`
	// ApprovedVersion is set only on a pending item whose name already has an
	// approved definition: the one currently exposed, to diff against.
	ApprovedVersion *PinnedToolApproved `json:"approved_version,omitempty"`
}

type PinnedToolApproved struct {
	Fingerprint string          `json:"fingerprint"`
	Definition  json.RawMessage `json:"definition"`
	DecidedAt   *time.Time      `json:"decided_at,omitempty"`
	DecidedBy   string          `json:"decided_by,omitempty"`
}

func FromPinnedToolList(l *appregistry.PinnedToolList) PinnedToolsResponse {
	items := make([]PinnedToolItem, 0, len(l.Items))
	for _, v := range l.Items {
		item := PinnedToolItem{
			Name:        v.Name,
			Fingerprint: v.Fingerprint,
			Status:      string(v.Status),
			Definition:  definitionOrEmpty(v.Definition),
			FirstSeenAt: v.FirstSeenAt,
			DecidedAt:   timePtr(v.DecidedAt),
			DecidedBy:   v.DecidedBy,
		}
		if v.Approved != nil {
			item.ApprovedVersion = &PinnedToolApproved{
				Fingerprint: v.Approved.Fingerprint,
				Definition:  definitionOrEmpty(v.Approved.Definition),
				DecidedAt:   timePtr(v.Approved.DecidedAt),
				DecidedBy:   v.Approved.DecidedBy,
			}
		}
		items = append(items, item)
	}
	return PinnedToolsResponse{ToolPolicy: string(l.ToolPolicy), Items: items, Total: len(items)}
}

func definitionOrEmpty(def json.RawMessage) json.RawMessage {
	if len(def) == 0 {
		return json.RawMessage(`{}`)
	}
	return def
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

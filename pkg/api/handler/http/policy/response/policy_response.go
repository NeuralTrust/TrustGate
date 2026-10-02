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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// Policy status values. They mirror app/policy.Status; the response package
// stays free of app-layer imports.
const (
	StatusActive = "active"
	StatusPaused = "paused"
	StatusError  = "error"
)

type PolicyResponse struct {
	ID          ids.PolicyID     `json:"id"`
	GatewayID   ids.GatewayID    `json:"gateway_id"`
	ConsumerIDs []ids.ConsumerID `json:"consumer_ids,omitempty"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Slug        string           `json:"slug"`
	Enabled     bool             `json:"enabled"`
	Global      bool             `json:"global"`
	// MCPWide marks a policy that runs on every MCP consumer of the gateway and
	// on the MCP Store, narrowed by its mcp_scope. It is never true together
	// with Global, and an MCP-wide policy has no consumer_ids.
	MCPWide  bool           `json:"mcp_wide"`
	Priority int            `json:"priority"`
	Parallel bool           `json:"parallel,omitempty"`
	Settings map[string]any `json:"settings,omitempty"`
	Stages   []string       `json:"stages,omitempty"`
	Mode     string         `json:"mode"`
	// Status is "active" (enabled and running), "paused" (disabled) or "error"
	// (enabled but the gateway cannot run it; see status_message).
	Status string `json:"status" enums:"active,paused,error"`
	// StatusMessage is the reason the gateway cannot run the policy. It is
	// present only when status is "error".
	StatusMessage string `json:"status_message,omitempty"`
	// MCPScope is echoed as stored: absent when the policy is consumer-wide,
	// {} when a registry delete pruned every destination.
	MCPScope *MCPScopeResponse `json:"mcp_scope,omitempty"`
	// Warnings are non-blocking notes about the write that just succeeded,
	// such as a consumer that already runs the same plugin without scope.
	Warnings  []string  `json:"warnings,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// MCPToolRefResponse names one upstream tool by registry and native name.
type MCPToolRefResponse struct {
	RegistryID ids.RegistryID `json:"registry_id"`
	Tool       string         `json:"tool"`
}

// MCPScopeResponse mirrors the stored mcp_scope of a policy.
type MCPScopeResponse struct {
	RegistryIDs  []ids.RegistryID     `json:"registry_ids,omitempty"`
	Tools        []MCPToolRefResponse `json:"tools,omitempty"`
	Groups       []string             `json:"groups,omitempty"`
	ExceptGroups []string             `json:"except_groups,omitempty"`
}

func FromPolicy(p *domain.Policy) PolicyResponse {
	status := StatusActive
	if !p.Enabled {
		status = StatusPaused
	}
	return PolicyResponse{
		Status:      status,
		ID:          p.ID,
		GatewayID:   p.GatewayID,
		ConsumerIDs: p.ConsumerIDs,
		Name:        p.Name,
		Description: p.Description,
		Slug:        p.Slug,
		Enabled:     p.Enabled,
		Global:      p.Global,
		MCPWide:     p.MCPWide,
		Priority:    p.Priority,
		Parallel:    p.Parallel,
		Settings:    p.Settings,
		Stages:      fromStages(p.Stages),
		Mode:        string(p.Mode.Normalize()),
		MCPScope:    fromMCPScope(p.MCPScope),
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
}

// WithStatus overrides the status derived from Enabled with an evaluated one.
func (r PolicyResponse) WithStatus(status, message string) PolicyResponse {
	r.Status = status
	r.StatusMessage = message
	return r
}

// FromPolicyWithWarnings is FromPolicy plus the non-blocking warnings of the
// write that produced p.
func FromPolicyWithWarnings(p *domain.Policy, warnings []string) PolicyResponse {
	out := FromPolicy(p)
	out.Warnings = warnings
	return out
}

func fromMCPScope(scope *domain.MCPScope) *MCPScopeResponse {
	if scope == nil {
		return nil
	}
	out := &MCPScopeResponse{
		RegistryIDs:  scope.RegistryIDs,
		Groups:       scope.Groups,
		ExceptGroups: scope.ExceptGroups,
	}
	if len(scope.Tools) > 0 {
		out.Tools = make([]MCPToolRefResponse, 0, len(scope.Tools))
		for _, ref := range scope.Tools {
			out.Tools = append(out.Tools, MCPToolRefResponse{RegistryID: ref.RegistryID, Tool: ref.Tool})
		}
	}
	return out
}

func fromStages(stages []domain.Stage) []string {
	if len(stages) == 0 {
		return nil
	}
	out := make([]string, 0, len(stages))
	for _, s := range stages {
		out = append(out, string(s))
	}
	return out
}

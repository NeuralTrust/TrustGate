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

package request

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// MCPToolRefRequest names one upstream tool by its registry and native name.
type MCPToolRefRequest struct {
	RegistryID string `json:"registry_id" format:"uuid"`
	Tool       string `json:"tool"`
}

// MCPScopeRequest narrows a policy to MCP destinations (registry_ids, tools)
// and principals (users, groups, except_users, except_groups). Registry ids
// are checked to be UUIDs here; existence, gateway ownership and the MCP type
// are validated by the application layer.
type MCPScopeRequest struct {
	RegistryIDs  []string            `json:"registry_ids,omitempty"`
	Tools        []MCPToolRefRequest `json:"tools,omitempty"`
	Users        []string            `json:"users,omitempty"`
	Groups       []string            `json:"groups,omitempty"`
	ExceptUsers  []string            `json:"except_users,omitempty"`
	ExceptGroups []string            `json:"except_groups,omitempty"`
}

// ToDomain converts the request into the domain scope. A nil receiver yields
// a nil scope; a registry id that is not a UUID yields ErrValidation.
func (r *MCPScopeRequest) ToDomain() (*domain.MCPScope, error) {
	if r == nil {
		return nil, nil
	}
	scope := &domain.MCPScope{
		Users:        r.Users,
		Groups:       r.Groups,
		ExceptUsers:  r.ExceptUsers,
		ExceptGroups: r.ExceptGroups,
	}
	if len(r.RegistryIDs) > 0 {
		scope.RegistryIDs = make([]ids.RegistryID, 0, len(r.RegistryIDs))
		for _, raw := range r.RegistryIDs {
			id, err := parseScopeRegistryID(raw)
			if err != nil {
				return nil, err
			}
			scope.RegistryIDs = append(scope.RegistryIDs, id)
		}
	}
	if len(r.Tools) > 0 {
		scope.Tools = make([]domain.MCPToolRef, 0, len(r.Tools))
		for _, ref := range r.Tools {
			id, err := parseScopeRegistryID(ref.RegistryID)
			if err != nil {
				return nil, err
			}
			scope.Tools = append(scope.Tools, domain.MCPToolRef{RegistryID: id, Tool: ref.Tool})
		}
	}
	return scope, nil
}

func parseScopeRegistryID(raw string) (ids.RegistryID, error) {
	id, err := ids.Parse[ids.RegistryKind](strings.TrimSpace(raw))
	if err != nil {
		return ids.RegistryID{}, fmt.Errorf("mcp_scope: invalid registry_id %q: %w", raw, commonerrors.ErrValidation)
	}
	return id, nil
}

var jsonNull = []byte("null")

// parseMCPScopePatch reads the tri-state mcp_scope of an update body. An
// absent key reports set=false; an explicit null reports set=true with a nil
// scope (clear); an object reports set=true with the parsed scope.
func parseMCPScopePatch(raw json.RawMessage) (set bool, scope *domain.MCPScope, err error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return false, nil, nil
	}
	if bytes.Equal(trimmed, jsonNull) {
		return true, nil, nil
	}
	var req MCPScopeRequest
	if err := json.Unmarshal(trimmed, &req); err != nil {
		return false, nil, fmt.Errorf("mcp_scope must be an object or null: %w", commonerrors.ErrValidation)
	}
	scope, err = req.ToDomain()
	if err != nil {
		return false, nil, err
	}
	return true, scope, nil
}

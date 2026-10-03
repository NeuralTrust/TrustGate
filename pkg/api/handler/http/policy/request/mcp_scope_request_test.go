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

package request_test

import (
	"encoding/json"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy/request"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreatePolicyRequest_ToMCPScope(t *testing.T) {
	t.Parallel()
	registryID := ids.New[ids.RegistryKind]()
	toolRegistryID := ids.New[ids.RegistryKind]()

	var req request.CreatePolicyRequest
	require.NoError(t, json.Unmarshal([]byte(`{
		"name": "dlp", "slug": "trustguard",
		"mcp_scope": {
			"registry_ids": ["`+registryID.String()+`"],
			"tools": [{"registry_id": "`+toolRegistryID.String()+`", "tool": "run_query"}],
			"groups": ["Finanzas"],
			"except_groups": ["Interns"]
		}
	}`), &req))

	scope, err := req.ToMCPScope()
	require.NoError(t, err)
	assert.Equal(t, &domain.MCPScope{
		RegistryIDs:  []ids.RegistryID{registryID},
		Tools:        []domain.MCPToolRef{{RegistryID: toolRegistryID, Tool: "run_query"}},
		Groups:       []string{"Finanzas"},
		ExceptGroups: []string{"Interns"},
	}, scope)
}

func TestCreatePolicyRequest_ToMCPScope_RejectsRetiredUserDimension(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"users", "except_users"} {
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			var req request.CreatePolicyRequest
			require.NoError(t, json.Unmarshal([]byte(`{
				"name": "dlp", "slug": "trustguard",
				"mcp_scope": {"groups": ["Finanzas"], "`+field+`": ["ana@acme.com"]}
			}`), &req))

			scope, err := req.ToMCPScope()
			assert.Nil(t, scope)
			require.ErrorIs(t, err, commonerrors.ErrValidation)
			assert.Contains(t, err.Error(), field+" is no longer supported")
		})
	}
}

func TestCreatePolicyRequest_ToMCPScope_OmittedIsNil(t *testing.T) {
	t.Parallel()
	var req request.CreatePolicyRequest
	require.NoError(t, json.Unmarshal([]byte(`{"name": "dlp", "slug": "trustguard"}`), &req))

	scope, err := req.ToMCPScope()
	require.NoError(t, err)
	assert.Nil(t, scope)
}

func TestCreatePolicyRequest_ToMCPScope_EmptyObjectIsEmptyScope(t *testing.T) {
	t.Parallel()
	var req request.CreatePolicyRequest
	require.NoError(t, json.Unmarshal([]byte(`{"name": "dlp", "slug": "trustguard", "mcp_scope": {}}`), &req))

	scope, err := req.ToMCPScope()
	require.NoError(t, err)
	require.NotNil(t, scope)
	assert.True(t, scope.IsEmpty(), "the app layer rejects it; the DTO only keeps nil and {} apart")
}

func TestCreatePolicyRequest_ToMCPScope_InvalidRegistryID(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"in registry_ids": `{"registry_ids": ["not-a-uuid"]}`,
		"in tools":        `{"tools": [{"registry_id": "nope", "tool": "run_query"}]}`,
	}
	for name, raw := range tests {
		raw := raw
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var req request.CreatePolicyRequest
			require.NoError(t, json.Unmarshal([]byte(`{"name": "dlp", "slug": "trustguard", "mcp_scope": `+raw+`}`), &req))

			_, err := req.ToMCPScope()
			assert.ErrorIs(t, err, commonerrors.ErrValidation)
		})
	}
}

func TestUpdatePolicyRequest_ToMCPScope_TriState(t *testing.T) {
	t.Parallel()
	registryID := ids.New[ids.RegistryKind]()
	tests := []struct {
		name      string
		body      string
		wantSet   bool
		wantScope *domain.MCPScope
		wantErr   error
	}{
		{name: "omitted keeps the stored scope", body: `{"name": "renamed"}`},
		{name: "null clears the scope", body: `{"mcp_scope": null}`, wantSet: true},
		{
			name:      "object replaces the scope",
			body:      `{"mcp_scope": {"registry_ids": ["` + registryID.String() + `"]}}`,
			wantSet:   true,
			wantScope: &domain.MCPScope{RegistryIDs: []ids.RegistryID{registryID}},
		},
		{name: "empty object is an empty scope", body: `{"mcp_scope": {}}`, wantSet: true, wantScope: &domain.MCPScope{}},
		{name: "non-object is rejected", body: `{"mcp_scope": "all"}`, wantErr: commonerrors.ErrValidation},
		{name: "invalid registry id is rejected", body: `{"mcp_scope": {"registry_ids": ["x"]}}`, wantErr: commonerrors.ErrValidation},
		{name: "users is rejected", body: `{"mcp_scope": {"users": ["ana@acme.com"]}}`, wantErr: commonerrors.ErrValidation},
		{name: "except_users is rejected", body: `{"mcp_scope": {"groups": ["Finanzas"], "except_users": ["ana@acme.com"]}}`, wantErr: commonerrors.ErrValidation},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var req request.UpdatePolicyRequest
			require.NoError(t, json.Unmarshal([]byte(tt.body), &req))

			set, scope, err := req.ToMCPScope()
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantSet, set)
			assert.Equal(t, tt.wantScope, scope)
		})
	}
}

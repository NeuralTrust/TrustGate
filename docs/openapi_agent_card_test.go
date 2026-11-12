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

package docs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenAPIDocumentsTheAgentCardRoutes(t *testing.T) {
	document := loadOpenAPIDocument(t)

	preview, ok := document.Paths["/v1/gateways/{gateway_id}/registries/preview-agent-card"]
	require.True(t, ok)
	body := schemaByRef(t, document, jsonBodySchemaRef(t, document, preview.Post.RequestBody))
	for _, field := range []string{"card_url", "provider", "auth", "cloud_auth"} {
		assert.Contains(t, body.Properties, field)
	}
	result := schemaByRef(t, document, preview.Post.Responses["200"].Content["application/json"].Schema.Ref)
	for _, field := range []string{"resolved_card_url", "card", "card_digest", "versions", "default_version"} {
		assert.Contains(t, result.Properties, field)
	}

	refresh, ok := document.Paths["/v1/gateways/{gateway_id}/registries/{id}/agent-card/refresh"]
	require.True(t, ok)
	diff := schemaByRef(t, document, refresh.Post.Responses["200"].Content["application/json"].Schema.Ref)
	for _, field := range []string{"changed", "pinned_digest", "fetched_digest", "changed_fields", "skills_added", "skills_removed", "fetched_card"} {
		assert.Contains(t, diff.Properties, field)
	}

	approve, ok := document.Paths["/v1/gateways/{gateway_id}/registries/{id}/agent-card/approve"]
	require.True(t, ok)
	assert.Contains(t, approve.Post.Responses, "409")
	assert.Contains(t, schemaByRef(t, document, jsonBodySchemaRef(t, document, approve.Post.RequestBody)).Properties, "digest")
}


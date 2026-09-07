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
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type openAPIDocument struct {
	Paths map[string]struct {
		Get struct {
			Description string `json:"description"`
			Responses   map[string]struct {
				Description string `json:"description"`
				Content     map[string]struct {
					Schema struct {
						Ref string `json:"$ref"`
					} `json:"schema"`
				} `json:"content"`
			} `json:"responses"`
		} `json:"get"`
	} `json:"paths"`
	Components struct {
		Schemas map[string]struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"schemas"`
	} `json:"components"`
}

func TestRegistryListOpenAPIDocumentsFlatAndGroupedShapes(t *testing.T) {
	raw, err := os.ReadFile("openapi.json")
	require.NoError(t, err)

	var document openAPIDocument
	require.NoError(t, json.Unmarshal(raw, &document))

	operation, ok := document.Paths["/v1/gateways/{gateway_id}/registries"]
	require.True(t, ok)
	assert.Contains(t, operation.Get.Description, "two mutually exclusive variants")
	assert.Contains(t, operation.Get.Description, "at most 200 total registries")

	success, ok := operation.Get.Responses["200"]
	require.True(t, ok)
	assert.Contains(t, success.Description, "flat (items/page/size/total)")
	assert.Contains(t, success.Description, "grouped (view/groups/total_groups/total_instances)")
	mediaType, ok := success.Content["application/json"]
	require.True(t, ok)
	schemaName := strings.TrimPrefix(mediaType.Schema.Ref, "#/components/schemas/")
	require.NotEmpty(t, schemaName)
	schema, ok := document.Components.Schemas[schemaName]
	require.True(t, ok)

	for _, field := range []string{
		"items",
		"page",
		"size",
		"total",
		"view",
		"groups",
		"total_groups",
		"total_instances",
	} {
		assert.Contains(t, schema.Properties, field)
	}
}

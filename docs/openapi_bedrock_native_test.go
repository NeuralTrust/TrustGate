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

func TestOpenAPIDocumentsTheNativeBedrockRoutes(t *testing.T) {
	document := loadOpenAPIDocument(t)

	for _, op := range []string{"converse", "converse-stream", "invoke", "invoke-with-response-stream"} {
		path := "/{consumer_slug}/model/{model_id}/" + op
		item, ok := document.Paths[path]
		require.True(t, ok, "%s is documented", path)
		assert.Contains(t, item.Post.Description, "exactly as the client sent it")

		assert.Contains(t, item.Post.Description, "SigV4 Authorization header is accepted and ignored")

		for _, status := range []string{"401", "403"} {
			failure, ok := item.Post.Responses[status]
			require.True(t, ok, "%s %s", path, status)
			schema := schemaByRef(t, document, failure.Content["application/json"].Schema.Ref)
			assert.Contains(t, schema.Properties, "__type")
			assert.Contains(t, schema.Properties, "message")
		}
	}
}

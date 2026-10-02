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

package semanticcache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The declared path is the contract the policy API masks by; this pins it to
// the field parseConfig actually reads. The plugin has no credentials.api_key.
func TestCredentialPaths(t *testing.T) {
	assert.Equal(t, []string{"embedding.api_key"}, (&Plugin{}).CredentialPaths())

	cfg, err := parseConfig(map[string]any{"embedding": map[string]any{"api_key": "canary"}})
	require.NoError(t, err)
	assert.Equal(t, "canary", cfg.Embedding.APIKey)

	cfg, err = parseConfig(map[string]any{"credentials": map[string]any{"api_key": "canary"}})
	require.NoError(t, err)
	assert.Empty(t, cfg.Embedding.APIKey, "credentials.api_key is not read by this plugin")
}

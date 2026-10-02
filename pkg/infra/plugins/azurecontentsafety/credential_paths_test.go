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

package azurecontentsafety

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The declared paths are the contract the policy API masks by; this pins them
// to the field parseConfig actually reads, so a renamed config key cannot leave
// a credential unmasked.
func TestCredentialPaths(t *testing.T) {
	t.Parallel()
	paths := (&Plugin{}).CredentialPaths()
	assert.Equal(t, []string{"api_key"}, paths)

	cfg, err := parseConfig(map[string]any{"api_key": "canary", "endpoint": "https://x.cognitiveservices.azure.com", "category_severity": map[string]any{CategoryHate: 4}})
	require.NoError(t, err)
	assert.Equal(t, "canary", cfg.APIKey)
}

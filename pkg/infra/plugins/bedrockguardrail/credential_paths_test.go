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

package bedrockguardrail

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The declared paths are the contract the policy API masks by; this pins them
// to the fields parseConfig actually reads.
func TestCredentialPaths(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{
		"credentials.access_key_id",
		"credentials.secret_access_key",
		"credentials.session_token",
	}, (&Plugin{}).CredentialPaths())

	cfg, err := parseConfig(map[string]any{
		"guardrail_id": "gr1abc",
		"credentials": map[string]any{
			"access_key_id":     "c1",
			"secret_access_key": "c2",
			"session_token":     "c3",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "c1", cfg.Credentials.AccessKeyID)
	assert.Equal(t, "c2", cfg.Credentials.SecretAccessKey)
	assert.Equal(t, "c3", cfg.Credentials.SessionToken)
}

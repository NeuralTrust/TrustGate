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

package googlemodelarmor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The declared paths are the contract the policy API masks by; this pins them
// to the field parseConfig actually reads.
func TestCredentialPaths(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"credentials.service_account_json"}, (&Plugin{}).CredentialPaths())

	s := validSettings()
	s["credentials"] = map[string]any{"service_account_json": `{"type":"service_account","private_key":"canary"}`}
	cfg, err := parseConfig(s)
	require.NoError(t, err)
	assert.Contains(t, cfg.Credentials.ServiceAccountJSON, "canary")
}

// location builds the host and project the path of the credentialed request.
func TestCredentialDestinations(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"location", "project"}, (&Plugin{}).CredentialDestinations())

	cfg, err := parseConfig(validSettings())
	require.NoError(t, err)
	assert.Equal(t, "us-central1", cfg.Location)
	assert.Equal(t, "proj", cfg.Project)
}

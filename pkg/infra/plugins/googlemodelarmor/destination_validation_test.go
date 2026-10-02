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

// project, location and template are interpolated into the request URL (location
// into the host) of a call that carries a cloud-platform bearer token, so each
// must be unable to change the host or the path.
func TestParseConfig_RejectsHostileDestinationFields(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, field, value string
	}{
		{"location host fragment", "location", "attacker.example#"},
		{"location with slash", "location", "a/b"},
		{"location subdomain", "location", "us-central1.evil.com"},
		{"location uppercase", "location", "US-CENTRAL1"},
		{"location userinfo", "location", "x@evil.com"},
		{"location without digit", "location", "global"},
		{"project path traversal", "project", "../other"},
		{"project query", "project", "p?x=1"},
		{"project slash", "project", "p/q"},
		{"project uppercase", "project", "Proj"},
		{"template path traversal", "template", "../x"},
		{"template query", "template", "t?x=1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := validSettings()
			s[tt.field] = tt.value
			_, err := parseConfig(s)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.field)
		})
	}
}

func TestParseConfig_AcceptsRealDestinationFields(t *testing.T) {
	t.Parallel()
	for _, loc := range []string{"us-central1", "europe-west4", "asia-northeast1", "northamerica-northeast2"} {
		s := validSettings()
		s["location"] = loc
		_, err := parseConfig(s)
		require.NoError(t, err, loc)
	}
	for _, project := range []string{"my-project-123", "proj", "123456789012"} {
		s := validSettings()
		s["project"] = project
		_, err := parseConfig(s)
		require.NoError(t, err, project)
	}
}

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

package keyscope

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScope_EmptyLeavesNamesUnchanged(t *testing.T) {
	t.Parallel()
	var s Scope
	assert.Equal(t, "trustgate:server:secret-key", s.Key("trustgate:server:secret-key"))
	assert.Equal(t, "{trafficlabels}", s.HashTag("trafficlabels"))
}

func TestScope_PrefixesNames(t *testing.T) {
	t.Parallel()
	s := Scope("dp-acme")
	assert.Equal(t, "dp-acme:gateway_events", s.Key("gateway_events"))
	assert.Equal(t, "{trafficlabels:dp-acme}", s.HashTag("trafficlabels"))
}

func TestValidate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		scope string
		ok    bool
	}{
		{"", true},
		{"dp-acme", true},
		{"dp_acme.v2", true},
		{"dp{acme}", false},
		{"dp:acme", false},
		{"dp*", false},
		{"dp?", false},
		{"dp[a]", false},
		{"dp acme", false},
		{strings.Repeat("a", 63), true},
		{strings.Repeat("a", 64), false},
	} {
		err := Validate(tc.scope)
		if tc.ok {
			assert.NoError(t, err, tc.scope)
		} else {
			assert.Error(t, err, tc.scope)
		}
	}
}

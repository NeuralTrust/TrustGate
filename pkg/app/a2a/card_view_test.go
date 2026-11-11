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

package a2a_test

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// card.v03.json is a 0.3 card from a2a-sdk 1.3.0's 0.3 conversion, and
// card.v10.json the card its server serves, which carries both versions'
// fields. Each has an unknown field, x-vendor-region, added by hand.
func TestRenderCard(t *testing.T) {
	t.Parallel()
	const endpoint = "https://acme.agents.example.com/research-bot/agents/0199a7c2-5d4e-7b8a-9c1d-2e3f4a5b6c7d"
	for _, tc := range []struct {
		card        string
		version     a2a.Version
		jsonrpcOnly bool
		golden      string
	}{
		{"card.v03.json", a2a.Version03, false, "card.v03.golden.json"},
		{"card.v03.json", a2a.Version03, true, "card.v03.jsonrpc_only.golden.json"},
		{"card.v10.json", a2a.Version10, false, "card.v10.golden.json"},
	} {
		got, err := a2a.RenderCard(readFixture(t, tc.card), tc.version, endpoint, tc.jsonrpcOnly)
		require.NoError(t, err)
		assert.JSONEq(t, string(readFixture(t, tc.golden)), string(got), tc.golden)
	}
}

func TestRenderCard_RefusesWhatIsNotACard(t *testing.T) {
	t.Parallel()
	_, err := a2a.RenderCard([]byte(`[]`), a2a.Version10, "https://gw", false)
	assert.Error(t, err)
}

func TestStreaming(t *testing.T) {
	t.Parallel()
	assert.True(t, a2a.Streaming([]byte(`{"capabilities":{"streaming":true}}`)))
	assert.False(t, a2a.Streaming([]byte(`{"capabilities":{"streaming":false}}`)))
	assert.False(t, a2a.Streaming([]byte(`{"capabilities":{}}`)))
	assert.False(t, a2a.Streaming([]byte(`{"name":"x"}`)))
}

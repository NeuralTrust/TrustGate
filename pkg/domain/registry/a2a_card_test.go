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

package registry

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	card10 = `{"name":"Travel planner","supportedInterfaces":[{"url":"https://travel.example.com/a2a","protocolBinding":"JSONRPC","protocolVersion":"1.0"}],"skills":[{"id":"book_trip","name":"Book"}]}`
	card03 = `{"name":"Travel planner","url":"https://travel.example.com/rpc","protocolVersion":"0.3.0"}`
	cardBoth = `{"name":"Travel planner","url":"https://travel.example.com/rpc","protocolVersion":"0.3.0",` +
		`"supportedInterfaces":[{"url":"https://travel.example.com/a2a","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`
	cardGRPC = `{"name":"Travel planner","supportedInterfaces":[{"url":"https://travel.example.com:443","protocolBinding":"GRPC","protocolVersion":"1.0"}]}`
)

func TestDetectVersions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		card string
		want []A2AProtocolVersion
	}{
		{"1.0 json-rpc", card10, []A2AProtocolVersion{A2AVersion10}},
		{"0.3 url", card03, []A2AProtocolVersion{A2AVersion03}},
		{"both", cardBoth, []A2AProtocolVersion{A2AVersion03, A2AVersion10}},
		{"grpc only", cardGRPC, nil},
		{"0.3 without protocolVersion", `{"name":"a","url":"https://a.example.com"}`, []A2AProtocolVersion{A2AVersion03}},
		{"0.2 card", `{"name":"a","url":"https://a.example.com","protocolVersion":"0.2.5"}`, nil},
		{"0.3 additional json-rpc interface", `{"name":"a","url":"https://a.example.com/grpc","protocolVersion":"0.3.0","preferredTransport":"GRPC",` +
			`"additionalInterfaces":[{"url":"https://a.example.com/rpc","transport":"JSONRPC"}]}`, []A2AProtocolVersion{A2AVersion03}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, DetectVersions([]byte(tt.card)))
		})
	}
}

func TestInterfaceURL(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "https://travel.example.com/a2a", InterfaceURL([]byte(cardBoth), A2AVersion10))
	assert.Equal(t, "https://travel.example.com/rpc", InterfaceURL([]byte(cardBoth), A2AVersion03))
	preferredGRPC := `{"name":"a","url":"https://a.example.com/grpc","protocolVersion":"0.3.0","preferredTransport":"GRPC",` +
		`"additionalInterfaces":[{"url":"https://a.example.com/rpc","transport":"JSONRPC"}]}`
	assert.Equal(t, "https://a.example.com/rpc", InterfaceURL([]byte(preferredGRPC), A2AVersion03))
	assert.Empty(t, InterfaceURL([]byte(cardGRPC), A2AVersion10))
}

func TestValidateCard(t *testing.T) {
	t.Parallel()
	require.NoError(t, ValidateCard([]byte(card10)))
	for _, raw := range []string{`[]`, `"x"`, `{}`, `{"name":"  "}`, `not json`} {
		assert.True(t, errors.Is(ValidateCard([]byte(raw)), ErrAgentCardUnavailable), raw)
	}
}

func TestCardDigestIgnoresKeyOrderAndSignatures(t *testing.T) {
	t.Parallel()
	a, err := CardDigest([]byte(`{"name":"x","skills":[{"id":"a"}],"version":1.10}`))
	require.NoError(t, err)
	b, err := CardDigest([]byte(`{"version":1.10, "signatures":[{"protected":"p","signature":"s"}],"skills":[{"id":"a"}],"name":"x"}`))
	require.NoError(t, err)
	assert.Equal(t, a, b)
	assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, a)

	c, err := CardDigest([]byte(`{"name":"y","skills":[{"id":"a"}],"version":1.10}`))
	require.NoError(t, err)
	assert.NotEqual(t, a, c)
}

func TestChangedFieldsAndSkillDiff(t *testing.T) {
	t.Parallel()
	before := []byte(`{"name":"x","description":"d","skills":[{"id":"book_trip"},{"id":"cancel_trip"}],"signatures":[1]}`)
	after := []byte(`{"name":"x","description":"d","skills":[{"id":"book_trip"},{"id":"refund_invoice"}],"signatures":[2],"version":"2"}`)

	assert.Equal(t, []string{"skills", "version"}, ChangedFields(before, after))
	added, removed := SkillDiff(before, after)
	assert.Equal(t, []string{"refund_invoice"}, added)
	assert.Equal(t, []string{"cancel_trip"}, removed)
	assert.Empty(t, ChangedFields(before, before))
}

func TestDefaultVersion(t *testing.T) {
	t.Parallel()
	assert.Equal(t, A2AVersion10, DefaultVersion([]A2AProtocolVersion{A2AVersion03, A2AVersion10}))
	assert.Equal(t, A2AVersion03, DefaultVersion([]A2AProtocolVersion{A2AVersion03}))
	assert.Empty(t, DefaultVersion(nil))
}

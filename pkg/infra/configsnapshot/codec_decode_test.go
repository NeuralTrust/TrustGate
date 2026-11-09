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

package configsnapshot

import (
	"encoding/json"
	"testing"
	"time"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"github.com/stretchr/testify/require"
)

func TestDecodeJSONPreservesEntitiesAndAdjustments(t *testing.T) {
	t.Parallel()
	type entity struct {
		Name   string
		Values []int
	}
	calls := 0
	got, err := decodeJSON[string, entity](
		[]string{`{"name":"first","values":[1]}`, `{"name":"second","values":[2]}`},
		"test entity",
		func(raw string) []byte { return []byte(raw) },
		func(_ string, value *entity) {
			value.Name += " adjusted"
			calls++
		},
	)
	require.NoError(t, err)
	require.Equal(t, []entity{{Name: "first adjusted", Values: []int{1}}, {Name: "second adjusted", Values: []int{2}}}, got)
	require.Equal(t, 2, calls)
	got[0].Values[0] = 99
	require.Equal(t, []int{2}, got[1].Values)
}

func TestDecodeJSONEmptyReturnsAnEmptySlice(t *testing.T) {
	t.Parallel()
	for _, messages := range [][]string{nil, {}} {
		got, err := decodeJSON[string, int](messages, "test entity", func(raw string) []byte { return []byte(raw) }, nil)
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Empty(t, got)
	}
}

func TestDecodeJSONRejectsMalformedEntitiesWithoutPartialResults(t *testing.T) {
	t.Parallel()
	calls := 0
	got, err := decodeJSON[string, int]([]string{"1", "{"}, "test entity",
		func(raw string) []byte { return []byte(raw) },
		func(_ string, _ *int) { calls++ },
	)
	require.Nil(t, got)
	require.ErrorContains(t, err, "configsnapshot: unmarshal test entity")
	var syntax *json.SyntaxError
	require.ErrorAs(t, err, &syntax)
	require.Equal(t, 1, calls)
}

func TestDecodeJSONRetainsLegacyInputSemantics(t *testing.T) {
	t.Parallel()
	type entity struct {
		Name      string           `json:"name"`
		GatewayID string           `json:"gateway_id"`
		Values    []map[string]int `json:"values"`
		CreatedAt time.Time        `json:"created_at"`
	}
	for _, tc := range []struct{ name, raw string }{
		{"case insensitive", `{"NAME":"legacy","GATEWAY_ID":"gateway"}`},
		{"case alias duplicates", `{"NAME":"first","name":"last"}`},
		{"delimiter sensitive", `{"gateway-id":"ignored","gatewayid":"also ignored"}`},
		{"duplicate scalar and null", `{"name":"kept","name":null}`},
		{"duplicate nested collections", `{"values":[{"kept":1}],"values":[null]}`},
		{"invalid utf8", "{\"name\":\"\xff\"}"},
		{"legacy timestamp", `{"created_at":"2026-11-09T1:02:03Z"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var want entity
			require.NoError(t, json.Unmarshal([]byte(tc.raw), &want))
			got, err := decodeJSON[string, entity]([]string{tc.raw}, "legacy entity", func(raw string) []byte { return []byte(raw) }, nil)
			require.NoError(t, err)
			require.Equal(t, []entity{want}, got)
		})
	}
}

func TestSnapshotJSONRejectsMalformedInputWithoutPartialMutations(t *testing.T) {
	t.Parallel()
	type entity struct {
		Name   string `json:"name"`
		Values []int  `json:"values"`
	}
	raw := []byte(`{"name":"partial","values":[1,`)
	var want, got entity
	require.Error(t, json.Unmarshal(raw, &want))
	err := unmarshalSnapshotJSON(raw, &got)
	var syntax *json.SyntaxError
	require.ErrorAs(t, err, &syntax)
	require.Equal(t, want, got)
}

func TestCodecPreservesFallbackNanoseconds(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		fallback *consumerdomain.Fallback
	}{
		{name: "nil"},
		{name: "zero", fallback: &consumerdomain.Fallback{}},
		{name: "nanoseconds", fallback: &consumerdomain.Fallback{Budget: consumerdomain.FallbackBudget{MaxAttempts: 3, MaxTotalLatency: 2*time.Second + 123*time.Nanosecond}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gatewayID := ids.New[ids.GatewayKind]()
			consumerID := ids.New[ids.ConsumerKind]()
			codec := NewCodec()
			raw, err := codec.Encode(readmodel.Build(readmodel.Data{
				Gateways:  []gatewaydomain.Gateway{{ID: gatewayID, Slug: "fallback", Entitlements: gatewaydomain.DefaultEntitlements()}},
				Consumers: []consumerdomain.Consumer{{ID: consumerID, GatewayID: gatewayID, Slug: "consumer", Fallback: tc.fallback}},
			}))
			require.NoError(t, err)
			decoded, err := codec.Decode(raw)
			require.NoError(t, err)
			consumer, ok := decoded.ConsumerByID(consumerID)
			require.True(t, ok)
			require.Equal(t, tc.fallback, consumer.Fallback)
			reencoded, err := codec.Encode(decoded)
			require.NoError(t, err)
			require.Equal(t, raw, reencoded)
		})
	}
}

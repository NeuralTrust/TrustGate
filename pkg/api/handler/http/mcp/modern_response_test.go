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

package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/stretchr/testify/require"
)

func TestNormalizeModernResult(t *testing.T) {
	t.Parallel()
	defaultTTL := modernCacheTTLDefault
	readTTL := modernCacheTTLRead
	cases := map[string]*int{
		"server/discover":          &defaultTTL,
		"tools/list":               &defaultTTL,
		"resources/list":           &defaultTTL,
		"resources/templates/list": &defaultTTL,
		"prompts/list":             &defaultTTL,
		"resources/read":           &readTTL,
		"tools/call":               nil,
		"prompts/get":              nil,
	}
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{}}
	for method, wantTTL := range cases {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			source := map[string]any{
				"value":      "preserved",
				"resultType": "input_required",
				"ttlMs":      1,
				"cacheScope": "public",
				"_meta": map[string]any{
					"upstream":          "preserved",
					modernServerInfoKey: map[string]any{"name": "upstream", "version": "0"},
				},
			}
			normalized, err := normalizeModernResult(method, source, rc, nil)
			require.NoError(t, err)
			require.Equal(t, "preserved", normalized["value"])
			// Only tools/call may keep an upstream input_required; every other
			// method is forced back to complete.
			wantResultType := "complete"
			if method == "tools/call" {
				wantResultType = "input_required"
			}
			require.Equal(t, wantResultType, normalized["resultType"])
			metadata := normalized["_meta"].(map[string]any)
			require.Equal(t, "preserved", metadata["upstream"])
			serverInfo := metadata[modernServerInfoKey].(map[string]any)
			require.Equal(t, serverName, serverInfo["name"])
			require.Equal(t, serverVersion+"+"+surfaceFingerprint(rc), serverInfo["version"])
			if wantTTL == nil {
				require.NotContains(t, normalized, "ttlMs")
				require.NotContains(t, normalized, "cacheScope")
			} else {
				require.Equal(t, *wantTTL, normalized["ttlMs"])
				require.Equal(t, "private", normalized["cacheScope"])
			}
			require.Equal(t, "input_required", source["resultType"])
			require.Equal(t, "public", source["cacheScope"])
			require.Equal(t, "upstream", source["_meta"].(map[string]any)[modernServerInfoKey].(map[string]any)["name"])
		})
	}
}

// The terminal frame of a lease is a result and is normalized as one, but it
// describes a stream that has already ended, so it is never cacheable.
func TestNormalizeModernResultSubscriptionsListenIsUncacheable(t *testing.T) {
	t.Parallel()
	id := json.RawMessage(`7`)
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{}}
	honoured := appmcp.NewHonouredSet(appmcp.NotificationToolsListChanged)

	normalized, err := normalizeModernResult(
		appmcp.MethodSubscriptionsListen,
		subscriptionsListenResult(id, honoured),
		rc,
		nil,
	)
	require.NoError(t, err)

	require.Equal(t, "complete", normalized["resultType"])
	require.Equal(t, modernCacheTTLRead, normalized["ttlMs"])
	require.Equal(t, "private", normalized["cacheScope"])
	require.Equal(t, []any{"toolsListChanged"}, normalized["notifications"])
	metadata := normalized["_meta"].(map[string]any)
	require.Equal(t, json.Number("7"), metadata[appmcp.MetaKeySubscriptionID])
	require.Contains(t, metadata, modernServerInfoKey)
}

// The frames a lease streams are notifications, not results, so they bypass
// normalization entirely: a client must never cache one or read a resultType off
// it.
func TestSubscriptionNotificationFramesAreNotResults(t *testing.T) {
	t.Parallel()
	id := json.RawMessage(`7`)
	honoured := appmcp.NewHonouredSet(appmcp.NotificationToolsListChanged)
	ack, err := json.Marshal(subscriptionAckNotification(id, honoured))
	require.NoError(t, err)
	frames, err := subscriptionNotificationFrames(id, honoured)
	require.NoError(t, err)

	cases := []struct {
		name       string
		frame      []byte
		wantMethod string
	}{
		{name: "ack", frame: ack, wantMethod: methodSubscriptionsAcknowledged},
		{
			name:       "list changed",
			frame:      frames[appmcp.NotificationToolsListChanged],
			wantMethod: appmcp.NotificationToolsListChanged.Method(),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var decoded map[string]any
			require.NoError(t, json.Unmarshal(tc.frame, &decoded))

			require.Equal(t, tc.wantMethod, decoded["method"])
			require.NotContains(t, decoded, "id")
			require.NotContains(t, decoded, "result")
			require.NotContains(t, decoded, "resultType")
			require.NotContains(t, decoded, "ttlMs")
			require.NotContains(t, decoded, "cacheScope")
			require.NotContains(t, decoded, "_meta")
			params := decoded["params"].(map[string]any)
			require.Equal(t, float64(7), params["_meta"].(map[string]any)[appmcp.MetaKeySubscriptionID])
		})
	}
}

func TestNormalizeModernResultToolsCallKeepsContinuation(t *testing.T) {
	t.Parallel()
	source := map[string]any{
		"resultType":   "input_required",
		"requestState": "tg1.c.payload.sig",
		"inputRequests": map[string]any{
			"confirm": map[string]any{"method": "elicitation/create", "params": map[string]any{}},
		},
	}
	caps := map[string]any{"elicitation": map[string]any{}}

	normalized, err := normalizeModernResult("tools/call", source, nil, caps)
	require.NoError(t, err)
	require.Equal(t, "input_required", normalized["resultType"])
	require.Equal(t, "tg1.c.payload.sig", normalized["requestState"])
	require.Contains(t, normalized["inputRequests"], "confirm")
}

func TestNormalizeModernResultToolsCallDropsUndeclaredKinds(t *testing.T) {
	t.Parallel()
	source := map[string]any{
		"resultType":   "input_required",
		"requestState": "tg1.c.payload.sig",
		"inputRequests": map[string]any{
			"confirm": map[string]any{"method": "elicitation/create"},
			"sample":  map[string]any{"method": "sampling/createMessage"},
			"weird":   map[string]any{"method": "made/up"},
		},
	}
	caps := map[string]any{"elicitation": map[string]any{}}

	normalized, err := normalizeModernResult("tools/call", source, nil, caps)
	require.NoError(t, err)
	requests, ok := normalized["inputRequests"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, requests, "confirm")
	require.NotContains(t, requests, "sample")
	require.NotContains(t, requests, "weird")
}

func TestNormalizeModernResultNonToolsStripsMRTRFields(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"prompts/get", "resources/read"} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			source := map[string]any{
				"resultType":    "input_required",
				"requestState":  "tg1.c.payload.sig",
				"inputRequests": map[string]any{"confirm": map[string]any{"method": "elicitation/create"}},
			}
			caps := map[string]any{"elicitation": map[string]any{}}

			normalized, err := normalizeModernResult(method, source, nil, caps)
			require.NoError(t, err)
			require.Equal(t, "complete", normalized["resultType"])
			require.NotContains(t, normalized, "requestState")
			require.NotContains(t, normalized, "inputRequests")
		})
	}
}

func TestNormalizeModernResultPreservesJSONNumbers(t *testing.T) {
	t.Parallel()
	normalized, err := normalizeModernResult("tools/call", json.RawMessage(`{"value":9007199254740993}`), nil, nil)
	require.NoError(t, err)
	raw, err := json.Marshal(normalized)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"value":9007199254740993`)
}

func TestNormalizeModernToolsListConcurrentImmutability(t *testing.T) {
	t.Parallel()
	var tool appmcp.Tool
	require.NoError(t, json.Unmarshal([]byte(`{
		"name":"search",
		"x-mcp-header":"top",
		"inputSchema":{
			"type":"object",
			"x-mcp-header":"schema",
			"properties":{
				"query":{"type":"string","x-mcp-header":"X-Query"},
				"nested":{"type":"array","items":[{"x-mcp-header":"array"},{"type":"string"}]}
			}
		}
	}`), &tool))
	source := map[string]any{"tools": []appmcp.Tool{tool}, "x-mcp-header": "result"}
	before, err := json.Marshal(source)
	require.NoError(t, err)

	const workers = 32
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			normalized, err := normalizeModernResult("tools/list", source, nil, nil)
			if err != nil {
				errs <- err
				return
			}
			if containsMCPHeaderAnnotation(normalized) {
				errs <- fmt.Errorf("modern result retained x-mcp-header")
				return
			}
			legacy, err := json.Marshal(source)
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(before, legacy) {
				errs <- fmt.Errorf("shared result mutated")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	after, err := json.Marshal(source)
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.True(t, containsMCPHeaderAnnotation(decodeJSONValue(t, after)))
}

func decodeJSONValue(t *testing.T, raw []byte) any {
	t.Helper()
	var value any
	require.NoError(t, json.Unmarshal(raw, &value))
	return value
}

func containsMCPHeaderAnnotation(value any) bool {
	switch current := value.(type) {
	case map[string]any:
		if _, ok := current["x-mcp-header"]; ok {
			return true
		}
		for _, nested := range current {
			if containsMCPHeaderAnnotation(nested) {
				return true
			}
		}
	case []any:
		for _, nested := range current {
			if containsMCPHeaderAnnotation(nested) {
				return true
			}
		}
	}
	return false
}

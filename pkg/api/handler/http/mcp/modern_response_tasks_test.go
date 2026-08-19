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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// A created task owns resultType and ttlMs. Both used to be scrubbed, which
// turned a CreateTaskResult into a bogus complete result carrying a bare taskId.
func TestNormalizeModernResult_PreservesCreatedTask(t *testing.T) {
	t.Parallel()
	source := map[string]any{
		"resultType":     "task",
		"taskId":         "tg1k.c.handle",
		"status":         "working",
		"createdAt":      "2026-01-01T00:00:00Z",
		"ttlMs":          json.Number("600000"),
		"pollIntervalMs": json.Number("1000"),
	}

	normalized, err := normalizeModernResult("tools/call", source, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "task", normalized["resultType"])
	require.Equal(t, json.Number("600000"), normalized["ttlMs"])
	require.Equal(t, json.Number("1000"), normalized["pollIntervalMs"])
	require.Equal(t, "tg1k.c.handle", normalized["taskId"])
	require.NotContains(t, normalized, "cacheScope")
}

// A polled task is an ordinary modern result: it reports complete, is never
// cached, and keeps only the input requests the client can actually answer.
func TestNormalizeModernResult_TasksGetReportsComplete(t *testing.T) {
	t.Parallel()
	source := map[string]any{
		"taskId": "tg1k.c.handle",
		"status": "input_required",
		"ttlMs":  json.Number("600000"),
		"inputRequests": map[string]any{
			"declared":   map[string]any{"method": "elicitation/create"},
			"undeclared": map[string]any{"method": "sampling/createMessage"},
		},
	}
	caps := map[string]any{"elicitation": map[string]any{}}

	normalized, err := normalizeModernResult("tasks/get", source, nil, caps)
	require.NoError(t, err)
	require.Equal(t, "complete", normalized["resultType"])
	require.Equal(t, modernCacheTTLRead, normalized["ttlMs"])
	require.Equal(t, "private", normalized["cacheScope"])
	requests, ok := normalized["inputRequests"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, requests, "declared")
	require.NotContains(t, requests, "undeclared")
}

// resultType: "task" is meaningful only on tools/call. Anywhere else it is an
// upstream field that must not survive.
func TestNormalizeModernResult_TaskResultTypeOnlyOnToolsCall(t *testing.T) {
	t.Parallel()
	source := map[string]any{"resultType": "task", "taskId": "u-123"}

	normalized, err := normalizeModernResult("tools/list", source, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "complete", normalized["resultType"])
}

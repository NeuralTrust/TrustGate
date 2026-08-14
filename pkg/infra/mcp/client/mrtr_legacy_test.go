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

package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// The legacy era has no continuation contract, so a ticketed call must reach the
// upstream as a plain tools/call: forwarding MRTR fields would ask a server that
// cannot honour them to interpret gateway state.
func TestLegacySession_CallTool_DropsContinuation(t *testing.T) {
	t.Parallel()
	var (
		mu     sync.Mutex
		bodies []string
	)
	capture := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read body: %v", err)
			}
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))
			mu.Lock()
			bodies = append(bodies, string(body))
			mu.Unlock()
			next.ServeHTTP(w, r)
		})
	}
	srv := newUpstream(t, addEchoTool, capture)
	sess := connect(t, appmcp.Target{URL: srv.URL})

	raw, err := sess.CallTool(context.Background(), appmcp.ToolCall{
		Name:           "echo",
		Arguments:      json.RawMessage(`{"message":"hi"}`),
		InputResponses: json.RawMessage(`{"q1":{"action":"accept","content":{"city":"Madrid"}}}`),
		RequestState:   "upstream-state-1",
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	var result sdk.CallToolResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	sawCall := false
	for _, body := range bodies {
		if !strings.Contains(body, `"tools/call"`) {
			continue
		}
		sawCall = true
		if strings.Contains(body, "requestState") ||
			strings.Contains(body, "inputResponses") ||
			strings.Contains(body, "Madrid") {
			t.Fatalf("legacy tools/call carried continuation fields: %s", body)
		}
	}
	if !sawCall {
		t.Fatal("no tools/call reached the upstream")
	}
}

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

package main

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNeedsURLConfig(t *testing.T) {
	t.Parallel()
	if !needsURLConfig(map[string]any{}, "https://x.example/{tenant}/mcp") {
		t.Fatal("expected template URL to need config")
	}
	if needsURLConfig(map[string]any{}, "https://x.example/mcp") {
		t.Fatal("plain URL should not need config")
	}
	s := map[string]any{
		"url_variables": []any{map[string]any{"name": "tenant", "required": true}},
	}
	if !needsURLConfig(s, "https://x.example/mcp") {
		t.Fatal("required url_variables should need config")
	}
}

func TestLooksLikeMCPInitialize(t *testing.T) {
	t.Parallel()
	ok := []byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"x"}}}`)
	if !looksLikeMCPInitialize(ok) {
		t.Fatal("expected valid initialize result")
	}
	rpcErr := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"auth"}}`)
	if !looksLikeMCPInitialize(rpcErr) {
		t.Fatal("MCP-level error still means protocol reached")
	}
	if looksLikeMCPInitialize([]byte(`{"ok":true}`)) {
		t.Fatal("non-MCP JSON should fail")
	}
}

func TestClassifyDialError(t *testing.T) {
	t.Parallel()
	status, _ := classifyDialError(context.DeadlineExceeded)
	if status != statusBrokenUnreach {
		t.Fatalf("deadline => %s", status)
	}
	status, _ = classifyDialError(&net.DNSError{Err: "no such host", Name: "x", IsNotFound: true})
	if status != statusBrokenUnreach {
		t.Fatalf("dns => %s", status)
	}
	status, _ = classifyDialError(timeoutError{})
	if status != statusBrokenUnreach {
		t.Fatalf("timeout => %s", status)
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestProbeOne_SSE(t *testing.T) {
	t.Parallel()
	r := probeOne(nil, time.Second, map[string]any{
		"name":       "io.invideo/mcp",
		"vendor":     "InVideo",
		"transport":  "sse",
		"server_url": "https://mcp.invideo.io/sse",
	})
	if r.Status != statusBrokenUnsupp {
		t.Fatalf("status = %s, want %s", r.Status, statusBrokenUnsupp)
	}
}

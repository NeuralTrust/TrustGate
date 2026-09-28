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

package mcp_test

import (
	"fmt"
	"strings"
	"testing"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
)

// A dial failure names the upstream address, which for a server with per-user
// URL variables can carry the user's token. The client must get a fixed
// message; the detail stays in the server log.
func TestHandler_ToolsCall_UnreachableUpstreamIsGeneric(t *testing.T) {
	t.Parallel()
	const secretURL = "https://mcp.brightdata.com/mcp?token=supersecret123"
	cases := []struct {
		name        string
		fromResolve bool
		err         error
	}{
		{
			name: "unreachable",
			err:  fmt.Errorf("%w: %s: dial tcp: connection refused", appmcp.ErrUnreachable, secretURL),
		},
		{
			name:        "unavailable (fail-closed)",
			fromResolve: true,
			err: fmt.Errorf("%w: registry %q: %w", appmcp.ErrUpstreamUnavailable, "brightdata",
				fmt.Errorf("%w: %s: dial tcp: connection refused", appmcp.ErrUnreachable, secretURL)),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			composer := mocks.NewComposer(t)
			if tc.fromResolve {
				composer.EXPECT().Resolve(mock.Anything, mock.Anything, "scrape").Return(nil, tc.err).Once()
			} else {
				expectToolCall(composer, "scrape", nil, tc.err)
			}
			app := newApp(t, composer, consumerdomain.TypeMCP, true)

			status, body := rpcCall(t, app, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"scrape"}}`)
			if status != fiber.StatusOK {
				t.Fatalf("JSON-RPC errors ride on HTTP 200, got %d", status)
			}
			rpcErr, _ := body["error"].(map[string]any)
			if rpcErr == nil {
				t.Fatalf("no error in body: %v", body)
			}
			msg, _ := rpcErr["message"].(string)
			if msg != "upstream MCP server unreachable" {
				t.Fatalf("message = %q, want the generic unreachable message", msg)
			}
			raw := fmt.Sprint(body)
			if strings.Contains(raw, "supersecret123") || strings.Contains(raw, "brightdata.com") {
				t.Fatalf("upstream URL or secret leaked to the client: %s", raw)
			}
		})
	}
}

// A per-user URL configuration problem is the caller's to fix, so it is an
// invalid request rather than an internal error — and the text names the
// variable, never a value.
func TestHandler_ToolsCall_URLTemplateErrorIsInvalidRequest(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	expectToolCall(composer, "query", nil,
		fmt.Errorf("%w: missing required variable %q", registrydomain.ErrURLTemplate, "account_url"))
	app := newApp(t, composer, consumerdomain.TypeMCP, true)

	_, body := rpcCall(t, app, `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"query"}}`)
	rpcErr, _ := body["error"].(map[string]any)
	if rpcErr == nil || rpcErr["code"].(float64) != -32600 {
		t.Fatalf("error = %v, want invalid request (-32600)", rpcErr)
	}
	if msg, _ := rpcErr["message"].(string); !strings.Contains(msg, "account_url") {
		t.Fatalf("message should name the variable: %q", msg)
	}
}

// Every error above the default branch was written for a caller to read. An
// error that falls through was not: it is whatever the layer that raised it
// produced, and relaying it hands a remote client the gateway's internals —
// a resolved upstream URL with a token in its query, a driver message, a path.
func TestHandler_ToolsCall_UnclassifiedErrorIsGeneric(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().Resolve(mock.Anything, mock.Anything, "scrape").
		Return(nil, fmt.Errorf(
			"post %q: pq: relation \"vault_credentials\" does not exist",
			"https://mcp.brightdata.com/mcp?token=supersecret123",
		)).Once()
	app := newApp(t, composer, consumerdomain.TypeMCP, true)

	status, body := rpcCall(t, app, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"scrape"}}`)
	if status != fiber.StatusOK {
		t.Fatalf("JSON-RPC errors ride on HTTP 200, got %d", status)
	}
	rpcErr, _ := body["error"].(map[string]any)
	if rpcErr == nil {
		t.Fatalf("no error in body: %v", body)
	}
	if code, _ := rpcErr["code"].(float64); int(code) != -32603 {
		t.Fatalf("code = %v, want internal error (-32603)", rpcErr["code"])
	}
	if msg, _ := rpcErr["message"].(string); msg != "internal error" {
		t.Fatalf("message = %q, want the generic internal message", msg)
	}
	raw := fmt.Sprint(body)
	for _, leak := range []string{"supersecret123", "brightdata.com", "vault_credentials"} {
		if strings.Contains(raw, leak) {
			t.Fatalf("internal detail %q leaked to the client: %s", leak, raw)
		}
	}
}

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

//go:build functional

package functional_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// keyedUpstream is an MCP server that authenticates each caller by their own
// X-API-Key, the way an upstream without OAuth does, and records the keys it
// was sent.
type keyedUpstream struct {
	server *httptest.Server
	mu     sync.Mutex
	keys   []string
	revoke map[string]bool
}

func startKeyedUpstream(t *testing.T) *keyedUpstream {
	t.Helper()
	mcp := sdk.NewServer(&sdk.Implementation{Name: "keyed-upstream", Version: "1.0"}, nil)
	addTool(mcp, "echo")
	handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return mcp }, nil)
	up := &keyedUpstream{revoke: map[string]bool{}}
	up.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		up.mu.Lock()
		up.keys = append(up.keys, key)
		refused := key == "" || up.revoke[key]
		up.mu.Unlock()
		if refused {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(up.server.Close)
	return up
}

func (u *keyedUpstream) seen() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.keys...)
}

func (u *keyedUpstream) reset() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.keys = nil
}

func (u *keyedUpstream) refuse(key string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.revoke[key] = true
}

func endUserHeaders(key, endUser string) map[string]string {
	return map[string]string{"X-AG-API-Key": key, "X-NeuralTrust-End-User": endUser}
}

func importUserHeaders(t *testing.T, gatewayID, registryID string, values []map[string]any) {
	t.Helper()
	target := fmt.Sprintf("%s/v1/gateways/%s/registries/%s/user-headers/values", AdminURL, gatewayID, registryID)
	status, body := sendRequest(t, http.MethodPut, target, nil, map[string]any{"values": values})
	require.Equal(t, http.StatusOK, status, "import failed: %v", body)
	require.Equal(t, float64(len(values)), body["count"])
}

// requireConsentCause asserts the -32003 a person gets and returns the
// connect ticket it carries.
func requireConsentCause(t *testing.T, status int, body map[string]any, cause string) string {
	t.Helper()
	require.Equal(t, http.StatusOK, status)
	rpcErr, ok := body["error"].(map[string]any)
	require.True(t, ok, "expected a consent error, got %v", body)
	require.Equal(t, float64(-32003), rpcErr["code"], "body=%v", body)
	data, _ := rpcErr["data"].(map[string]any)
	require.Equal(t, cause, data["cause"], "body=%v", body)
	link, _ := data["connect_url"].(string)
	require.NotEmpty(t, link, "a person is handed the link to enter their key: %v", body)
	parsed, err := url.Parse(link)
	require.NoError(t, err)
	ticket := parsed.Query().Get("ticket")
	require.NotEmpty(t, ticket, "the link carries a ticket: %s", link)
	return ticket
}

// enterKeyOnConnectPage does what a person's browser does: open the link,
// then post the form the page shows.
func enterKeyOnConnectPage(t *testing.T, ticket, registryID string, form url.Values) string {
	t.Helper()
	page := doWith(t, noRedirectClient(), http.MethodGet, MCPURL+"/+/connect?ticket="+url.QueryEscape(ticket), "connect page", nil)
	html, err := io.ReadAll(page.Body)
	_ = page.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, page.StatusCode)
	action := "/oauth/user-headers/" + registryID + "?ticket=" + ticket
	require.Contains(t, string(html), action, "the page offers the form for this server")

	req, err := http.NewRequest(http.MethodPost, MCPURL+action, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", MCPURL)
	resp, err := noRedirectClient().Do(req)
	require.NoError(t, err)
	saved, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "save failed: %s", saved)
	return string(saved)
}

// Ana and Bruno reach the same header-authenticated upstream through one
// application; each call carries the caller's own key, never the other's, and
// the key never leaves the gateway.
func TestMCPUserHeaders_EachPersonSendsTheirOwnKey(t *testing.T) {
	up := startKeyedUpstream(t)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(t, gatewayID, map[string]any{
		"name": uniqueName("keyed"), "type": "mcp", "weight": 1,
		"mcp_target": map[string]any{
			"url":  up.server.URL,
			"auth": map[string]any{"mode": "none"},
			"user_headers": []map[string]any{
				{"name": "X-API-Key", "required": true, "secret": true, "description": "Your personal API key"},
			},
		},
	})
	consumerID, key := createMCPConsumer(t, gatewayID, []string{registryID}, nil, "")
	echo := map[string]any{"name": exposedToolName(registryID, "echo"), "arguments": map[string]any{"message": "hola"}}
	ana, bruno := "app:"+consumerID+":ana", "app:"+consumerID+":bruno"

	t.Run("the application itself has no key of its own", func(t *testing.T) {
		status, body := mcpRPC(t, gatewayID, consumerID, apiKeyHeaders(key), "tools/call", echo)
		requireNotConnected(t, status, body, false)
		require.Empty(t, up.seen(), "a refused call must not reach the upstream")
	})

	t.Run("a person without a key enters it through the link they are handed", func(t *testing.T) {
		status, body := mcpRPC(t, gatewayID, consumerID, endUserHeaders(key, "ana"), "tools/call", echo)
		ticket := requireConsentCause(t, status, body, "user_header_missing")
		require.Empty(t, up.seen())

		page := enterKeyOnConnectPage(t, ticket, registryID, url.Values{"X-API-Key": {"ana-key"}})
		require.NotContains(t, page, "ana-key", "the saved key is never written back into the page")
		require.Contains(t, page, "Saved")
	})

	// Bruno's key is loaded by an admin, the other way to enroll.
	importUserHeaders(t, gatewayID, registryID, []map[string]any{
		{"principal_sub": bruno, "header": "x-api-key", "value": "bruno-key"},
	})

	t.Run("each person's call carries their own key", func(t *testing.T) {
		for person, want := range map[string]string{"ana": "ana-key", "bruno": "bruno-key"} {
			up.reset()
			status, body := mcpRPC(t, gatewayID, consumerID, endUserHeaders(key, person), "tools/call", echo)
			requireRPCSucceeded(t, status, body)
			seen := up.seen()
			require.NotEmpty(t, seen, "%s must reach the upstream", person)
			for _, got := range seen {
				require.Equal(t, want, got, "%s's call carried another key", person)
			}
		}
	})

	t.Run("a key the client sends never reaches the upstream", func(t *testing.T) {
		up.reset()
		headers := endUserHeaders(key, "ana")
		headers["X-API-Key"] = "forged-key"
		status, body := mcpRPC(t, gatewayID, consumerID, headers, "tools/call", echo)
		requireRPCSucceeded(t, status, body)
		for _, got := range up.seen() {
			require.Equal(t, "ana-key", got)
		}
	})

	t.Run("an admin sees who holds a key, never the key", func(t *testing.T) {
		target := fmt.Sprintf("%s/v1/gateways/%s/registries/%s/user-headers", AdminURL, gatewayID, registryID)
		status, body := sendRequest(t, http.MethodGet, target, nil, nil)
		require.Equal(t, http.StatusOK, status, "body=%v", body)
		raw := fmt.Sprint(body)
		require.Contains(t, raw, ana)
		require.Contains(t, raw, bruno)
		require.NotContains(t, raw, "ana-key")
		require.NotContains(t, raw, "bruno-key")
	})

	t.Run("a key the upstream refuses must be entered again", func(t *testing.T) {
		up.refuse("bruno-key")
		status, body := mcpRPC(t, gatewayID, consumerID, endUserHeaders(key, "bruno"), "tools/call", echo)
		_ = requireConsentCause(t, status, body, "user_header_rejected")
		up.reset()
		status, body = mcpRPC(t, gatewayID, consumerID, endUserHeaders(key, "bruno"), "tools/call", echo)
		_ = requireConsentCause(t, status, body, "user_header_rejected")
		require.Empty(t, up.seen(), "a refused key is not sent again")

		status, body = mcpRPC(t, gatewayID, consumerID, endUserHeaders(key, "ana"), "tools/call", echo)
		requireRPCSucceeded(t, status, body)
	})

	t.Run("an admin reset asks everyone for their key again", func(t *testing.T) {
		target := fmt.Sprintf("%s/v1/gateways/%s/registries/%s/user-headers/values", AdminURL, gatewayID, registryID)
		status, body := sendRequest(t, http.MethodDelete, target, nil, nil)
		require.Equal(t, http.StatusOK, status, "body=%v", body)
		status, body = mcpRPC(t, gatewayID, consumerID, endUserHeaders(key, "ana"), "tools/call", echo)
		_ = requireConsentCause(t, status, body, "user_header_missing")
	})
}

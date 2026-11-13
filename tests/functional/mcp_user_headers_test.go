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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// perUserKeyUpstream is an MCP server that authenticates each caller by their own
// X-API-Key, the way an upstream without OAuth does, and records the keys it
// was sent.
type perUserKeyUpstream struct {
	server *httptest.Server
	mu     sync.Mutex
	keys   []string
	revoke map[string]bool
}

func startPerUserKeyUpstream(t *testing.T) *perUserKeyUpstream {
	t.Helper()
	mcp := sdk.NewServer(&sdk.Implementation{Name: "keyed-upstream", Version: "1.0"}, nil)
	addTool(mcp, "echo")
	handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return mcp }, nil)
	up := &perUserKeyUpstream{revoke: map[string]bool{}}
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

func (u *perUserKeyUpstream) seen() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.keys...)
}

func (u *perUserKeyUpstream) reset() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.keys = nil
}

func (u *perUserKeyUpstream) refuse(key string) {
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
	up := startPerUserKeyUpstream(t)
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

// mcpRPCAt is mcpRPC against a given MCP plane.
func mcpRPCAt(t *testing.T, base, gatewayID, consumerID string, headers map[string]string, method string, params any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, base+"/"+ConsumerSlug(t, consumerID)+"/mcp", strings.NewReader(string(raw)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	host, ok := gatewayHosts.Load(gatewayID)
	require.True(t, ok, "gateway host missing for %s", gatewayID)
	req.Host = host.(string)
	return doJSONRequest(t, req)
}

// On the MCP plane as production runs it — no database, reading the vault
// from the shared Redis only — a key an admin loads on the control plane is
// the key the plane sends, and an admin reset reaches it too.
func TestDBLessMCP_UserHeaderLoadedByAnAdminReachesTheDataPlane(t *testing.T) {
	defer Track(t, "DBLessDataPlane")()
	up := startPerUserKeyUpstream(t)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("dbless-keyed")})
	registryID := CreateRegistry(t, gatewayID, map[string]any{
		"name": uniqueName("keyed"), "type": "mcp", "weight": 1,
		"mcp_target": map[string]any{
			"url":          up.server.URL,
			"auth":         map[string]any{"mode": "none"},
			"user_headers": []map[string]any{{"name": "X-API-Key", "required": true, "secret": true}},
		},
	})
	consumerID, key := createMCPConsumer(t, gatewayID, []string{registryID}, nil, "")
	importUserHeaders(t, gatewayID, registryID, []map[string]any{
		{"principal_sub": "app:" + consumerID + ":ana", "header": "X-API-Key", "value": "ana-dbless-key"},
	})
	echo := map[string]any{"name": exposedToolName(registryID, "echo"), "arguments": map[string]any{"message": "hola"}}

	base, logs := startDBLessMCPPlane(t, GlobalConfig.Server.MCPPort+106, uniqueName("dbless-keyed"))
	require.Eventually(t, func() bool {
		up.reset()
		status, body := mcpRPCAt(t, base, gatewayID, consumerID, endUserHeaders(key, "ana"), "tools/call", echo)
		if status != http.StatusOK || body["error"] != nil {
			return false
		}
		for _, got := range up.seen() {
			if got != "ana-dbless-key" {
				return false
			}
		}
		return len(up.seen()) > 0
	}, 30*time.Second, 300*time.Millisecond, "the db-less plane never sent the imported key; logs:\n%s", logs.String())
	require.NotContains(t, logs.String(), "ana-dbless-key", "the key must never reach the plane's logs")

	target := fmt.Sprintf("%s/v1/gateways/%s/registries/%s/user-headers/values", AdminURL, gatewayID, registryID)
	status, body := sendRequest(t, http.MethodDelete, target, nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	status, body = mcpRPCAt(t, base, gatewayID, consumerID, endUserHeaders(key, "ana"), "tools/call", echo)
	_ = requireConsentCause(t, status, body, "user_header_missing")
}

// A person who signs in with the customer's IdP (OAuth inbound) holds their
// own key too: an admin hands them the link for a custom server through the
// virtual MCP that binds it, they enter the key on the page, and their calls
// carry it.
func TestMCPUserHeaders_OAuthCallerEnrollsThroughAnAdminLink(t *testing.T) {
	up := startPerUserKeyUpstream(t)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(t, gatewayID, map[string]any{
		"name": uniqueName("keyed"), "type": "mcp", "weight": 1,
		"mcp_target": map[string]any{
			"url":          up.server.URL,
			"auth":         map[string]any{"mode": "none"},
			"user_headers": []map[string]any{{"name": "X-API-Key", "required": true, "secret": true}},
		},
	})
	idp := newOAuthIDPStub(t)
	consumerID, audience := createOAuthMCPConsumer(t, gatewayID, []string{registryID}, idp)
	subject := uniqueName("carla")
	carla := bearerHeaders(idp.mint(t, audience, map[string]any{"sub": subject}))
	echo := map[string]any{"name": exposedToolName(registryID, "echo"), "arguments": map[string]any{"message": "hola"}}

	status, body := mcpRPC(t, gatewayID, consumerID, carla, "tools/call", echo)
	_ = requireConsentCause(t, status, body, "user_header_missing")

	links := fmt.Sprintf("%s/v1/gateways/%s/registries/%s/user-headers/links", AdminURL, gatewayID, registryID)
	status, body = sendRequest(t, http.MethodPost, links, nil, map[string]any{"principal_sub": subject})
	require.Equal(t, http.StatusUnprocessableEntity, status, "a custom server's link must name its virtual MCP: %v", body)

	consumerPath := "/" + ConsumerSlug(t, consumerID) + "/mcp"
	status, body = sendRequest(t, http.MethodPost, links, nil, map[string]any{"principal_sub": subject, "consumer_path": consumerPath})
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	ticket, _ := body["ticket"].(string)
	require.NotEmpty(t, ticket, "body=%v", body)

	enterKeyOnConnectPage(t, ticket, registryID, url.Values{"X-API-Key": {"carla-key"}})

	up.reset()
	status, body = mcpRPC(t, gatewayID, consumerID, carla, "tools/call", echo)
	requireRPCSucceeded(t, status, body)
	seen := up.seen()
	require.NotEmpty(t, seen)
	for _, got := range seen {
		require.Equal(t, "carla-key", got)
	}
}

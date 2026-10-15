//go:build functional

package functional_test

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A person asks for a provider's models from an MCP client: the Store checks
// it with the console, hands a form, and the request is filed with the words
// they typed there, never the model's.
func TestStoreRequestModelsTool_FilesThePersonsRequest(t *testing.T) {
	defer Track(t, "LLMStore")()
	f := setupStoreFixture(t, map[string]any{"slug": uniqueName("store-request-models")})
	before := len(ConsoleModelRequestsStub.Calls())

	var structured map[string]any
	eventuallyStore(t, func() bool {
		status, called := storeMCPWith(t, f.gatewayID, f.key, "tools/call", map[string]any{
			"name": "trustgate_store_request_models", "arguments": map[string]any{"provider": "Mistral"},
		})
		if status != http.StatusOK || called["error"] != nil {
			return false
		}
		result, _ := called["result"].(map[string]any)
		structured, _ = result["structuredContent"].(map[string]any)
		return structured["request_url"] != nil
	}, "the Store never handed the request form")
	require.Equal(t, true, structured["requires_reason"])
	require.Equal(t, "Request access to Mistral models", structured["request_link_label"])

	calls := ConsoleModelRequestsStub.Calls()[before:]
	require.NotEmpty(t, calls)
	check := calls[len(calls)-1]
	require.Equal(t, "check", check["action"])
	require.Equal(t, functionalTenantID, check["team_id"])
	require.Equal(t, f.gatewayID, check["gateway_id"])
	require.Equal(t, f.owner, check["user_id"])
	require.Equal(t, "Mistral", check["provider"])

	link, err := url.Parse(fmt.Sprint(structured["request_url"]))
	require.NoError(t, err)
	status, page := modelRequestPage(t, http.MethodGet, link, "")
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, page, "Request access to Mistral models")

	status, page = modelRequestPage(t, http.MethodPost, link, url.Values{"reason": {"French support tickets"}}.Encode())
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, page, "Sent. An administrator has to approve it")
	filed := ConsoleModelRequestsStub.Calls()
	file := filed[len(filed)-1]
	require.Equal(t, "file", file["action"])
	require.Equal(t, "reg-mistral", file["registry_id"])
	require.Equal(t, "French support tickets", file["reason"])
	require.Equal(t, f.owner, file["user_id"])

	status, _ = modelRequestPage(t, http.MethodGet, link, "")
	require.Equal(t, http.StatusUnauthorized, status, "a sent request spends its link")
}

// modelRequestPage opens the page the link names on the MCP plane, as the
// person's browser would on the gateway's host.
func modelRequestPage(t *testing.T, method string, link *url.URL, form string) (int, string) {
	t.Helper()
	var body io.Reader
	if form != "" {
		body = strings.NewReader(form)
	}
	req, err := http.NewRequest(method, MCPURL+link.RequestURI(), body)
	require.NoError(t, err)
	req.Host = link.Host
	if form != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(raw)
}

//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// The Store's models tool answers what the key's own /store/v1/models does,
// grouped by provider, for a person asking from an MCP client.
func TestStoreModelsTool_ListsWhatTheKeyReaches(t *testing.T) {
	defer Track(t, "LLMStore")()
	seedStoreOpenAICatalog(t)
	f := setupStoreFixture(t, map[string]any{"slug": uniqueName("store-models-tool")})
	want := map[string]string{}
	eventuallyStore(t, func() bool {
		want = storeModels(t, ProxyURL, f.gatewayID, f.key)
		return len(want) > 0
	}, "the proxy never listed the key's models")

	var got map[string]string
	var structured map[string]any
	eventuallyStore(t, func() bool {
		status, called := storeMCPWith(t, f.gatewayID, f.key, "tools/call", map[string]any{"name": "trustgate_store_models", "arguments": map[string]any{}})
		if status != http.StatusOK || called["error"] != nil {
			return false
		}
		result, _ := called["result"].(map[string]any)
		structured, _ = result["structuredContent"].(map[string]any)
		got = map[string]string{}
		providers, _ := structured["providers"].([]any)
		for _, raw := range providers {
			p, _ := raw.(map[string]any)
			models, _ := p["models"].([]any)
			for _, m := range models {
				got[fmt.Sprint(m)] = fmt.Sprint(p["provider"])
			}
		}
		return len(got) == len(want)
	}, "the Store never listed the key's models")

	require.Equal(t, want, got, "the tool and /store/v1/models must agree")
	require.Equal(t, true, structured["has_key"])
	require.Contains(t, fmt.Sprint(structured["base_url"]), "/store/v1")

	status, issued := CreateLLMKey(t, f.gatewayID, uniqueName("bob"), llmKeyExpiry(llmKeyDay))
	require.Equal(t, http.StatusCreated, status, "body=%v", issued)
	var bob map[string]any
	eventuallyStore(t, func() bool {
		status, called := storeMCPWith(t, f.gatewayID, fmt.Sprint(issued["api_key"]), "tools/call", map[string]any{"name": "trustgate_store_models", "arguments": map[string]any{}})
		if status != http.StatusOK || called["error"] != nil {
			return false
		}
		result, _ := called["result"].(map[string]any)
		bob, _ = result["structuredContent"].(map[string]any)
		return bob != nil
	}, "the Store never answered bob")
	require.Equal(t, []any{}, bob["providers"], "a key without links reaches no models")
}

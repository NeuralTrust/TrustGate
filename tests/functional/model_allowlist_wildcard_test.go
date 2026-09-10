//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertServed(t *testing.T, apiKey, path, model, marker string, up *fakeUpstream) {
	t.Helper()
	before := up.Hits()

	status, _, body := proxyPost(t, apiKey, path, chatRequestModel(model))

	assert.Equal(t, http.StatusOK, status, "model %q must be allowed, body: %s", model, body)
	assert.Contains(t, string(body), marker)
	assert.Equal(t, before+1, up.Hits(), "model %q must reach the upstream", model)
	assert.Contains(t, string(up.LastBody()), fmt.Sprintf(`"model":%q`, model),
		"the requested model must reach the upstream verbatim")
}

func assertDenied(t *testing.T, apiKey, path, model string, up *fakeUpstream) {
	t.Helper()
	before := up.Hits()

	status, _, body := proxyPost(t, apiKey, path, chatRequestModel(model))

	assert.Equal(t, http.StatusForbidden, status, "model %q must be denied, body: %s", model, body)
	assert.Equal(t, before, up.Hits(), "a denied model must never reach the upstream")
}

// TestModelAllowlist_ExactEntriesUnchanged is the regression half: adding glob
// support must not move a single exact-match behaviour.
func TestModelAllowlist_ExactEntriesUnchanged(t *testing.T) {
	defer Track(t, "ModelAllowlist")()

	t.Run("a listed model is served and an unlisted one is denied", func(t *testing.T) {
		up := newJSONUpstream(t, "exact-served")
		apiKey, path := setupModelPolicyRoute(t, up, []string{"gpt-4o-mini", "gpt-4o"}, "")

		assertServed(t, apiKey, path, "gpt-4o-mini", "exact-served", up)
		assertServed(t, apiKey, path, "gpt-4o", "exact-served", up)
		assertDenied(t, apiKey, path, "claude-opus-4", up)
	})

	t.Run("an exact entry never widens to its family", func(t *testing.T) {
		up := newJSONUpstream(t, "exact-served")
		apiKey, path := setupModelPolicyRoute(t, up, []string{"gpt-4o"}, "")

		assertServed(t, apiKey, path, "gpt-4o", "exact-served", up)
		assertDenied(t, apiKey, path, "gpt-4o-mini", up)
		assertDenied(t, apiKey, path, "gpt-4o-2024-08-06", up)
	})

	t.Run("an omitted allow-list permits any model", func(t *testing.T) {
		up := newJSONUpstream(t, "open-served")
		apiKey, path := setupModelPolicyRoute(t, up, nil, "")

		assertServed(t, apiKey, path, "gpt-4o-mini", "open-served", up)
		assertServed(t, apiKey, path, "anything-at-all", "open-served", up)
	})

	t.Run("a missing model injects the configured default", func(t *testing.T) {
		up := newJSONUpstream(t, "default-served")
		apiKey, path := setupModelPolicyRoute(t, up, []string{"gpt-4o-mini"}, "gpt-4o-mini")

		status, _, body := proxyPost(t, apiKey, path, chatRequestNoModel())

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(up.LastBody()), `"model":"gpt-4o-mini"`)
	})

	t.Run("a qualified reference is checked against the exact list", func(t *testing.T) {
		up := newJSONUpstream(t, "qualified-served")
		apiKey, path := setupModelPolicyRoute(t, up, []string{"gpt-4o-mini"}, "")

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("@openai/gpt-4o-mini"))
		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(up.LastBody()), `"model":"gpt-4o-mini"`,
			"the provider prefix must be stripped before the upstream call")

		hits := up.Hits()
		status, _, body = proxyPost(t, apiKey, path, chatRequestModel("@openai/gpt-4o"))
		assert.Equal(t, http.StatusForbidden, status, "body: %s", body)
		assert.Equal(t, hits, up.Hits())
	})
}

// TestModelAllowlist_WildcardEntries is the feature half: what a pattern must
// admit, and just as importantly what it must not.
func TestModelAllowlist_WildcardEntries(t *testing.T) {
	defer Track(t, "ModelAllowlist")()

	t.Run("a trailing wildcard admits the family and nothing else", func(t *testing.T) {
		up := newJSONUpstream(t, "wildcard-served")
		apiKey, path := setupModelPolicyRoute(t, up, []string{"gpt-4o*"}, "")

		assertServed(t, apiKey, path, "gpt-4o", "wildcard-served", up)
		assertServed(t, apiKey, path, "gpt-4o-mini", "wildcard-served", up)
		assertServed(t, apiKey, path, "gpt-4o-2024-08-06", "wildcard-served", up)
		assertDenied(t, apiKey, path, "claude-opus-4", up)
		assertDenied(t, apiKey, path, "gpt-5", up)
	})

	t.Run("a leading wildcard anchors on the suffix", func(t *testing.T) {
		up := newJSONUpstream(t, "suffix-served")
		apiKey, path := setupModelPolicyRoute(t, up, []string{"*-mini"}, "")

		assertServed(t, apiKey, path, "gpt-4o-mini", "suffix-served", up)
		assertServed(t, apiKey, path, "claude-3-mini", "suffix-served", up)
		assertDenied(t, apiKey, path, "gpt-4o", up)
	})

	t.Run("an interior wildcard anchors on both ends", func(t *testing.T) {
		up := newJSONUpstream(t, "interior-served")
		apiKey, path := setupModelPolicyRoute(t, up, []string{"gpt-*-mini"}, "")

		assertServed(t, apiKey, path, "gpt-4o-mini", "interior-served", up)
		assertDenied(t, apiKey, path, "gpt-4o-nano", up)
		assertDenied(t, apiKey, path, "claude-3-mini", up)
	})

	t.Run("matching is case sensitive and prefix anchored", func(t *testing.T) {
		up := newJSONUpstream(t, "anchored-served")
		apiKey, path := setupModelPolicyRoute(t, up, []string{"gpt-4o*"}, "")

		assertDenied(t, apiKey, path, "GPT-4O", up)
		assertDenied(t, apiKey, path, "GPT-4o-mini", up)
		assertDenied(t, apiKey, path, "xgpt-4o", up)
		assertDenied(t, apiKey, path, "azure/gpt-4o", up)
	})

	t.Run("only the asterisk is a metacharacter", func(t *testing.T) {
		up := newJSONUpstream(t, "literal-served")
		apiKey, path := setupModelPolicyRoute(t, up, []string{"gpt-5.*"}, "")

		assertServed(t, apiKey, path, "gpt-5.1", "literal-served", up)
		assertServed(t, apiKey, path, "gpt-5.2-mini", "literal-served", up)
		assertDenied(t, apiKey, path, "gpt-5-mini", up)
		assertDenied(t, apiKey, path, "gpt-5", up)
	})

	t.Run("literals and patterns coexist in one list", func(t *testing.T) {
		up := newJSONUpstream(t, "mixed-served")
		apiKey, path := setupModelPolicyRoute(t, up, []string{"claude-opus-4", "gpt-4o*"}, "")

		assertServed(t, apiKey, path, "claude-opus-4", "mixed-served", up)
		assertServed(t, apiKey, path, "gpt-4o-mini", "mixed-served", up)
		assertDenied(t, apiKey, path, "claude-opus-4-1", up)
		assertDenied(t, apiKey, path, "gemini-3-flash", up)
	})

	t.Run("a pattern sent as the model never authorizes itself", func(t *testing.T) {
		up := newJSONUpstream(t, "must-not-serve")
		apiKey, path := setupModelPolicyRoute(t, up, []string{"gpt-4o*"}, "")

		assertDenied(t, apiKey, path, "gpt-4o*", up)
		assertDenied(t, apiKey, path, "*", up)
		assertDenied(t, apiKey, path, "gpt-*-mini", up)
	})

	t.Run("a missing model injects the concrete default, never the pattern", func(t *testing.T) {
		up := newJSONUpstream(t, "default-served")
		apiKey, path := setupModelPolicyRoute(t, up, []string{"gpt-4o*"}, "gpt-4o-mini")

		status, _, body := proxyPost(t, apiKey, path, chatRequestNoModel())

		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(up.LastBody()), `"model":"gpt-4o-mini"`)
		assert.NotContains(t, string(up.LastBody()), "*", "no pattern may reach the wire")
	})

	t.Run("a qualified reference resolves against a pattern list", func(t *testing.T) {
		up := newJSONUpstream(t, "qualified-served")
		apiKey, path := setupModelPolicyRoute(t, up, []string{"gpt-4o*"}, "")

		status, _, body := proxyPost(t, apiKey, path, chatRequestModel("@openai/gpt-4o-mini"))
		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(up.LastBody()), `"model":"gpt-4o-mini"`)

		hits := up.Hits()
		status, _, body = proxyPost(t, apiKey, path, chatRequestModel("@openai/claude-opus-4"))
		assert.Equal(t, http.StatusForbidden, status, "body: %s", body)
		assert.Equal(t, hits, up.Hits())
	})
}

// TestModelAllowlist_NoxusIntegration is the shape the Santander integration
// actually sends: a bare model name, no "@provider/" prefix it cannot inject.
func TestModelAllowlist_NoxusIntegration(t *testing.T) {
	defer Track(t, "ModelAllowlist")()

	up := newJSONUpstream(t, "noxus-served")
	apiKey, path := setupModelPolicyRoute(t, up, []string{"gpt-*"}, "")

	assertServed(t, apiKey, path, "gpt-4.1", "noxus-served", up)
	assertServed(t, apiKey, path, "gpt-4.1-mini", "noxus-served", up)
	assertDenied(t, apiKey, path, "gemini-3-flash-preview", up)
}

func TestModelAllowlist_ModelsEndpointNeverPublishesAPattern(t *testing.T) {
	defer Track(t, "ModelAllowlist")()

	apiKey, path := setupModelsDiscoveryRoute(
		t,
		openaiBackendPayload(uniqueName("oai-wild"), "https://api.openai.com/v1"),
		[]string{"gpt-4o-mini", "gpt-4o*"},
	)

	status, _, body := proxyRequest(t, http.MethodGet, apiKey, path, nil, nil)
	require.Equal(t, http.StatusOK, status, "body: %s", body)

	list := decodeModelsList(t, body)
	ids := make([]string, 0, len(list.Data))
	for _, card := range list.Data {
		assert.NotContains(t, card.ID, "*", "a pattern must never be published as a model id")
		ids = append(ids, card.ID)
	}
	assert.Contains(t, ids, "gpt-4o-mini", "literal entries must still be listed")

	status, _, body = proxyRequest(t, http.MethodGet, apiKey, path+"/gpt-4o*", nil, nil)
	assert.Equal(t, http.StatusNotFound, status, "a pattern is not a retrievable model, body: %s", body)
}

func TestModelAllowlist_AdminRejectsUnsafeEntries(t *testing.T) {
	defer Track(t, "ModelAllowlist")()

	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mp-reject-gw")})
	registryID := CreateRegistry(t, gatewayID,
		openaiBackendPayload(uniqueName("be"), "https://api.openai.com/v1"))

	create := func(t *testing.T, policy map[string]any) (int, map[string]any) {
		t.Helper()
		return sendRequest(t, http.MethodPost,
			fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gatewayID), nil,
			map[string]any{
				"name": uniqueName("cons"),
				"registries": []map[string]any{
					{"id": registryID, "model_policies": policy},
				},
			})
	}

	rejected := []struct {
		name   string
		policy map[string]any
	}{
		{
			name:   "wildcard-only entry",
			policy: map[string]any{"allowed": []string{"*"}},
		},
		{
			name:   "double wildcard entry",
			policy: map[string]any{"allowed": []string{"**"}},
		},
		{
			name:   "padded entry",
			policy: map[string]any{"allowed": []string{" gpt-4o* "}},
		},
		{
			name:   "pattern as the default model",
			policy: map[string]any{"allowed": []string{"gpt-4o*"}, "default": "gpt-4o*"},
		},
		{
			name:   "default outside every pattern",
			policy: map[string]any{"allowed": []string{"gpt-4o*"}, "default": "claude-opus-4"},
		},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			status, body := create(t, tc.policy)
			assert.Equal(t, http.StatusUnprocessableEntity, status, "body: %v", body)
		})
	}

	t.Run("a concrete default under a pattern allow-list is accepted", func(t *testing.T) {
		status, body := create(t, map[string]any{
			"allowed": []string{"gpt-4o*"},
			"default": "gpt-4o-mini",
		})
		assert.Equal(t, http.StatusCreated, status, "body: %v", body)
	})
}

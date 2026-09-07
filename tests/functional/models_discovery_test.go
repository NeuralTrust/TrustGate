//go:build functional

package functional_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupModelsDiscoveryRoute(t *testing.T, payload map[string]any, allowed []string) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("models-gw")})
	registryID := CreateRegistry(t, gatewayID, payload)
	policy := map[string]any{"allowed": allowed}
	coID := CreateConsumer(t, gatewayID, map[string]any{
		"name": uniqueName("models-cons"),
		"registries": []map[string]any{
			{"id": registryID, "model_policies": policy},
		},
	})
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	return apiKey, "/" + ConsumerSlug(t, coID) + "/v1/models"
}

func setupModelsDiscoveryUnion(t *testing.T, first, second map[string]any, firstAllowed, secondAllowed []string) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("models-union-gw")})
	firstID := CreateRegistry(t, gatewayID, first)
	secondID := CreateRegistry(t, gatewayID, second)
	coID := CreateConsumer(t, gatewayID, map[string]any{
		"name": uniqueName("models-union-cons"),
		"registries": []map[string]any{
			{"id": firstID, "model_policies": map[string]any{"allowed": firstAllowed}},
			{"id": secondID, "model_policies": map[string]any{"allowed": secondAllowed}},
		},
	})
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	return apiKey, "/" + ConsumerSlug(t, coID) + "/v1/models"
}

type modelsListBody struct {
	Object string `json:"object"`
	Data   []struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		OwnedBy string `json:"owned_by"`
	} `json:"data"`
}

func decodeModelsList(t *testing.T, body []byte) modelsListBody {
	t.Helper()
	var out modelsListBody
	require.NoError(t, json.Unmarshal(body, &out))
	return out
}

func TestModelsDiscovery_AllowList(t *testing.T) {
	defer Track(t, "ModelsDiscovery")()

	apiKey, path := setupModelsDiscoveryRoute(
		t,
		openaiBackendPayload(uniqueName("oai-models"), "https://api.openai.com/v1"),
		[]string{"gpt-4o-mini", "text-embedding-3-small"},
	)

	status, _, body := proxyRequest(t, http.MethodGet, apiKey, path, nil, nil)
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	list := decodeModelsList(t, body)
	assert.Equal(t, "list", list.Object)
	require.Len(t, list.Data, 2)
	assert.Equal(t, "gpt-4o-mini", list.Data[0].ID)
	assert.Equal(t, "model", list.Data[0].Object)
	assert.Equal(t, "openai", list.Data[0].OwnedBy)
	assert.Equal(t, "text-embedding-3-small", list.Data[1].ID)

	status, _, body = proxyRequest(t, http.MethodGet, apiKey, path+"/gpt-4o-mini", nil, nil)
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Contains(t, string(body), `"id":"gpt-4o-mini"`)

	status, _, body = proxyRequest(t, http.MethodGet, apiKey, path+"/gpt-4-forbidden", nil, nil)
	assert.Equal(t, http.StatusNotFound, status, "body: %s", body)
	assert.Contains(t, string(body), `"error":"not_found"`)
}

func TestModelsDiscovery_FiltersIncapableModels(t *testing.T) {
	defer Track(t, "ModelsDiscovery")()

	apiKey, path := setupModelsDiscoveryRoute(
		t,
		anthropicBackendPayload(uniqueName("ant-models")),
		[]string{"claude-sonnet-4", "text-embedding-3-small", "rerank-english-v3.0"},
	)

	status, _, body := proxyRequest(t, http.MethodGet, apiKey, path, nil, nil)
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	list := decodeModelsList(t, body)
	require.Len(t, list.Data, 1)
	assert.Equal(t, "claude-sonnet-4", list.Data[0].ID)
	assert.Equal(t, "anthropic", list.Data[0].OwnedBy)
}

func TestModelsDiscovery_UnionDedupesSharedSlugs(t *testing.T) {
	defer Track(t, "ModelsDiscovery")()

	apiKey, path := setupModelsDiscoveryUnion(
		t,
		openaiBackendPayload(uniqueName("oai-union"), "https://api.openai.com/v1"),
		anthropicBackendPayload(uniqueName("ant-union")),
		[]string{"gpt-4o-mini"},
		[]string{"claude-sonnet-4", "gpt-4o-mini"},
	)

	status, _, body := proxyRequest(t, http.MethodGet, apiKey, path, nil, nil)
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	list := decodeModelsList(t, body)
	ids := make([]string, 0, len(list.Data))
	for _, card := range list.Data {
		ids = append(ids, card.ID)
	}
	assert.Equal(t, []string{"claude-sonnet-4", "gpt-4o-mini"}, ids)
}

func TestModelsDiscovery_RejectsNonGET(t *testing.T) {
	defer Track(t, "ModelsDiscovery")()

	apiKey, path := setupModelsDiscoveryRoute(
		t,
		openaiBackendPayload(uniqueName("oai-models-post"), "https://api.openai.com/v1"),
		[]string{"gpt-4o-mini"},
	)

	status, _, body := proxyRequest(t, http.MethodPost, apiKey, path, nil, []byte(`{}`))
	assert.Equal(t, http.StatusBadRequest, status, "body: %s", body)
	assert.True(t, strings.Contains(string(body), "invalid_request"), "body: %s", body)
}

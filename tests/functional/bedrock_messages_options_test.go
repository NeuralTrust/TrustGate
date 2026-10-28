//go:build functional

package functional_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const bedrockMessagesOptionsBody = `{
	"model": %q,
	"max_tokens": 64,
	"top_k": 40,
	"system": "Answer briefly.",
	"messages": [{"role": "user", "content": "hi there"}],
	"tools": [{"name": "lookup", "strict": true, "input_schema": {"type": "object", "properties": {}, "additionalProperties": false}}],
	"output_config": {"format": {"type": "json_schema", "schema": {"type": "object", "properties": {"a": {"type": "string"}}, "additionalProperties": false}}}
}`

type sentConverse struct {
	System                       []map[string]any `json:"system"`
	AdditionalModelRequestFields map[string]any   `json:"additionalModelRequestFields"`
	OutputConfig                 struct {
		TextFormat struct {
			Type      string `json:"type"`
			Structure struct {
				JSONSchema struct {
					Schema string `json:"schema"`
				} `json:"jsonSchema"`
			} `json:"structure"`
		} `json:"textFormat"`
	} `json:"outputConfig"`
	ToolConfig struct {
		Tools []struct {
			ToolSpec struct {
				Name   string `json:"name"`
				Strict *bool  `json:"strict"`
			} `json:"toolSpec"`
		} `json:"tools"`
	} `json:"toolConfig"`
}

func TestBedrockMessages_AnthropicOptionsReachConverse(t *testing.T) {
	defer Track(t, "BedrockMessagesOptions")()
	stub := newBedrockRuntimeStub(t)
	apiKey, slug := setupBedrockNativeRoute(t, promptTemplatePolicy(map[string]any{
		"inject_templates": []map[string]any{
			{"id": "brand", "content": "You speak for the airline.", "on_existing_system": "merge"},
		},
	}))
	const model = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
	const escapedModel = "us.anthropic.claude-sonnet-4-5-20250929-v1%3A0"

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, "/"+slug+"/v1/messages",
		map[string]string{"anthropic-version": "2023-06-01"},
		[]byte(fmt.Sprintf(bedrockMessagesOptionsBody, model)))
	require.Equal(t, http.StatusOK, status, "body: %s", raw)

	got := stub.last(t)
	assert.Equal(t, "/model/"+escapedModel+"/converse", got.RequestURI)
	var sent sentConverse
	require.NoError(t, json.Unmarshal(got.Body, &sent), "body: %s", got.Body)

	assert.Equal(t, map[string]any{"top_k": float64(40)}, sent.AdditionalModelRequestFields)
	assert.Equal(t, "json_schema", sent.OutputConfig.TextFormat.Type)
	assert.JSONEq(t, `{"type":"object","properties":{"a":{"type":"string"}},"additionalProperties":false}`,
		sent.OutputConfig.TextFormat.Structure.JSONSchema.Schema)
	require.Len(t, sent.ToolConfig.Tools, 1)
	require.NotNil(t, sent.ToolConfig.Tools[0].ToolSpec.Strict)
	assert.True(t, *sent.ToolConfig.Tools[0].ToolSpec.Strict)
	assert.Contains(t, string(got.Body), "You speak for the airline.", "the prompt template still applies")
}

func TestBedrockMessages_AnthropicOptionsRefusedForAnotherFamily(t *testing.T) {
	defer Track(t, "BedrockMessagesOptions")()
	stub := newBedrockRuntimeStub(t)
	apiKey, slug := setupBedrockNativeRoute(t)

	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, "/"+slug+"/v1/messages",
		map[string]string{"anthropic-version": "2023-06-01"},
		[]byte(fmt.Sprintf(bedrockMessagesOptionsBody, "amazon.nova-lite-v1:0")))

	assert.Equal(t, http.StatusBadRequest, status, "body: %s", raw)
	assert.Contains(t, string(raw), "top_k")
	assert.Zero(t, stub.callCount(), "the gateway answers before calling AWS")
}

const bedrockMessagesReasoningBody = `{
	"model": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
	"max_tokens": 4096,
	"thinking": {"type": "enabled", "budget_tokens": 1024},
	"output_config": {"effort": "high"},
	"messages": [{"role": "user", "content": "hi there"}]
}`

const bedrockMessagesHistoryBody = `{
	"model": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
	"max_tokens": 4096,
	"messages": [
		{"role": "user", "content": "weather in Madrid?"},
		{"role": "assistant", "content": [
			{"type": "thinking", "thinking": "need the tool", "signature": "sig-1"},
			{"type": "text", "text": "Checking."},
			{"type": "tool_use", "id": "tu_1", "name": "get_weather", "input": {"city": "Madrid"}}]},
		{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "tu_1", "content": "sunny"}]}
	],
	"tools": [{"name": "get_weather", "input_schema": {"type": "object"}}]
}`

func setupBedrockReasoningRoute(t *testing.T, options map[string]any) (apiKey, slug string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("bedrock-reasoning-gw")})
	registry := bedrockNativeRegistryPayload(uniqueName("bedrock"))
	if options != nil {
		registry["provider_options"] = options
	}
	registryID := CreateRegistry(t, gatewayID, registry)
	consumerID := CreateConsumerWithRegistries(t, gatewayID, uniqueName("cons"), registryID)
	return createAndAttachAPIKey(t, gatewayID, consumerID), ConsumerSlug(t, consumerID)
}

func TestBedrockMessages_ReasoningIsOptInPerRegistry(t *testing.T) {
	defer Track(t, "BedrockMessagesOptions")()
	stub := newBedrockRuntimeStub(t)
	headers := map[string]string{
		"anthropic-version": "2023-06-01",
		"anthropic-beta":    "claude-code-20250219,interleaved-thinking-2025-05-14",
	}

	t.Run("by default thinking, effort and betas stay behind", func(t *testing.T) {
		apiKey, slug := setupBedrockReasoningRoute(t, nil)
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, "/"+slug+"/v1/messages", headers, []byte(bedrockMessagesReasoningBody))
		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.NotContains(t, string(stub.last(t).Body), "additionalModelRequestFields")
	})

	t.Run("by default earlier reasoning blocks stay behind too", func(t *testing.T) {
		apiKey, slug := setupBedrockReasoningRoute(t, nil)
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, "/"+slug+"/v1/messages", headers, []byte(bedrockMessagesHistoryBody))
		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		sent := string(stub.last(t).Body)
		assert.NotContains(t, sent, "reasoningContent")
		assert.Contains(t, sent, "Checking.")
	})

	t.Run("a forwarding registry sends earlier reasoning back signed", func(t *testing.T) {
		apiKey, slug := setupBedrockReasoningRoute(t, map[string]any{"reasoning": "forward"})
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, "/"+slug+"/v1/messages", headers, []byte(bedrockMessagesHistoryBody))
		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Contains(t, string(stub.last(t).Body), `"reasoningContent":{"reasoningText":{"signature":"sig-1","text":"need the tool"}}`)
	})

	t.Run("a registry that forwards reasoning sends it with the betas bedrock takes", func(t *testing.T) {
		apiKey, slug := setupBedrockReasoningRoute(t, map[string]any{"reasoning": "forward"})
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, "/"+slug+"/v1/messages", headers, []byte(bedrockMessagesReasoningBody))
		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		var sent sentConverse
		require.NoError(t, json.Unmarshal(stub.last(t).Body, &sent))
		assert.Equal(t, map[string]any{
			"thinking":       map[string]any{"type": "enabled", "budget_tokens": float64(1024)},
			"output_config":  map[string]any{"effort": "high"},
			"anthropic_beta": []any{"interleaved-thinking-2025-05-14"},
		}, sent.AdditionalModelRequestFields)
	})

	t.Run("an unknown reasoning mode is refused when the registry is saved", func(t *testing.T) {
		gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("bedrock-reasoning-gw")})
		registry := bedrockNativeRegistryPayload(uniqueName("bedrock"))
		registry["provider_options"] = map[string]any{"reasoning": "always"}
		status, body := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/v1/gateways/%s/registries", AdminURL, gatewayID), nil, registry)
		assert.GreaterOrEqual(t, status, http.StatusBadRequest, "body: %s", body)
		assert.Less(t, status, http.StatusInternalServerError, "body: %s", body)
		assert.Contains(t, fmt.Sprint(body), `provider_options.reasoning must be "drop" or "forward"`)
	})
}

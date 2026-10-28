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

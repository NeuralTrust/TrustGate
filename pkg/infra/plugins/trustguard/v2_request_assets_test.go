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

package trustguard

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

func marshalV2(t *testing.T, body GuardRequest) string {
	t.Helper()
	raw, err := marshalNoEscape(toV2Request(body, body.request))
	require.NoError(t, err)
	return string(raw)
}

// TrustGuard v2 refuses application_id, attributes.{application,model,user,mcp_server}:
// what the request is about travels only in assets.
func TestV2RequestNamesAssetsOnlyInAssetsBlock(t *testing.T) {
	t.Parallel()
	llm := &infracontext.RequestContext{Provider: "OpenAI", ResolvedModel: "gpt-4o", RequestedModel: "@openai/gpt-4o"}
	body := GuardRequest{
		Payload:    json.RawMessage(`{"input":"hi"}`),
		Direction:  directionInput,
		Protocol:   protocolLLM,
		GatewayID:  "gw-1",
		SessionID:  "s-1",
		ConsumerID: " app-1 ",
		Attributes: GuardAttributes{
			ContentType: "text",
			User:        &GuardUser{ID: "u-1", Email: "ana@example.com"},
			Consumer:    &GuardConsumer{ID: "app-1", Name: "Support", Audience: "internal", Synthetic: true},
			Stream:      &GuardStream{ID: "t:response", Seq: 2},
		},
		request: llm,
	}
	assert.JSONEq(t, `{
		"payload":{"input":"hi"},"direction":"input","protocol":"llm","gateway_id":"gw-1","session_id":"s-1",
		"assets":{
			"agent":{"id":"app-1","name":"Support","audience":"internal","synthetic":true},
			"model":{"name":"gpt-4o","provider":"openai","requested_name":"@openai/gpt-4o"},
			"user":{"id":"u-1","email":"ana@example.com"}
		},
		"attributes":{"content_type":"text","stream":{"id":"t:response","seq":2,"final":false}}
	}`, marshalV2(t, body))
}

func TestV2RequestMCPAssets(t *testing.T) {
	t.Parallel()
	body := GuardRequest{
		Direction:  directionInput,
		Protocol:   protocolMCP,
		ConsumerID: "app-1",
		Attributes: GuardAttributes{
			ContentType: "text",
			MCPServer:   &GuardMCPServer{ID: "reg-1", Code: "github"},
		},
		request: &infracontext.RequestContext{MCP: true, MCPServerName: "GitHub", MCPTool: "search"},
	}
	assert.JSONEq(t, `{
		"payload":null,"direction":"input","protocol":"mcp","gateway_id":"",
		"assets":{
			"agent":{"id":"app-1"},
			"mcp_server":{"id":"github","name":"GitHub","tool":{"name":"search"}}
		},
		"attributes":{"content_type":"text"}
	}`, marshalV2(t, body))
}

func TestV2RequestOmitsEmptyAssets(t *testing.T) {
	t.Parallel()
	got := marshalV2(t, GuardRequest{Direction: directionInput, Protocol: protocolLLM, Attributes: GuardAttributes{ContentType: "text"}})
	assert.NotContains(t, got, `"assets"`)
	assert.NotContains(t, got, "application_id")
}

// The v1 body is not touched by the v2 change: consumer_id and attributes.{consumer,model,user}.
func TestV1RequestKeepsItsOwnShape(t *testing.T) {
	t.Parallel()
	body := GuardRequest{
		Direction:  directionInput,
		Protocol:   protocolLLM,
		ConsumerID: "app-1",
		Attributes: GuardAttributes{
			ContentType: "text",
			Model:       GuardModel{Name: "gpt-4o", Provider: "openai"},
			User:        &GuardUser{ID: "u-1"},
			Consumer:    &GuardConsumer{Name: "Support"},
		},
	}
	raw, err := marshalNoEscape(withInventory(body))
	require.NoError(t, err)
	var wire map[string]any
	require.NoError(t, json.Unmarshal(raw, &wire))
	assert.Equal(t, "app-1", wire["consumer_id"])
	assert.NotContains(t, wire, "assets")
	assert.NotContains(t, wire, "application_id")
	attrs, ok := wire["attributes"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, map[string]any{"name": "gpt-4o", "provider": "openai"}, attrs["model"])
	assert.Equal(t, map[string]any{"id": "u-1"}, attrs["user"])
	assert.Equal(t, map[string]any{"name": "Support"}, attrs["consumer"])
}

// Without a request context nothing is known of the model nor of the MCP server's name and tool:
// the assets block carries what the body itself names.
func TestV2RequestWithoutRequestContext(t *testing.T) {
	t.Parallel()
	llm := GuardRequest{
		Direction:  directionInput,
		Protocol:   protocolLLM,
		ConsumerID: "app-1",
		Attributes: GuardAttributes{ContentType: "text", User: &GuardUser{ID: "u-1"}},
	}
	assert.JSONEq(t, `{
		"payload":null,"direction":"input","protocol":"llm","gateway_id":"",
		"assets":{"agent":{"id":"app-1"},"user":{"id":"u-1"}},
		"attributes":{"content_type":"text"}
	}`, marshalV2(t, llm))

	mcp := GuardRequest{
		Direction:  directionInput,
		Protocol:   protocolMCP,
		ConsumerID: "app-1",
		Attributes: GuardAttributes{ContentType: "text", MCPServer: &GuardMCPServer{ID: "reg-1", Code: "github"}},
	}
	assert.JSONEq(t, `{
		"payload":null,"direction":"input","protocol":"mcp","gateway_id":"",
		"assets":{"agent":{"id":"app-1"},"mcp_server":{"id":"github"}},
		"attributes":{"content_type":"text"}
	}`, marshalV2(t, mcp))
}

var updateGolden = flag.Bool("update", false, "rewrite testdata/v2_request_golden.json")

const v2GoldenPath = "testdata/v2_request_golden.json"

// The golden holds the exact v2 evaluate bodies TrustGate emits; TrustGuard decodes the same
// file in its contract test. Regenerate with: go test ./pkg/infra/plugins/trustguard -run TestV2RequestGolden -update
func TestV2RequestGolden(t *testing.T) {
	consumer := &GuardConsumer{ID: "app-1", Name: "Support", Audience: "internal"}
	user := &GuardUser{ID: "u-1", Email: "ana@example.com"}
	cases := []struct {
		name string
		body GuardRequest
	}{
		{"llm_input", GuardRequest{
			Payload: json.RawMessage(`{"messages":[{"role":"user","content":"hello"}]}`), Direction: directionInput, Protocol: protocolLLM,
			GatewayID: "gw-1", SessionID: "s-1", ConsumerID: "app-1",
			Attributes: GuardAttributes{ContentType: "text", User: user, Consumer: consumer},
			request:    &infracontext.RequestContext{Provider: "openai", ResolvedModel: "gpt-4o", RequestedModel: "@openai/gpt-4o"},
		}},
		{"llm_output", GuardRequest{
			Payload: json.RawMessage(`{"input":"hi there"}`), Direction: directionOutput, Protocol: protocolLLM,
			GatewayID: "gw-1", SessionID: "s-1", ConsumerID: "app-1",
			Attributes: GuardAttributes{ContentType: "text", User: user, Consumer: consumer, Stream: &GuardStream{ID: "t:response", Seq: 1, Final: true}},
			request:    &infracontext.RequestContext{Provider: "openai", ResolvedModel: "gpt-4o", SentModel: "gpt-4o", RequestedModel: "@openai/gpt-4o"},
		}},
		{"mcp", GuardRequest{
			Payload: json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"q":"login"}}}`), Direction: directionInput, Protocol: protocolMCP,
			GatewayID: "gw-1", SessionID: "s-1", ConsumerID: "app-1",
			Attributes: GuardAttributes{ContentType: "text", User: user, Consumer: consumer, MCPServer: &GuardMCPServer{ID: "reg-1", Code: "github"}},
			request:    &infracontext.RequestContext{MCP: true, MCPServerName: "GitHub", MCPTool: "search"},
		}},
		{"a2a", GuardRequest{
			Payload: json.RawMessage(`{"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`), Direction: directionInput, Protocol: protocolA2A,
			GatewayID: "gw-1", SessionID: "ctx-1", ConsumerID: "app-1",
			Attributes: GuardAttributes{ContentType: "text", Consumer: consumer},
			request:    &infracontext.RequestContext{A2A: true},
		}},
	}
	got := map[string]json.RawMessage{}
	for _, c := range cases {
		got[c.name] = json.RawMessage(marshalV2(t, c.body))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	require.NoError(t, enc.Encode(got))

	if *updateGolden {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(v2GoldenPath, buf.Bytes(), 0o644))
	}
	want, err := os.ReadFile(v2GoldenPath)
	require.NoError(t, err, "run with -update to create the golden")
	assert.JSONEq(t, string(want), buf.String())
}

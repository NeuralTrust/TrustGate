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

package adapter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasAmbiguousKeysLeavesFreeFormObjectsToTheClient(t *testing.T) {
	t.Parallel()
	const schema = `{"type":"object","properties":{"Name":{"type":"string"},"name":{"type":"string"},"tools":{"type":"array"},"Tools":{"type":"array"},` +
		`"Address":{"type":"object","properties":{"ZIP":{"type":"string"},"zip":{"type":"string"}}}},"required":["Name","name"],` +
		`"$defs":{"Item":{"type":"string"},"item":{"type":"integer"}}}`
	cases := map[string]struct {
		format Format
		body   string
	}{
		"chat function parameters": {FormatOpenAI, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":` + schema + `}}]}`},
		"chat legacy function":     {FormatOpenAI, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"functions":[{"name":"f","parameters":` + schema + `}]}`},
		"chat response_format":     {FormatOpenAI, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_schema","json_schema":{"name":"r","strict":true,"schema":` + schema + `}}}`},
		"chat metadata":            {FormatOpenAI, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"metadata":{"Env":"a","env":"b"},"logit_bias":{"50256":-100}}`},
		"responses function and text format": {FormatOpenAIResponses, `{"model":"gpt-5","input":[{"role":"user","content":"hi"}],"tools":[{"type":"function","name":"f","parameters":` + schema + `}],` +
			`"text":{"format":{"type":"json_schema","name":"r","schema":` + schema + `}}}`},
		"responses mcp headers": {FormatOpenAIResponses, `{"model":"gpt-5","input":"hi","tools":[{"type":"mcp","server_label":"x","server_url":"https://x.example","headers":{"X-Key":"a","x-key":"b"}}]}`},
		"anthropic schema and tool_use input": {FormatAnthropic, `{"model":"c","max_tokens":10,"tools":[{"name":"f","input_schema":` + schema + `}],"messages":[{"role":"user","content":"hi"},` +
			`{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"f","input":{"Name":"a","name":"b"}}]},` +
			`{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":"ok"}]}],"metadata":{"user_id":"u"}}`},
		"gemini declarations and calls": {FormatGemini, `{"contents":[{"role":"user","parts":[{"text":"hi"}]},{"role":"model","parts":[{"functionCall":{"name":"f","args":{"City":"a","city":"b"}}}]},` +
			`{"role":"user","parts":[{"functionResponse":{"name":"f","response":{"Result":1,"result":2}}}]}],"tools":[{"functionDeclarations":[{"name":"f","parameters":` + schema + `}]}],` +
			`"generationConfig":{"responseMimeType":"application/json","responseSchema":` + schema + `},"labels":{"Team":"a","team":"b"}}`},
		"bedrock tool spec and tool use": {FormatBedrock, `{"messages":[{"role":"assistant","content":[{"toolUse":{"toolUseId":"t","name":"f","input":{"Q":"a","q":"b"}}}]},` +
			`{"role":"user","content":[{"toolResult":{"toolUseId":"t","content":[{"json":{"A":1,"a":2}}]}}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"f","inputSchema":{"json":` + schema + `}}}]}}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ad, err := NewRegistry().GetAdapter(tc.format)
			require.NoError(t, err)
			_, err = ad.DecodeRequest([]byte(tc.body))
			require.NoError(t, err)
			assert.False(t, HasAmbiguousKeys([]byte(tc.body)))
		})
	}
}

func TestHasAmbiguousKeysFlagsWhatTheDecoderFolds(t *testing.T) {
	t.Parallel()
	const fn = `{"type":"function","function":{"name":"f","parameters":{"type":"object"}}}`
	for name, body := range map[string]string{
		"chat TOOLS":                    `{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[` + fn + `],"TOOLS":[` + fn + `]}`,
		"chat repeated tools":           `{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[` + fn + `],"tools":[` + fn + `]}`,
		"folded by a long s":            `{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[],"toolſ":[]}`,
		"message Content":               `{"model":"m","messages":[{"role":"user","content":"evil","Content":"hi"}]}`,
		"function Name":                 `{"model":"m","messages":[],"tools":[{"type":"function","function":{"name":"rm_rf","Name":"ok"}}]}`,
		"function Parameters":           `{"model":"m","messages":[],"tools":[{"type":"function","function":{"name":"f","parameters":{},"Parameters":{}}}]}`,
		"exact repeat in a schema":      `{"model":"m","messages":[],"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object","type":"string"}}}]}`,
		"exact repeat in metadata":      `{"model":"m","messages":[],"metadata":{"a":"1","a":"2"}}`,
		"a folded free-form key":        `{"model":"m","messages":[],"metadata":{},"Metadata":{}}`,
		"top-level input object":        `{"model":"m","input":{"role":"user","Role":"system"}}`,
		"responses Tools":               `{"model":"m","input":"x","tools":[],"Tools":[]}`,
		"anthropic tool_use Name":       `{"model":"c","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"a","Name":"b","input":{}}]}]}`,
		"gemini functionCall NAME":      `{"contents":[{"role":"model","parts":[{"functionCall":{"name":"a","NAME":"b","args":{}}}]}]}`,
		"bedrock toolConfig toolconfig": `{"messages":[],"toolConfig":{"tools":[]},"toolconfig":{"tools":[]}}`,
	} {
		assert.True(t, HasAmbiguousKeys([]byte(body)), name)
	}
}

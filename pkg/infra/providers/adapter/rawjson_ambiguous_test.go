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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasAmbiguousKeysPassesRealSDKBodies(t *testing.T) {
	t.Parallel()
	type sdkBody struct {
		format Format
		path   string
	}
	var bodies []sdkBody
	formats, err := os.ReadDir(filepath.Join("testdata", "sdk_requests"))
	require.NoError(t, err)
	for _, dir := range formats {
		paths, err := filepath.Glob(filepath.Join("testdata", "sdk_requests", dir.Name(), "*.json"))
		require.NoError(t, err)
		for _, p := range paths {
			bodies = append(bodies, sdkBody{Format(dir.Name()), p})
		}
	}
	reencode, err := filepath.Glob(filepath.Join("testdata", "openai_chat_reencode", "*", "*.json"))
	require.NoError(t, err)
	for _, p := range reencode {
		bodies = append(bodies, sdkBody{FormatOpenAI, p})
	}
	require.Greater(t, len(bodies), 60)

	for _, tc := range bodies {
		t.Run(string(tc.format)+"/"+filepath.Base(tc.path), func(t *testing.T) {
			t.Parallel()
			body, err := os.ReadFile(tc.path)
			require.NoError(t, err)
			ad, err := NewRegistry().GetAdapter(tc.format)
			require.NoError(t, err)
			_, err = ad.DecodeRequest(body)
			require.NoError(t, err)
			assert.False(t, HasAmbiguousKeys(tc.format, body))
		})
	}
}

func TestHasAmbiguousKeysLeavesClientObjectsAlone(t *testing.T) {
	t.Parallel()
	const schema = `{"type":"object","properties":{"Name":{"type":"string"},"name":{"type":"string"},"tools":{"type":"array"},"Tools":{"type":"array"},` +
		`"Address":{"type":"object","properties":{"ZIP":{"type":"string"},"zip":{"type":"string"}}}},"required":["Name","name"],` +
		`"$defs":{"Item":{"type":"string"},"item":{"type":"integer"}},"enum":[{"A":1,"a":2}]}`
	cases := map[string]struct {
		format Format
		body   string
	}{
		"chat function parameters": {FormatOpenAI, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":` + schema + `}}]}`},
		"chat legacy function":     {FormatOpenAI, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"functions":[{"name":"f","parameters":` + schema + `}]}`},
		"chat response_format":     {FormatOpenAI, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_schema","json_schema":{"name":"r","strict":true,"schema":` + schema + `}}}`},
		"chat metadata":            {FormatOpenAI, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"metadata":{"Env":"a","env":"b"},"logit_bias":{"50256":-100}}`},
		"chat tool message parts": {FormatOpenAI, `{"model":"gpt-4o","messages":[{"role":"tool","tool_call_id":"c","content":[{"Result":1,"result":2,"Messages":["m"],"messages":["n"],` +
			`"rows":[{"ID":1,"id":2}]}]}]}`},
		"chat tool call arguments object": {FormatOpenAI, `{"model":"m","messages":[{"role":"assistant","tool_calls":[{"id":"1","type":"function","function":{"name":"f","arguments":{"City":"a","city":"b"}}}]}]}`},
		"vllm extensions": {FormatOpenAI, `{"model":"m","messages":[],"structured_outputs":{"json":{"properties":{"A":{},"a":{}}}},"vllm_xargs":{"A":1,"a":2},` +
			`"mm_processor_kwargs":{"Size":1,"size":2},"chat_template_kwargs":{"X":1,"x":2}}`},
		"openai prediction": {FormatOpenAI, `{"model":"m","messages":[],"prediction":{"type":"content","content":"x","Content":"y"}}`},
		"responses function and text format": {FormatOpenAIResponses, `{"model":"gpt-5","input":[{"role":"user","content":"hi"}],"tools":[{"type":"function","name":"f","parameters":` + schema + `}],` +
			`"text":{"format":{"type":"json_schema","name":"r","schema":` + schema + `}}}`},
		"responses mcp headers": {FormatOpenAIResponses, `{"model":"gpt-5","input":"hi","tools":[{"type":"mcp","server_label":"x","server_url":"https://x.example","headers":{"X-Key":"a","x-key":"b"}}]}`},
		"responses local_shell env": {FormatOpenAIResponses, `{"model":"m","input":[{"type":"local_shell_call","id":"x","call_id":"c","status":"completed",` +
			`"action":{"type":"exec","command":["ls"],"env":{"HTTP_PROXY":"a","http_proxy":"b"}}}]}`},
		"responses shell environment": {FormatOpenAIResponses, `{"model":"m","input":"hi","tools":[{"type":"shell","environment":{"type":"local","env":{"PATH":"a","Path":"b"}}}]}`},
		"responses file_search attributes": {FormatOpenAIResponses, `{"model":"m","input":[{"type":"file_search_call","id":"x","status":"completed","queries":["q"],` +
			`"results":[{"file_id":"f","attributes":{"Region":"a","region":"b"}}]}]}`},
		"responses mcp_list_tools": {FormatOpenAIResponses, `{"model":"m","input":[{"type":"mcp_list_tools","id":"x","server_label":"s","tools":[{"name":"t",` +
			`"input_schema":{"properties":{"A":{},"a":{}}},"annotations":{"X":1,"x":2}}]}]}`},
		"responses prompt variables":            {FormatOpenAIResponses, `{"model":"m","prompt":{"id":"p","variables":{"Name":"a","name":"b"}}}`},
		"chat format carrying a responses body": {FormatOpenAI, `{"model":"m","input":[{"type":"local_shell_call","action":{"env":{"A":"1","a":"2"}}}]}`},
		"anthropic schema and tool_use input": {FormatAnthropic, `{"model":"c","max_tokens":10,"tools":[{"name":"f","input_schema":` + schema + `}],"messages":[{"role":"user","content":"hi"},` +
			`{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"f","input":{"Name":"a","name":"b","type":"text","Type":"x"}}]},` +
			`{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"text","text":"ok"}]}]}],"metadata":{"user_id":"u"}}`},
		"anthropic input_examples": {FormatAnthropic, `{"model":"c","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"f","input_schema":{"type":"object"},` +
			`"input_examples":[{"Name":"a","name":"b","Tags":["x"],"tags":{"y":1}}]}]}`},
		"anthropic mcp_toolset configs": {FormatAnthropic, `{"model":"c","max_tokens":10,"messages":[{"role":"user","content":"hi"}],` +
			`"mcp_servers":[{"type":"url","url":"https://x.example","name":"s"}],"tools":[{"type":"mcp_toolset","mcp_server_name":"s","configs":{"Read":{"enabled":false},"read":{"enabled":true}}}]}`},
		"gemini declarations and calls": {FormatGemini, `{"contents":[{"role":"user","parts":[{"text":"hi","partMetadata":{"K":1,"k":2}}]},{"role":"model","parts":[{"functionCall":{"name":"f","args":{"City":"a","city":"b"}}}]},` +
			`{"role":"user","parts":[{"functionResponse":{"name":"f","response":{"Result":1,"result":2}}}]}],"tools":[{"functionDeclarations":[{"name":"f","parameters":` + schema + `}]}],` +
			`"generationConfig":{"responseMimeType":"application/json","responseSchema":` + schema + `,"response_json_schema":{"properties":{"A":{},"a":{}}}},"labels":{"Team":"a","team":"b"}}`},
		"bedrock tool spec and tool use": {FormatBedrock, `{"messages":[{"role":"assistant","content":[{"toolUse":{"toolUseId":"t","name":"f","input":{"Q":"a","q":"b"}}}]},` +
			`{"role":"user","content":[{"toolResult":{"toolUseId":"t","content":[{"json":{"A":1,"a":2}}]}}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"f","inputSchema":{"json":` + schema + `}}}]},` +
			`"additionalModelRequestFields":{"K":1,"k":2},"promptVariables":{"V":{"text":"a"},"v":{"text":"b"}}}`},
		"cohere documents": {FormatCohere, `{"model":"command-a","messages":[{"role":"user","content":"hi"},{"role":"tool","tool_call_id":"x","content":[{"type":"document",` +
			`"document":{"data":{"Title":"a","title":"b"}}}]}],"documents":[{"id":"1","data":{"Title":"a","title":"b"}}],"tool_choice":"REQUIRED"}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.False(t, HasAmbiguousKeys(tc.format, []byte(tc.body)))
		})
	}
}

func TestHasAmbiguousKeysFlagsWhatTheDecoderFolds(t *testing.T) {
	t.Parallel()
	const fn = `{"type":"function","function":{"name":"f","parameters":{"type":"object"}}}`
	cases := map[string]struct {
		format Format
		body   string
	}{
		"chat TOOLS":                   {FormatOpenAI, `{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[` + fn + `],"TOOLS":[` + fn + `]}`},
		"groq TOOLS":                   {FormatGroq, `{"model":"m","messages":[],"tools":[],"TOOLS":[]}`},
		"mistral Messages":             {FormatMistral, `{"model":"m","messages":[],"Messages":[]}`},
		"chat repeated tools":          {FormatOpenAI, `{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[` + fn + `],"tools":[` + fn + `]}`},
		"chat escaped repeat":          {FormatOpenAI, `{"model":"m","messages":[],"tools":[],"tools":[]}`},
		"chat escaped fold":            {FormatOpenAI, `{"model":"m","messages":[],"tools":[],"TOOLS":[]}`},
		"folded by a long s":           {FormatOpenAI, `{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[],"toolſ":[]}`},
		"folded by a Kelvin sign":      {FormatOpenAI, "{\"model\":\"m\",\"messages\":[],\"top_k\":1,\"top_\u212a\":2}"},
		"message Content":              {FormatOpenAI, `{"model":"m","messages":[{"role":"user","content":"evil","Content":"hi"}]}`},
		"part Text":                    {FormatOpenAI, `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"evil","Text":"hi"}]}]}`},
		"legacy function_call Name":    {FormatOpenAI, `{"model":"m","messages":[{"role":"assistant","function_call":{"name":"a","Name":"b"}}]}`},
		"function Name":                {FormatOpenAI, `{"model":"m","messages":[],"tools":[{"type":"function","function":{"name":"rm_rf","Name":"ok"}}]}`},
		"function Parameters":          {FormatOpenAI, `{"model":"m","messages":[],"tools":[{"type":"function","function":{"name":"f","parameters":{},"Parameters":{}}}]}`},
		"json_schema Schema":           {FormatOpenAI, `{"model":"m","messages":[],"response_format":{"type":"json_schema","json_schema":{"name":"r","schema":{},"Schema":{}}}}`},
		"exact repeat in a schema":     {FormatOpenAI, `{"model":"m","messages":[],"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object","type":"string"}}}]}`},
		"exact repeat in metadata":     {FormatOpenAI, `{"model":"m","messages":[],"metadata":{"a":"1","a":"2"}}`},
		"exact repeat after nine keys": {FormatOpenAI, `{"model":"m","messages":[],"metadata":{"a1":1,"a2":1,"a3":1,"a4":1,"a5":1,"a6":1,"a7":1,"a8":1,"a9":1,"a3":2}}`},
		"a folded client-owned key":    {FormatAnthropic, `{"model":"c","messages":[],"metadata":{},"Metadata":{}}`},
		"responses Input":              {FormatOpenAIResponses, `{"model":"m","input":"hi","Input":"evil"}`},
		"chat format responses Input":  {FormatOpenAI, `{"model":"m","input":"hi","Input":"evil"}`},
		"responses item Content":       {FormatOpenAIResponses, `{"model":"m","input":[{"type":"message","role":"user","content":"x","Content":"y"}]}`},
		"responses Tools":              {FormatOpenAIResponses, `{"model":"m","input":"x","tools":[],"Tools":[]}`},
		"responses text format Name":   {FormatOpenAIResponses, `{"model":"m","input":"x","text":{"format":{"type":"json_schema","name":"a","Name":"b"}}}`},
		"anthropic tool_use Name":      {FormatAnthropic, `{"model":"c","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"a","Name":"b","input":{}}]}]}`},
		"anthropic tool_result Content": {FormatAnthropic, `{"model":"c","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t",` +
			`"content":[{"type":"text","text":"a","TEXT":"b"}]}]}]}`},
		"anthropic system Text":         {FormatAnthropic, `{"model":"c","system":[{"type":"text","text":"a","Text":"b"}],"messages":[]}`},
		"gemini functionCall NAME":      {FormatGemini, `{"contents":[{"role":"model","parts":[{"functionCall":{"name":"a","NAME":"b","args":{}}}]}]}`},
		"gemini part Text":              {FormatGemini, `{"contents":[{"role":"user","parts":[{"text":"evil","Text":"hi"}]}]}`},
		"gemini both system spellings":  {FormatGemini, `{"contents":[],"systemInstruction":{"parts":[{"text":"a"}]},"system_instruction":{"parts":[{"text":"b"}]}}`},
		"gemini both call spellings":    {FormatGemini, `{"contents":[{"role":"model","parts":[{"functionCall":{"name":"a"},"function_call":{"name":"b"}}]}]}`},
		"gemini both inline spellings":  {FormatGemini, `{"contents":[{"role":"user","parts":[{"inlineData":{"data":"a"},"inline_data":{"data":"b"}}]}]}`},
		"gemini both config spellings":  {FormatGemini, `{"contents":[],"toolConfig":{"functionCallingConfig":{"mode":"ANY"}},"tool_config":{"function_calling_config":{"mode":"NONE"}}}`},
		"gemini allowed names":          {FormatVertex, `{"contents":[],"toolConfig":{"functionCallingConfig":{"allowedFunctionNames":["a"],"allowed_function_names":["b"]}}}`},
		"bedrock toolConfig toolconfig": {FormatBedrock, `{"messages":[],"toolConfig":{"tools":[]},"toolconfig":{"tools":[]}}`},
		"bedrock toolSpec Name":         {FormatBedrock, `{"messages":[],"toolConfig":{"tools":[{"toolSpec":{"name":"a","Name":"b","inputSchema":{"json":{}}}}]}}`},
		"cohere tool function Name":     {FormatCohere, `{"model":"c","messages":[],"tools":[{"type":"function","function":{"name":"a","Name":"b"}}]}`},
		"unknown format folds anywhere": {Format("custom"), `{"x":{"k":1,"K":2}}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.True(t, HasAmbiguousKeys(tc.format, []byte(tc.body)))
		})
	}
}

func TestHasAmbiguousKeysRefusesBodiesTheDecoderCannotRead(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"byte order mark":  "\xef\xbb\xbf{\"model\":\"m\",\"messages\":[]}",
		"trailing value":   `{"model":"m","messages":[]}{"TOOLS":[]}`,
		"trailing comma":   `{"model":"m","messages":[],}`,
		"NaN":              `{"model":"m","messages":[],"temperature":NaN}`,
		"utf-16":           "{\x00\"\x00m\x00\"\x00:\x001\x00}\x00",
		"too deep":         strings.Repeat("[", maxKeyDepth+1) + strings.Repeat("]", maxKeyDepth+1),
		"unterminated key": `{"model":"m","messages":[],"tools`,
	} {
		assert.True(t, HasAmbiguousKeys(FormatOpenAI, []byte(body)), name)
	}
}

func TestAmbiguousKeysScanIsBounded(t *testing.T) {
	for name, open := range map[string]string{"arrays": "[", "objects": `{"a":`} {
		body := []byte(`{"model":"m","messages":` + strings.Repeat(open, (8<<20)/len(open)))
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		ambiguous := HasAmbiguousKeys(FormatOpenAI, body) && ambiguousKeys(body, chatShape)
		runtime.ReadMemStats(&after)
		assert.True(t, ambiguous, name)
		assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(4<<20), name)
	}
}

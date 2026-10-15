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
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func allRequestText(cr *CanonicalRequest) string {
	return requestText(cr)
}

// The model reads the fields of its own family whatever the client put first,
// so every text a body carries must reach the guardrails, not just the one a
// first-key sniff would have chosen.
func TestBedrockNativeAdapter_DecodeRequest_UnionSeesEveryHiddenText(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		body   string
		wanted []string
	}{
		{"inputText beside prompt", `{"inputText":"hello","prompt":"HIDDEN-ONE"}`, []string{"hello", "HIDDEN-ONE"}},
		{"anthropic_version beside prompt", `{"anthropic_version":"bedrock-2023-05-31","messages":[{"role":"user","content":[{"type":"text","text":"visible"}]}],"prompt":"HIDDEN-TWO"}`, []string{"visible", "HIDDEN-TWO"}},
		{"prompt beside messages", `{"prompt":"first","messages":[{"role":"user","content":"HIDDEN-THREE"}]}`, []string{"first", "HIDDEN-THREE"}},
		{"cohere message beside inputText", `{"message":"m1","inputText":"HIDDEN-FOUR"}`, []string{"m1", "HIDDEN-FOUR"}},
		{"unknown keys", `{"input":"HIDDEN-FIVE","query":"HIDDEN-SIX","inputs":["HIDDEN-SEVEN"],"instruction":"HIDDEN-EIGHT"}`,
			[]string{"HIDDEN-FIVE", "HIDDEN-SIX", "HIDDEN-SEVEN", "HIDDEN-EIGHT"}},
		{"converse additionalModelRequestFields", `{"messages":[{"role":"user","content":[{"text":"visible"}]}],"additionalModelRequestFields":{"prompt":"HIDDEN-NINE","extra":{"text":"HIDDEN-TEN"}}}`,
			[]string{"visible", "HIDDEN-NINE", "HIDDEN-TEN"}},
		{"converse tool description", `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"t","description":"HIDDEN-ELEVEN","inputSchema":{"json":{}}}}]}}`,
			[]string{"hi", "HIDDEN-ELEVEN"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cr, err := (&BedrockNativeAdapter{}).DecodeRequest([]byte(tc.body))
			require.NoError(t, err)
			text := allRequestText(cr)
			for _, want := range tc.wanted {
				assert.Contains(t, text, want)
			}
		})
	}
}

func TestBedrockNativeAdapter_DecodeRequest_PlumbingIsNotText(t *testing.T) {
	t.Parallel()
	cr, err := (&BedrockNativeAdapter{}).DecodeRequest([]byte(
		`{"anthropic_version":"bedrock-2023-05-31","model":"anthropic.claude","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],"stop_sequences":["END"],"tools":[{"name":"get_weather","input_schema":{"type":"object"}}]}`))
	require.NoError(t, err)
	text := allRequestText(cr)
	for _, noise := range []string{"bedrock-2023-05-31", "anthropic.claude"} {
		assert.NotContains(t, text, noise)
	}
}

func TestBedrockNativeAdapter_DecodeResponse_UnionSeesEveryHiddenText(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		body   string
		wanted []string
	}{
		{"results beside generation", `{"results":[{"outputText":"one","completionReason":"FINISH"}],"generation":"HIDDEN-A"}`, []string{"one", "HIDDEN-A"}},
		{"anthropic beside outputs", `{"type":"message","role":"assistant","content":[{"type":"text","text":"two"}],"outputs":[{"text":"HIDDEN-B"}]}`, []string{"two", "HIDDEN-B"}},
		{"unknown key", `{"output":{"message":{"role":"assistant","content":[{"text":"three"}]}},"completion":"HIDDEN-C","other":{"body":"HIDDEN-D"}}`, []string{"three", "HIDDEN-C", "HIDDEN-D"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cr, err := (&BedrockNativeAdapter{}).DecodeResponse([]byte(tc.body))
			require.NoError(t, err)
			for _, want := range tc.wanted {
				assert.Contains(t, cr.Content, want)
			}
		})
	}
}

func TestBedrockNativeAdapter_DecodeStreamChunk_UnionSeesEveryHiddenText(t *testing.T) {
	t.Parallel()
	got, err := (&BedrockNativeAdapter{}).DecodeStreamChunk([]byte(`{"outputText":"visible","generation":"HIDDEN-X","other":"HIDDEN-Y"}`))
	require.NoError(t, err)
	require.NotNil(t, got)
	for _, want := range []string{"visible", "HIDDEN-X", "HIDDEN-Y"} {
		assert.Contains(t, got.Delta, want)
	}
}

func TestHasInvalidText(t *testing.T) {
	t.Parallel()
	bad := []string{
		"{\"prompt\":\"\xff\xfe\"}",
		`{"prompt":"\ud800"}`,
		`{"prompt":"\udc00x"}`,
		`{"prompt":"\ud800A"}`,
		`{"prompt":"\ud83d"}`,
		`{"prompt":"\uZZZZ"}`,
	}
	for _, b := range bad {
		assert.True(t, HasInvalidText([]byte(b)), b)
	}
	good := []string{
		`{"prompt":"hello"}`,
		`{"prompt":"😀 emoji"}`,
		`{"prompt":"é ünïcode \\ud800 escaped backslash"}`,
		`{"prompt":"line\nbreak \"quoted\""}`,
	}
	for _, b := range good {
		assert.False(t, HasInvalidText([]byte(b)), b)
	}
}

// The translated path decodes Converse bodies the gateway wrote itself. The
// native view must never run there, or a body of the gateway's making could
// be misread as another family.
func TestBedrockAdapter_NeverAppliesTheNativeView(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	a, err := reg.GetAdapter(FormatBedrock)
	require.NoError(t, err)
	assert.IsType(t, &BedrockAdapter{}, a)
	n, err := reg.GetAdapter(FormatBedrockNative)
	require.NoError(t, err)
	assert.IsType(t, &BedrockNativeAdapter{}, n)

	// A polyglot body means nothing to the Converse adapter: no prompt is read.
	cr, err := a.DecodeRequest([]byte(`{"inputText":"x","prompt":"not read"}`))
	require.NoError(t, err)
	assert.Empty(t, cr.Messages)

	// What the adapter's own encoders write decodes as Converse and round trips.
	req := &CanonicalRequest{Messages: []CanonicalMessage{{Role: "user", Content: "hello there"}}, System: "be brief"}
	body, err := a.EncodeRequest(req)
	require.NoError(t, err)
	back, err := a.DecodeRequest(body)
	require.NoError(t, err)
	assert.Equal(t, "hello there", back.Messages[0].Content)
	assert.Equal(t, "be brief", back.System)

	respBody, err := a.EncodeResponse(&CanonicalResponse{Content: "answer", FinishReason: "stop"})
	require.NoError(t, err)
	resp, err := a.DecodeResponse(respBody)
	require.NoError(t, err)
	assert.Equal(t, "answer", resp.Content)
	_, err = a.DecodeResponse([]byte(`{"generation":"not read"}`))
	require.NoError(t, err)
}

func TestHasAmbiguousInvokeKeys_UsesThePreciseShape(t *testing.T) {
	t.Parallel()
	// Objects a family leaves to the client, here a tool's JSON schema, may hold
	// keys that differ only in case.
	valid := `{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],` +
		`"tools":[{"name":"t","input_schema":{"type":"object","properties":{"Name":{"type":"string"},"name":{"type":"string"}}}}]}`
	assert.False(t, HasAmbiguousInvokeKeys([]byte(valid)))

	for name, body := range map[string]string{
		"repeated key":                 `{"anthropic_version":"v","max_tokens":1,"max_tokens":2}`,
		"case-folded struct field":     `{"anthropic_version":"v","max_tokens":1,"Max_Tokens":2}`,
		"byte order mark":              "\xef\xbb\xbf{\"prompt\":\"a\"}",
		"not json":                     `{"prompt":`,
		"unknown family, strict":       `{"x":{"A":1,"a":2}}`,
		"chat family struct field":     `{"messages":[{"role":"user","content":"a","Content":"b"}]}`,
		"converse family struct field": `{"messages":[{"role":"user","content":[{"text":"a"}]}],"System":[],"system":[]}`,
	} {
		assert.True(t, HasAmbiguousInvokeKeys([]byte(body)), name)
	}
}

func b64s(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// Text the model reads through a document, a name or a schema must reach the
// guardrails. Each case hides SECRET where a field-by-field denylist would miss.
func TestBedrockNativeAdapter_DecodeRequest_DocumentsNamesAndSchemas(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"anthropic text document":        `{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":[{"type":"document","source":{"type":"text","media_type":"text/plain","data":"SECRET"}},{"type":"text","text":"summarise"}]}]}`,
		"anthropic base64 text document": `{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":[{"type":"document","source":{"type":"base64","media_type":"text/plain","data":"` + b64s("SECRET") + `"}}]}]}`,
		"converse document name":         `{"messages":[{"role":"user","content":[{"document":{"format":"pdf","name":"SECRET","source":{"bytes":"aGk="}}},{"text":"summarise"}]}]}`,
		"converse txt document":          `{"messages":[{"role":"user","content":[{"document":{"format":"txt","name":"d","source":{"bytes":"` + b64s("SECRET") + `"}}}]}]}`,
		"converse md document":           `{"messages":[{"role":"user","content":[{"document":{"format":"md","name":"d","source":{"bytes":"` + b64s("SECRET") + `"}}}]}]}`,
		"openai message name":            `{"messages":[{"role":"user","name":"SECRET","content":"hi"}]}`,
		"converse tool schema key":       `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"t","inputSchema":{"json":{"type":"object","properties":{"SECRET":{"type":"string"}}}}}}]}}`,
		"anthropic tool schema key":      `{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"t","input_schema":{"type":"object","properties":{"SECRET":{"type":"string"}}}}]}`,
		"converse text document":         `{"messages":[{"role":"user","content":[{"document":{"format":"txt","name":"d","source":{"text":"SECRET"}}}]}]}`,
		"anthropic tool_result":          `{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"x","content":[{"type":"text","text":"SECRET"}]}]}]}`,
		"converse guardContent":          `{"messages":[{"role":"user","content":[{"guardContent":{"text":{"text":"SECRET"}}}]}]}`,
		"system array":                   `{"system":[{"text":"SECRET"}],"messages":[{"role":"user","content":[{"text":"hi"}]}]}`,
		"additional fields":              `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"additionalModelRequestFields":{"foo":"SECRET"}}`,
		"nested array":                   `{"prompt":"x","extra":[["SECRET"]]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cr, err := (&BedrockNativeAdapter{}).DecodeRequest([]byte(body))
			require.NoError(t, err)
			assert.Contains(t, requestText(cr), "SECRET")
		})
	}
}

func TestBedrockNativeAdapter_DecodeRequest_NonTextStaysOut(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"anthropic image":  `{"anthropic_version":"v","max_tokens":1,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + b64s("PIXELS") + `"}}]}]}`,
		"converse pdf":     `{"messages":[{"role":"user","content":[{"document":{"format":"pdf","name":"d","source":{"bytes":"` + b64s("PDFBYTES") + `"}}}]}]}`,
		"converse image":   `{"messages":[{"role":"user","content":[{"image":{"format":"png","source":{"bytes":"` + b64s("PIXELS") + `"}}}]}]}`,
		"bad base64 doc":   `{"messages":[{"role":"user","content":[{"document":{"format":"txt","name":"d","source":{"bytes":"!!not base64!!"}}}]}]}`,
		"tool names":       `{"anthropic_version":"v","max_tokens":1,"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"TOOLNAME","input_schema":{"type":"object"}}],"tool_choice":{"type":"tool","name":"TOOLNAME"}}`,
		"converse toolUse": `{"messages":[{"role":"assistant","content":[{"toolUse":{"toolUseId":"a","name":"TOOLNAME","input":{}}}]}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cr, err := (&BedrockNativeAdapter{}).DecodeRequest([]byte(body))
			require.NoError(t, err, "an undecodable document is skipped, never an error")
			text := requestText(cr)
			for _, noise := range []string{"PIXELS", "PDFBYTES", "TOOLNAME"} {
				assert.NotContains(t, text, noise)
			}
		})
	}
}

func TestBedrockNativeAdapter_DecodeStreamChunk_NoDuplicatesNoNoise(t *testing.T) {
	t.Parallel()
	a := &BedrockNativeAdapter{}

	got, err := a.DecodeStreamChunk([]byte(`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"city\":\"Rome\"}"}}`))
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.NotContains(t, got.Delta, "Rome", "a tool-call fragment is arguments, not text, and is not duplicated into the text")

	got, err = a.DecodeStreamChunk([]byte(`{"event_type":"stream-end","is_finished":true,"finish_reason":"COMPLETE","response":{"text":"the whole answer again"}}`))
	require.NoError(t, err)
	if got != nil {
		assert.NotContains(t, got.Delta, "the whole answer again")
	}
}

// A text document the view cannot read is not a document with nothing in it: the
// model reads whatever bytes the client sent, so one that does not decode to text
// is reported, and the gateway refuses the call.
func TestHasUninspectableDocument(t *testing.T) {
	t.Parallel()
	enc := base64.StdEncoding.EncodeToString
	cases := map[string]struct {
		body string
		want bool
	}{
		"padded text document":           {`{"messages":[{"role":"user","content":[{"document":{"format":"txt","name":"n","source":{"bytes":"` + enc([]byte("hello john@x.com")) + `"}}}]}]}`, false},
		"unpadded text document":         {`{"messages":[{"role":"user","content":[{"document":{"format":"txt","name":"n","source":{"bytes":"` + base64.RawStdEncoding.EncodeToString([]byte("hello john@x.com")) + `"}}}]}]}`, false},
		"document that is not base64":    {`{"messages":[{"role":"user","content":[{"document":{"format":"csv","name":"n","source":{"bytes":"@@not base64@@"}}}]}]}`, true},
		"document that is not UTF-8":     {`{"messages":[{"role":"user","content":[{"document":{"format":"txt","name":"n","source":{"bytes":"` + enc([]byte{0xff, 0xfe, 'a'}) + `"}}}]}]}`, true},
		"anthropic text document":        {`{"anthropic_version":"v","messages":[{"role":"user","content":[{"type":"document","source":{"type":"base64","media_type":"text/plain","data":"` + enc([]byte{0xc3, 0x28}) + `"}}]}]}`, true},
		"a pdf is not text, so not read": {`{"messages":[{"role":"user","content":[{"document":{"format":"pdf","name":"n","source":{"bytes":"` + enc([]byte{0xff, 0xfe}) + `"}}}]}]}`, false},
		"an image is not text":           {`{"messages":[{"role":"user","content":[{"image":{"format":"png","source":{"bytes":"` + enc([]byte{0xff, 0xfe}) + `"}}}]}]}`, false},
		"no document":                    {`{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`, false},
		"not JSON":                       {`nope`, false},
	}
	for name, tc := range cases {
		assert.Equal(t, tc.want, HasUninspectableDocument([]byte(tc.body)), name)
	}
}

// Unpadded base64 is how some clients write a document: its text is in the view,
// and a mask on it keeps the style it was sent in.
func TestNativeAdapter_UnpaddedDocumentIsReadAndMaskedInItsOwnStyle(t *testing.T) {
	t.Parallel()
	text := "contact john@x.com now" // 22 bytes: its padded form ends in "="
	raw := base64.RawStdEncoding.EncodeToString([]byte(text))
	require.NotContains(t, raw, "=")
	original := []byte(`{"messages":[{"role":"user","content":[{"document":{"format":"txt","name":"n","source":{"bytes":"` + raw + `"}}}]}]}`)

	cr, err := (&BedrockNativeAdapter{}).DecodeRequest(original)
	require.NoError(t, err)
	assert.Contains(t, requestText(cr), "john@x.com", "the document is in the view")

	masked, ok := NativeMasker{}.MaskRequest(original, pluginRewrite(t, original, "john@x.com", "<EMAIL>"))
	require.True(t, ok)
	var tree struct {
		Messages []struct {
			Content []struct {
				Document struct {
					Source struct {
						Bytes string `json:"bytes"`
					} `json:"source"`
				} `json:"document"`
			} `json:"content"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(masked, &tree))
	got := tree.Messages[0].Content[0].Document.Source.Bytes
	assert.NotContains(t, got, "=", "the style the client used is kept")
	decoded, err := base64.RawStdEncoding.DecodeString(got)
	require.NoError(t, err)
	assert.Equal(t, "contact <EMAIL> now", string(decoded))
}

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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const nativeMaskEmail = "john.doe@example.com"

// pluginRewrite does what a masking plugin does to a native body: read it with
// the view, replace text in the canonical request, encode it again. What comes
// out is the lossy body the mask is derived from and never the one that is sent.
func pluginRewrite(t *testing.T, body []byte, from, to string) []byte {
	t.Helper()
	a := &BedrockNativeAdapter{}
	cr, err := a.DecodeRequest(body)
	require.NoError(t, err)
	cr.System = strings.ReplaceAll(cr.System, from, to)
	for i := range cr.Messages {
		cr.Messages[i].Content = strings.ReplaceAll(cr.Messages[i].Content, from, to)
	}
	out, err := a.EncodeRequest(cr)
	require.NoError(t, err)
	return out
}

func pluginRewriteResponse(t *testing.T, body []byte, from, to string) []byte {
	t.Helper()
	a := &BedrockNativeAdapter{}
	cr, err := a.DecodeResponse(body)
	require.NoError(t, err)
	cr.Content = strings.ReplaceAll(cr.Content, from, to)
	out, err := a.EncodeResponse(cr)
	require.NoError(t, err)
	return out
}

func decodeTree(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree map[string]any
	require.NoError(t, dec.Decode(&tree))
	return tree
}

func nativeRequestBody() []byte {
	doc := base64.StdEncoding.EncodeToString([]byte("notes: contact " + nativeMaskEmail + " tomorrow"))
	return []byte(`{
  "system": [{"text": "You help ` + nativeMaskEmail + `"}],
  "messages": [
    {"role": "user", "content": [
      {"text": "my email is ` + nativeMaskEmail + ` please reply"},
      {"cachePoint": {"type": "default"}},
      {"document": {"format": "txt", "name": "notes for ` + nativeMaskEmail + `", "source": {"bytes": "` + doc + `"}}}
    ]}
  ],
  "inferenceConfig": {"maxTokens": 100, "temperature": 0.1, "topP": 0.9},
  "guardrailConfig": {"guardrailIdentifier": "gr-1", "guardrailVersion": "1", "trace": "enabled"},
  "additionalModelRequestFields": {
    "note": "copy for ` + nativeMaskEmail + `",
    "numbers": [0.1, 1e-7, 9007199254740993, 12345678901234567890],
    "unicode": "héllo ✓   <tag> & done"
  }
}`)
}

func TestNativeMasker_MaskRequest_CarriesTheMaskOntoTheOriginal(t *testing.T) {
	t.Parallel()
	original := nativeRequestBody()
	modified := pluginRewrite(t, original, nativeMaskEmail, "<EMAIL>")

	masked, ok := NativeMasker{}.MaskRequest(original, modified)
	require.True(t, ok)

	text := string(masked)
	assert.NotContains(t, text, nativeMaskEmail, "no copy of the original text survives, in any field")
	assert.Contains(t, text, "<EMAIL>", "HTML escaping is off: the mask stays literal")
	assert.NotContains(t, text, "\\u003c")

	tree := decodeTree(t, masked)
	orig := decodeTree(t, original)

	// Fields that were not masked are equal in value, numbers by their literal.
	assert.Equal(t, orig["inferenceConfig"], tree["inferenceConfig"])
	assert.Equal(t, orig["guardrailConfig"], tree["guardrailConfig"])
	extra := tree["additionalModelRequestFields"].(map[string]any)
	origExtra := orig["additionalModelRequestFields"].(map[string]any)
	assert.Equal(t, origExtra["numbers"], extra["numbers"])
	assert.Equal(t, origExtra["unicode"], extra["unicode"])
	assert.Equal(t, "copy for <EMAIL>", extra["note"], "an unmodelled copy of the same text is masked too")
	assert.Contains(t, text, `"temperature": 0.1`, "spacing and literals of what is not masked are as they were")
	assert.Contains(t, text, `1e-7`)
	assert.Contains(t, text, `9007199254740993`)
	assert.Contains(t, text, `12345678901234567890`)

	content := tree["messages"].([]any)[0].(map[string]any)["content"].([]any)
	assert.Equal(t, "my email is <EMAIL> please reply", content[0].(map[string]any)["text"])
	assert.Equal(t, orig["messages"].([]any)[0].(map[string]any)["content"].([]any)[1], content[1], "cachePoint is untouched")
	document := content[2].(map[string]any)["document"].(map[string]any)
	assert.Equal(t, "notes for <EMAIL>", document["name"])
	raw, err := base64.StdEncoding.DecodeString(document["source"].(map[string]any)["bytes"].(string))
	require.NoError(t, err)
	assert.Equal(t, "notes: contact <EMAIL> tomorrow", string(raw), "a base64 text document is decoded, masked and encoded again")
	assert.Equal(t, "You help <EMAIL>", tree["system"].([]any)[0].(map[string]any)["text"])
}

func TestNativeMasker_MaskRequest_AnthropicBase64TextDocument(t *testing.T) {
	t.Parallel()
	doc := base64.StdEncoding.EncodeToString([]byte("report for " + nativeMaskEmail))
	original := []byte(`{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":[` +
		`{"type":"document","source":{"type":"base64","media_type":"text/plain","data":"` + doc + `"}},` +
		`{"type":"text","text":"write to ` + nativeMaskEmail + `"}]}]}`)
	modified := pluginRewrite(t, original, nativeMaskEmail, "<EMAIL>")

	masked, ok := NativeMasker{}.MaskRequest(original, modified)
	require.True(t, ok)
	assert.NotContains(t, string(masked), nativeMaskEmail)
	content := decodeTree(t, masked)["messages"].([]any)[0].(map[string]any)["content"].([]any)
	data := content[0].(map[string]any)["source"].(map[string]any)["data"].(string)
	raw, err := base64.StdEncoding.DecodeString(data)
	require.NoError(t, err)
	assert.Equal(t, "report for <EMAIL>", string(raw))
}

func TestNativeMasker_MaskRequest_InvokeFamilies(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"titan":  `{"inputText":"mail ` + nativeMaskEmail + `","textGenerationConfig":{"maxTokenCount":50,"temperature":0.5}}`,
		"llama":  `{"prompt":"mail ` + nativeMaskEmail + `","max_gen_len":50,"temperature":0.5}`,
		"cohere": `{"message":"mail ` + nativeMaskEmail + `","max_tokens":50,"temperature":0.5}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			original := []byte(body)
			modified := pluginRewrite(t, original, nativeMaskEmail, "<EMAIL>")
			masked, ok := NativeMasker{}.MaskRequest(original, modified)
			require.True(t, ok)
			assert.NotContains(t, string(masked), nativeMaskEmail)
			assert.Contains(t, string(masked), "<EMAIL>")
			assert.NotContains(t, string(masked), "messages", "the family's own shape is kept, not turned into Converse")
		})
	}
}

// The leak check is the safety net: a patcher that leaves one copy behind must
// send nothing, whatever it claims.
func TestNativeMasker_MaskRequest_BrokenPatcherLeaksNothing(t *testing.T) {
	t.Parallel()
	original := nativeRequestBody()
	modified := pluginRewrite(t, original, nativeMaskEmail, "<EMAIL>")

	leavesOneCopy := NativeMasker{Patch: func(body []byte, subs []Substitution) ([]byte, error) {
		out, err := patchInPlace(body, subs)
		if err != nil {
			return nil, err
		}
		// Put the original back into the unmodelled field.
		return bytes.Replace(out, []byte("copy for <EMAIL>"), []byte("copy for "+nativeMaskEmail), 1), nil
	}}
	masked, ok := leavesOneCopy.MaskRequest(original, modified)
	assert.False(t, ok)
	assert.Nil(t, masked, "nothing is returned to send")

	doesNothing := NativeMasker{Patch: func(body []byte, _ []Substitution) ([]byte, error) { return body, nil }}
	_, ok = doesNothing.MaskRequest(original, modified)
	assert.False(t, ok)

	fails := NativeMasker{Patch: func([]byte, []Substitution) ([]byte, error) { return nil, assert.AnError }}
	_, ok = fails.MaskRequest(original, modified)
	assert.False(t, ok)

	// Only the leak check catches this one: the patcher leaves the text in the
	// base64 document, which no field-by-field look at the tree would see.
	skipsDocuments := NativeMasker{Patch: func(body []byte, subs []Substitution) ([]byte, error) {
		tree := decodeTree(t, body)
		doc := tree["messages"].([]any)[0].(map[string]any)["content"].([]any)[2].(map[string]any)["document"].(map[string]any)
		saved := doc["source"].(map[string]any)["bytes"]
		out, err := patchInPlace(body, subs)
		if err != nil {
			return nil, err
		}
		patched := decodeTree(t, out)
		patched["messages"].([]any)[0].(map[string]any)["content"].([]any)[2].(map[string]any)["document"].(map[string]any)["source"].(map[string]any)["bytes"] = saved
		return marshalNoEscape(patched)
	}}
	_, ok = skipsDocuments.MaskRequest(original, modified)
	assert.False(t, ok, "a copy hidden in a base64 document is found by the leak check")
}

// The view leaves out keys and identifiers, so a patcher that leaves the text in
// one of those is not seen by the view-based checks. The tree walk is the one
// that does not depend on the view.
func TestNativeMasker_MaskRequest_LeakInAPlaceTheViewDoesNotReadIsFound(t *testing.T) {
	t.Parallel()
	original := []byte(`{"messages":[{"role":"user","content":[{"text":"mail ` + nativeMaskEmail + `"}]}],"extra":{"` + nativeMaskEmail + `":1}}`)
	modified := pluginRewrite(t, original, nativeMaskEmail, "<EMAIL>")

	// The patch writes into the strings the view reads, never into a key, so the
	// key keeps the text and nothing may be sent.
	_, ok := NativeMasker{}.MaskRequest(original, modified)
	assert.False(t, ok)

	assert.True(t, treeLeaks([]byte(`{"a":{"`+nativeMaskEmail+`":1}}`), []Substitution{{From: nativeMaskEmail, To: "<EMAIL>"}}))
	assert.False(t, treeLeaks([]byte(`{"a":"clean"}`), []Substitution{{From: nativeMaskEmail, To: "<EMAIL>"}}))
	assert.True(t, treeLeaks([]byte(`not json`), []Substitution{{From: nativeMaskEmail}}), "an unreadable body is refused")
}

func TestNativeMasker_MaskRequest_RefusesWhatItCannotReproduce(t *testing.T) {
	t.Parallel()
	a := &BedrockNativeAdapter{}
	original := []byte(`{"messages":[{"role":"user","content":[{"text":"mail ` + nativeMaskEmail + `"}]}],` +
		`"inferenceConfig":{"maxTokens":100,"temperature":0.5},` +
		`"toolConfig":{"tools":[{"toolSpec":{"name":"a","inputSchema":{"json":{"type":"object"}}}},{"toolSpec":{"name":"b","inputSchema":{"json":{"type":"object"}}}}]}}`)
	withCR := func(mutate func(cr *CanonicalRequest)) []byte {
		cr, err := a.DecodeRequest(original)
		require.NoError(t, err)
		mutate(cr)
		out, err := a.EncodeRequest(cr)
		require.NoError(t, err)
		return out
	}
	mask := func(cr *CanonicalRequest) {
		for i := range cr.Messages {
			cr.Messages[i].Content = strings.ReplaceAll(cr.Messages[i].Content, nativeMaskEmail, "<EMAIL>")
		}
	}
	cases := map[string][]byte{
		"a tool was removed too":  withCR(func(cr *CanonicalRequest) { mask(cr); cr.Tools = cr.Tools[:1] }),
		"a limit was changed too": withCR(func(cr *CanonicalRequest) { mask(cr); cr.MaxTokens = 5 }),
		"text was added":          withCR(func(cr *CanonicalRequest) { mask(cr); cr.System = "an injected rule" }),
		"nothing textual changed": withCR(func(cr *CanonicalRequest) { cr.MaxTokens = 5 }),
		"not a body":              []byte(`not json`),
	}
	for name, modified := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, ok := NativeMasker{}.MaskRequest(original, modified)
			assert.False(t, ok)
		})
	}
}

func TestNativeMasker_MaskResponse(t *testing.T) {
	t.Parallel()
	t.Run("converse output", func(t *testing.T) {
		t.Parallel()
		original := []byte(`{"output":{"message":{"role":"assistant","content":[{"text":"write to ` + nativeMaskEmail + `"}]}},"stopReason":"end_turn",` +
			`"usage":{"inputTokens":7,"outputTokens":3,"totalTokens":10},"metrics":{"latencyMs":1234},"trace":{"guardrail":{"note":"` + nativeMaskEmail + `"}}}`)
		modified := pluginRewriteResponse(t, original, nativeMaskEmail, "<EMAIL>")
		masked, ok := NativeMasker{}.MaskResponse(original, modified)
		require.True(t, ok)
		tree := decodeTree(t, masked)
		assert.Equal(t, nativeMaskEmail, tree["trace"].(map[string]any)["guardrail"].(map[string]any)["note"],
			"the trace is not text the view reads, so it is not part of the mask")
		assert.Equal(t, decodeTree(t, original)["usage"], tree["usage"])
		assert.Equal(t, decodeTree(t, original)["metrics"], tree["metrics"])
		assert.Equal(t, "end_turn", tree["stopReason"])
		assert.Contains(t, string(masked), "write to <EMAIL>")
	})
	t.Run("anthropic invoke body", func(t *testing.T) {
		t.Parallel()
		original := []byte(`{"id":"msg_01","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"mail ` + nativeMaskEmail + `"}],` +
			`"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}}`)
		modified := pluginRewriteResponse(t, original, nativeMaskEmail, "<EMAIL>")
		masked, ok := NativeMasker{}.MaskResponse(original, modified)
		require.True(t, ok)
		assert.NotContains(t, string(masked), nativeMaskEmail)
		tree := decodeTree(t, masked)
		assert.Equal(t, "msg_01", tree["id"])
		assert.Equal(t, "message", tree["type"], "the body keeps the family's shape, not Converse")
		assert.Equal(t, decodeTree(t, original)["usage"], tree["usage"])
		assert.Contains(t, string(masked), "mail <EMAIL>")
	})
	t.Run("a broken patcher leaks nothing", func(t *testing.T) {
		t.Parallel()
		original := []byte(`{"output":{"message":{"role":"assistant","content":[{"text":"write to ` + nativeMaskEmail + `"}]}},"x":"` + nativeMaskEmail + `"}`)
		modified := pluginRewriteResponse(t, original, nativeMaskEmail, "<EMAIL>")
		broken := NativeMasker{Patch: func(body []byte, subs []Substitution) ([]byte, error) {
			out, _ := patchInPlace(body, subs)
			return bytes.Replace(out, []byte(`"x":"<EMAIL>"`), []byte(`"x":"`+nativeMaskEmail+`"`), 1), nil
		}}
		_, ok := broken.MaskResponse(original, modified)
		assert.False(t, ok)
	})
}

func TestDistributeHunks(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		texts []string
		hunks []TextHunk
		want  []string
	}{
		{"inside one piece", []string{"hello ", "bob@x.io now"}, []TextHunk{{Start: 6, End: 14, Insert: "<E>"}}, []string{"hello ", "<E> now"}},
		{"split across two pieces", []string{"mail bob@", "x.io now"}, []TextHunk{{Start: 5, End: 13, Insert: "<EMAIL>"}}, []string{"mail <EMAIL>", " now"}},
		{"split across three pieces", []string{"a bo", "b@x", ".io z"}, []TextHunk{{Start: 2, End: 10, Insert: "<M>"}}, []string{"a <M>", "", " z"}},
		{"two hunks", []string{"one two ", "three four"}, []TextHunk{{Start: 0, End: 3, Insert: "1"}, {Start: 8, End: 13, Insert: "3"}}, []string{"1 two ", "3 four"}},
		{"insertion at the end", []string{"ab", "cd"}, []TextHunk{{Start: 4, End: 4, Insert: "!"}}, []string{"ab", "cd!"}},
		{"deletion", []string{"abc", "def"}, []TextHunk{{Start: 2, End: 4, Insert: ""}}, []string{"ab", "ef"}},
		{"no hunks", []string{"x", "y"}, nil, []string{"x", "y"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := DistributeHunks(tc.texts, tc.hunks)
			assert.Equal(t, tc.want, got)
			// The concatenation is the concatenation with the hunks applied.
			joined := strings.Join(tc.texts, "")
			applied := joined
			for i := len(tc.hunks) - 1; i >= 0; i-- {
				h := tc.hunks[i]
				applied = applied[:h.Start] + h.Insert + applied[h.End:]
			}
			assert.Equal(t, applied, strings.Join(got, ""))
		})
	}
}

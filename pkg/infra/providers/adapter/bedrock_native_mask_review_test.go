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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Everything the mask must leave alone is compared as raw bytes, not as a tree:
// the patch is made in place on the bytes the client sent.

const (
	fakeImageB64 = "AAAABobBBBBB" // base64 that happens to contain "Bob"
	fakePDFB64   = "CCCCBobDDDD"  // not even valid base64 padding: must be left alone anyway
)

func TestNativeMask_InPlace_NonTextBase64AndIdentifiersAreByteIdentical(t *testing.T) {
	t.Parallel()
	original := []byte(`{"messages":[` +
		`{"role":"user","content":[{"text":"my name is Bob, describe the image"},` +
		`{"image":{"format":"png","source":{"bytes":"` + fakeImageB64 + `"}}},` +
		`{"document":{"format":"pdf","name":"scan of Bob","source":{"bytes":"` + fakePDFB64 + `"}}}]},` +
		`{"role":"assistant","content":[{"toolUse":{"toolUseId":"tooluse_Bob9xQ","name":"lookup","input":{"q":"x"}}}]},` +
		`{"role":"user","content":[{"toolResult":{"toolUseId":"tooluse_Bob9xQ","content":[{"text":"found"}]}}]}],` +
		`"guardrailConfig":{"guardrailIdentifier":"Bobguard1","guardrailVersion":"1"},"requestMetadata":{"tenant_id":"Bob-42"},` +
		`"toolConfig":{"tools":[{"toolSpec":{"name":"lookup","inputSchema":{"json":{"type":"object","properties":{"q":{"type":"string"}}}}}}]}}`)
	modified := pluginRewrite(t, original, "Bob", "[NAME]")

	masked, ok := NativeMasker{}.MaskRequest(original, modified)
	require.True(t, ok)
	s := string(masked)
	assert.Contains(t, s, `"bytes":"`+fakeImageB64+`"`, "image bytes are not text and are untouched")
	assert.Contains(t, s, `"bytes":"`+fakePDFB64+`"`, "pdf bytes are not text and are untouched")
	assert.Contains(t, s, `"toolUseId":"tooluse_Bob9xQ"`, "an identifier is untouched, or the tool result no longer matches its call")
	assert.Contains(t, s, `"guardrailIdentifier":"Bobguard1"`)
	assert.Contains(t, s, `"tenant_id":"Bob-42"`)
	assert.Contains(t, s, `my name is [NAME], describe the image`)
	assert.Contains(t, s, `scan of [NAME]`)
}

func TestNativeMask_InPlace_PartialMaskDoesNotRewriteUnrelatedValues(t *testing.T) {
	t.Parallel()
	original := []byte(`{"messages":[{"role":"user","content":[{"text":"mail john@x.com"}]}],` +
		`"guardrailConfig":{"guardrailIdentifier":"ohnguard1","guardrailVersion":"1"},"requestMetadata":{"tenant_id":"ohn-42"}}`)
	modified := pluginRewrite(t, original, "john@x.com", "j***@x.com")

	masked, ok := NativeMasker{}.MaskRequest(original, modified)
	require.True(t, ok, "a value that merely contains the trimmed original is not a leak")
	s := string(masked)
	assert.Contains(t, s, `"guardrailIdentifier":"ohnguard1"`)
	assert.Contains(t, s, `"tenant_id":"ohn-42"`)
	assert.Contains(t, s, `mail j***@x.com`)
}

func TestNativeMask_InPlace_KeepsTheBytesOfEverythingElse(t *testing.T) {
	t.Parallel()
	// Key order, spacing, escapes and number literals of what is not masked.
	original := []byte("{\n  \"zeta\": 1.50,\n  \"messages\": [ {\"role\":\"user\", \"content\":[{\"text\":\"mail john@x.com \\u00e9\"}]} ],\n" +
		"  \"alpha\": 1e-7, \"big\": 12345678901234567890, \"dup\": \"a\\/b\", \"dup\": 2 }")
	modified := pluginRewrite(t, original, "john@x.com", "<EMAIL>")
	masked, ok := NativeMasker{}.MaskRequest(original, modified)
	require.True(t, ok)
	want := strings.Replace(string(original), "mail john@x.com \\u00e9", "mail <EMAIL> é", 1)
	assert.Equal(t, want, string(masked), "only the masked string changes; keys, spacing, numbers and escapes elsewhere are byte-identical")
}

func TestNativeMask_InPlace_NumberPIIOutsideTheViewIsRefused(t *testing.T) {
	t.Parallel()
	original := []byte(`{"messages":[{"role":"user","content":[{"text":"card 4111111111111111"}]},` +
		`{"role":"assistant","content":[{"toolUse":{"toolUseId":"t1","name":"pay","input":{"card":4111111111111111}}}]},` +
		`{"role":"user","content":[{"toolResult":{"toolUseId":"t1","content":[{"text":"ok"}]}}]}],` +
		`"toolConfig":{"tools":[{"toolSpec":{"name":"pay","inputSchema":{"json":{"type":"object"}}}}]}}`)
	modified := pluginRewrite(t, original, "4111111111111111", "[CARD]")
	_, ok := NativeMasker{}.MaskRequest(original, modified)
	assert.False(t, ok, "the same card number as a JSON number would reach Bedrock")
}

func TestNativeMask_InPlace_EscapedOriginals(t *testing.T) {
	t.Parallel()
	original := []byte(`{"messages":[{"role":"user","content":[{"text":"mail john\u0040x.com and Jos\u00e9 P\u00e9rez"}]}],` +
		`"additionalModelRequestFields":{"n":"john@x.com"}}`)
	for name, c := range map[string]struct{ from, to, want string }{
		"escaped email":     {"john@x.com", "[E]", `mail [E] and Jos`},
		"escaped non-ascii": {"José Pérez", "[P]", `and [P]`},
	} {
		t.Run(name, func(t *testing.T) {
			modified := pluginRewrite(t, original, c.from, c.to)
			masked, ok := NativeMasker{}.MaskRequest(original, modified)
			require.True(t, ok)
			assert.Contains(t, string(masked), c.want)
			assert.NotContains(t, string(masked), c.from)
		})
	}
}

func TestNativeMask_InPlace_SignedBlocksAreNeverRewritten(t *testing.T) {
	t.Parallel()
	t.Run("response with a thinking block", func(t *testing.T) {
		t.Parallel()
		original := []byte(`{"id":"msg_01","type":"message","role":"assistant","model":"claude","content":[` +
			`{"type":"thinking","thinking":"user is john@x.com so","signature":"EqQBCgIYAhIM"},` +
			`{"type":"text","text":"mail john@x.com"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}}`)
		modified := pluginRewriteResponse(t, original, "john@x.com", "<EMAIL>")
		_, ok := NativeMasker{}.MaskResponse(original, modified)
		assert.False(t, ok, "a signed block cannot be edited without invalidating its signature")
	})
	t.Run("request with a thinking block in the history", func(t *testing.T) {
		t.Parallel()
		original := []byte(`{"anthropic_version":"bedrock-2023-05-31","max_tokens":100,"messages":[` +
			`{"role":"user","content":"hi john@x.com"},` +
			`{"role":"assistant","content":[{"type":"thinking","thinking":"user john@x.com","signature":"EqQBCgIYAhIM"},{"type":"text","text":"hello"}]},` +
			`{"role":"user","content":"thanks"}]}`)
		modified := pluginRewrite(t, original, "john@x.com", "<EMAIL>")
		_, ok := NativeMasker{}.MaskRequest(original, modified)
		assert.False(t, ok)
	})
	t.Run("converse reasoning content", func(t *testing.T) {
		t.Parallel()
		original := []byte(`{"messages":[{"role":"assistant","content":[{"reasoningContent":{"reasoningText":{"text":"john@x.com is the user","signature":"sig"}}},{"text":"hi john@x.com"}]}]}`)
		modified := pluginRewrite(t, original, "john@x.com", "<EMAIL>")
		_, ok := NativeMasker{}.MaskRequest(original, modified)
		assert.False(t, ok)
	})
	t.Run("a mask that does not touch the signed block still goes through", func(t *testing.T) {
		t.Parallel()
		original := []byte(`{"anthropic_version":"bedrock-2023-05-31","max_tokens":100,"messages":[` +
			`{"role":"assistant","content":[{"type":"thinking","thinking":"thinking about nothing","signature":"EqQB"},{"type":"text","text":"hello"}]},` +
			`{"role":"user","content":"mail john@x.com"}]}`)
		modified := pluginRewrite(t, original, "john@x.com", "<EMAIL>")
		masked, ok := NativeMasker{}.MaskRequest(original, modified)
		require.True(t, ok)
		assert.Contains(t, string(masked), `"signature":"EqQB"`)
		assert.Contains(t, string(masked), `"thinking":"thinking about nothing"`)
	})
}

// The same body must read the same every time, or a mask succeeds a few times
// in a hundred and the view a plugin sees changes under its feet.
func TestNativeMask_ViewIsDeterministic(t *testing.T) {
	t.Parallel()
	original := []byte(`{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"tools":[{"name":"f","description":"d","input_schema":{"type":"object",` +
		`"properties":{"zeta":{"type":"string"},"alpha":{"type":"string"},"mid":{"type":"string"},"beta":{"type":"string"},"omega":{"type":"string"}},"required":["zeta"]}}],` +
		`"messages":[{"role":"user","content":"mail john@x.com"}]}`)
	a := &BedrockNativeAdapter{}
	views := map[string]int{}
	oks := 0
	for range 200 {
		cr, err := a.DecodeRequest(original)
		require.NoError(t, err)
		views[requestText(cr)]++
		modified := pluginRewrite(t, original, "john@x.com", "<EMAIL>")
		if _, ok := (NativeMasker{}).MaskRequest(original, modified); ok {
			oks++
		}
	}
	assert.Len(t, views, 1, "one body, one view")
	assert.Equal(t, 200, oks, "masking a request with a multi-property tool schema succeeds every time")
}

// A string the policy did not touch must not come back as an addition: masking
// "Paris Hilton" leaves the enum "Paris" of a tool exactly where it was.
func TestNativeMask_InPlace_LeftoverDoesNotDependOnTheMaskedText(t *testing.T) {
	t.Parallel()
	original := []byte(`{"messages":[{"role":"user","content":[{"text":"I am Paris Hilton"}]}],` +
		`"toolConfig":{"tools":[{"toolSpec":{"name":"weather","description":"weather","inputSchema":{"json":{"type":"object","properties":{"city":{"type":"string","enum":["Paris","Rome"]}}}}}}]}}`)
	modified := pluginRewrite(t, original, "Paris Hilton", "[PERSON]")
	masked, ok := NativeMasker{}.MaskRequest(original, modified)
	require.True(t, ok, "masking a name that contains an enum value is not an addition")
	assert.Contains(t, string(masked), `"enum":["Paris","Rome"]`, "the tool contract is untouched")
	assert.Contains(t, string(masked), "I am [PERSON]")

	// Masking the enum value itself would change the tool's contract: refused.
	modified2 := pluginRewrite(t, original, "Paris", "[CITY]")
	_, ok = NativeMasker{}.MaskRequest(original, modified2)
	assert.False(t, ok)
}

func TestNativeMask_InPlace_ReplacementIsAProperlyEscapedJSONString(t *testing.T) {
	t.Parallel()
	original := []byte(`{"messages":[{"role":"user","content":[{"text":"token SECRET123 end"}]}]}`)
	modified := pluginRewrite(t, original, "SECRET123", "<a \"b\" \\ c\nd & e>")
	masked, ok := NativeMasker{}.MaskRequest(original, modified)
	require.True(t, ok)
	assert.Contains(t, string(masked), `token <a \"b\" \\ c\nd & e> end`, "quotes, backslash and newline are escaped; < > & are not")
	tree := decodeTree(t, masked)
	assert.Equal(t, "token <a \"b\" \\ c\nd & e> end", tree["messages"].([]any)[0].(map[string]any)["content"].([]any)[0].(map[string]any)["text"])
}

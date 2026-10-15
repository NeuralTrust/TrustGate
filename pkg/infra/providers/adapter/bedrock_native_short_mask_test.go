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

// pluginRewriteMessage is a plugin that masks one message only: from becomes to
// in the message at index, and nowhere else.
func pluginRewriteMessage(t *testing.T, body []byte, index int, from, to string) []byte {
	t.Helper()
	a := &BedrockNativeAdapter{}
	cr, err := a.DecodeRequest(body)
	require.NoError(t, err)
	cr.Messages[index].Content = strings.ReplaceAll(cr.Messages[index].Content, from, to)
	out, err := a.EncodeRequest(cr)
	require.NoError(t, err)
	return out
}

const shortMaskConverse = `{
  "messages": [
    {"role": "user", "content": [{"text": "my pin is 42 ok"}]},
    {"role": "user", "content": [{"text": "order 42 shipped, total 142"}]}
  ],
  "inferenceConfig": {"maxTokens": 42, "temperature": 0.42},
  "additionalModelRequestFields": {"id": "x-42-y", "ref": 42}
}`

// A value of two characters is applied where the plugin changed it and nowhere
// else: the same two characters in another message, in a number and in an
// identifier are left alone.
func TestNativeMasker_ShortValueIsMaskedWhereThePluginFoundIt(t *testing.T) {
	t.Parallel()
	original := []byte(shortMaskConverse)
	modified := pluginRewriteMessage(t, original, 0, "42", "##")

	masked, ok := NativeMasker{}.MaskRequest(original, modified)
	require.True(t, ok)

	want := strings.Replace(shortMaskConverse, "my pin is 42 ok", "my pin is ## ok", 1)
	assert.Equal(t, want, string(masked), "one string changed, every other byte is as it was")
}

func TestNativeMasker_ShortValueMaskedInEveryPlaceThePluginChangedIt(t *testing.T) {
	t.Parallel()
	original := []byte(shortMaskConverse)
	modified := pluginRewrite(t, original, "42", "##")

	masked, ok := NativeMasker{}.MaskRequest(original, modified)
	require.True(t, ok)

	want := strings.Replace(shortMaskConverse, "my pin is 42 ok", "my pin is ## ok", 1)
	want = strings.Replace(want, "order 42 shipped, total 142", "order ## shipped, total 1##", 1)
	assert.Equal(t, want, string(masked))
	assert.Contains(t, string(masked), `"maxTokens": 42`)
	assert.Contains(t, string(masked), `"id": "x-42-y"`)
	assert.Contains(t, string(masked), `"ref": 42`)
}

// Only one of two identical strings was masked by the plugin.
func TestNativeMasker_ShortValueInOneOfTwoIdenticalStrings(t *testing.T) {
	t.Parallel()
	original := []byte(`{"messages":[{"role":"user","content":[{"text":"pin 42"}]},{"role":"user","content":[{"text":"pin 42"}]}]}`)
	modified := pluginRewriteMessage(t, original, 1, "42", "##")

	masked, ok := NativeMasker{}.MaskRequest(original, modified)
	require.True(t, ok)
	assert.JSONEq(t, `{"messages":[{"role":"user","content":[{"text":"pin 42"}]},{"role":"user","content":[{"text":"pin ##"}]}]}`, string(masked))
}

func TestNativeMasker_ShortAndLongValuesTogether(t *testing.T) {
	t.Parallel()
	original := []byte(`{"messages":[` +
		`{"role":"user","content":[{"text":"pin 42 mail ` + nativeMaskEmail + `"}]},` +
		`{"role":"user","content":[{"text":"again 42 and ` + nativeMaskEmail + `"}]}],` +
		`"additionalModelRequestFields":{"note":"copy ` + nativeMaskEmail + ` 42"}}`)
	a := &BedrockNativeAdapter{}
	cr, err := a.DecodeRequest(original)
	require.NoError(t, err)
	cr.Messages[0].Content = strings.NewReplacer("42", "##", nativeMaskEmail, "<EMAIL>").Replace(cr.Messages[0].Content)
	cr.Messages[1].Content = strings.ReplaceAll(cr.Messages[1].Content, nativeMaskEmail, "<EMAIL>")
	for i := 2; i < len(cr.Messages); i++ {
		cr.Messages[i].Content = strings.ReplaceAll(cr.Messages[i].Content, nativeMaskEmail, "<EMAIL>")
	}
	modified, err := a.EncodeRequest(cr)
	require.NoError(t, err)

	masked, ok := NativeMasker{}.MaskRequest(original, modified)
	require.True(t, ok)
	text := string(masked)
	assert.NotContains(t, text, nativeMaskEmail, "the long value is masked everywhere, unmodelled copies included")
	assert.Contains(t, text, "pin ## mail <EMAIL>")
	assert.Contains(t, text, "again 42 and <EMAIL>", "the short value is left where the plugin left it")
	assert.Contains(t, text, "copy <EMAIL> 42")
}

func TestNativeMasker_ShortValueAnthropicInvoke(t *testing.T) {
	t.Parallel()
	original := []byte(`{"anthropic_version":"bedrock-2023-05-31","max_tokens":42,"messages":[` +
		`{"role":"user","content":[{"type":"text","text":"call me on 42 now"}]},` +
		`{"role":"user","content":[{"type":"text","text":"or at 42 later"}]}]}`)
	modified := pluginRewriteMessage(t, original, 0, "42", "##")

	masked, ok := NativeMasker{}.MaskRequest(original, modified)
	require.True(t, ok)
	assert.Equal(t, strings.Replace(string(original), "call me on 42 now", "call me on ## now", 1), string(masked))
}

func TestNativeMasker_ShortValueBufferedResponse(t *testing.T) {
	t.Parallel()
	original := []byte(`{"output":{"message":{"role":"assistant","content":[{"text":"code 42"},{"text":"and 42 again"}]}},` +
		`"stopReason":"end_turn","usage":{"inputTokens":42,"outputTokens":3,"totalTokens":45}}`)
	a := &BedrockNativeAdapter{}
	cr, err := a.DecodeResponse(original)
	require.NoError(t, err)
	cr.Content = strings.ReplaceAll(cr.Content, "code 42", "code ##")
	modified, err := a.EncodeResponse(cr)
	require.NoError(t, err)

	masked, ok := NativeMasker{}.MaskResponse(original, modified)
	require.True(t, ok)
	assert.Equal(t, strings.Replace(string(original), "code 42", "code ##", 1), string(masked))
}

// The leak check stays on: a patcher that skips the spot, or that edits another
// one, sends nothing.
func TestNativeMasker_ShortValueBrokenPatchersAreRefused(t *testing.T) {
	t.Parallel()
	original := []byte(shortMaskConverse)
	modified := pluginRewriteMessage(t, original, 0, "42", "##")

	skips := NativeMasker{Patch: func(body []byte, _ []Substitution) ([]byte, error) { return body, nil }}
	_, ok := skips.MaskRequest(original, modified)
	assert.False(t, ok, "the spot was left as it was")

	wrongSpot := NativeMasker{Patch: func(body []byte, _ []Substitution) ([]byte, error) {
		return []byte(strings.Replace(string(body), "order 42 shipped", "order ## shipped", 1)), nil
	}}
	_, ok = wrongSpot.MaskRequest(original, modified)
	assert.False(t, ok, "another spot was masked and the one the plugin found was not")

	everywhere := NativeMasker{Patch: func(body []byte, _ []Substitution) ([]byte, error) {
		return []byte(strings.ReplaceAll(string(body), "42", "##")), nil
	}}
	_, ok = everywhere.MaskRequest(original, modified)
	assert.False(t, ok, "a number, an id and another message were rewritten too")
}

func TestNativeMasker_ShortValuePatcherWithStalePlaceIsRefused(t *testing.T) {
	t.Parallel()
	_, err := patchInPlace([]byte(`{"messages":[{"role":"user","content":[{"text":"pin 42"}]}]}`),
		[]Substitution{{From: "42", To: "##", Places: []Place{{Target: 0, Off: 0}}}})
	assert.Error(t, err, "the text is not at the offset it was said to be at")
}

// A view the tags cannot be read back from is not guessed at.
func TestNativeMasker_ShortValueRefusedWhenThePlaceCannotBeProven(t *testing.T) {
	t.Parallel()
	// A short value inside a tool schema property name, which is part of the
	// view but is a key, not a string that can be patched.
	original := []byte(`{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"t","inputSchema":{"json":{"type":"object","properties":{"id42":{"type":"string"}}}}}}]}}`)
	modified := []byte(strings.Replace(string(original), "id42", "id##", 1))
	a := &BedrockNativeAdapter{}
	before, err := a.DecodeRequest(original)
	require.NoError(t, err)
	after, err := a.DecodeRequest(modified)
	require.NoError(t, err)
	_, hits, derived := deriveSubstitutions(requestText(before), requestText(after))
	require.True(t, derived, "the plugin changed the property name: there is a spot to place")
	require.NotEmpty(t, hits)

	_, ok := NativeMasker{}.MaskRequest(original, modified)
	assert.False(t, ok, "a key is not a string that can be patched, so the spot has no place")
}

// When the tagged copy of a body does not read back as the view of the real one,
// the mapping cannot be trusted and a short value is refused rather than guessed
// at. Here the same text is also a copy in a field no decoder models, which the
// view lists once, and the tags make the two copies different strings.
func TestNativeMasker_ShortValueRefusedWhenTheViewCannotBeReadBack(t *testing.T) {
	t.Parallel()
	original := []byte(`{"messages":[{"role":"user","content":[{"text":"pin 42 ok"}]}],"additionalModelRequestFields":{"note":"pin 42 ok"}}`)
	modified := pluginRewrite(t, original, "42", "##")
	_, ok := NativeMasker{}.MaskRequest(original, modified)
	assert.False(t, ok)
}

// Every way a mask can fail to apply names its cause, which the caller records
// as the failure reason of a failed-open outcome.
func TestNativeMasker_RefusalsNameTheirCause(t *testing.T) {
	t.Parallel()
	plain := []byte(`{"messages":[{"role":"user","content":[{"text":"mail ` + nativeMaskEmail + `"}]}],"guardrailConfig":{"guardrailIdentifier":"g1"}}`)
	plainModified := pluginRewrite(t, plain, nativeMaskEmail, "<EMAIL>")

	check := func(t *testing.T, m NativeMasker, original, modified []byte, want MaskCause) {
		t.Helper()
		masked, cause := m.MaskRequestWhy(original, modified)
		assert.Nil(t, masked)
		assert.Equal(t, want, cause)
	}
	t.Run("it names no cause when it masks", func(t *testing.T) {
		t.Parallel()
		masked, cause := NativeMasker{}.MaskRequestWhy(plain, plainModified)
		assert.Empty(t, cause)
		assert.NotContains(t, string(masked), nativeMaskEmail)
	})
	t.Run("the body cannot be read", func(t *testing.T) {
		t.Parallel()
		check(t, NativeMasker{}, []byte(`not json`), plainModified, MaskCauseDecode)
	})
	t.Run("text was added", func(t *testing.T) {
		t.Parallel()
		added := pluginRewrite(t, plain, "mail ", "mail and more words ")
		check(t, NativeMasker{}, plain, added, MaskCauseNotAReplacement)
	})
	t.Run("a patcher that fails", func(t *testing.T) {
		t.Parallel()
		m := NativeMasker{Patch: func([]byte, []Substitution) ([]byte, error) { return nil, assert.AnError }}
		check(t, m, plain, plainModified, MaskCausePatch)
	})
	t.Run("a signed block", func(t *testing.T) {
		t.Parallel()
		signed := []byte(`{"anthropic_version":"bedrock-2023-05-31","messages":[{"role":"assistant","content":[` +
			`{"type":"thinking","thinking":"user is ` + nativeMaskEmail + `","signature":"EqQB"}]}]}`)
		check(t, NativeMasker{}, signed, pluginRewrite(t, signed, nativeMaskEmail, "<EMAIL>"), MaskCauseSignedBlock)
	})
	t.Run("a patcher that changes what the view does not read", func(t *testing.T) {
		t.Parallel()
		m := NativeMasker{Patch: func(body []byte, subs []Substitution) ([]byte, error) {
			out, err := patchInPlace(body, subs)
			return []byte(replaceOnce(string(out), `"g1"`, `"g2"`)), err
		}}
		check(t, m, plain, plainModified, MaskCauseOutsideReadStrings)
	})
	t.Run("a patcher that leaves the text behind", func(t *testing.T) {
		t.Parallel()
		m := NativeMasker{Patch: func(body []byte, _ []Substitution) ([]byte, error) { return body, nil }}
		_, cause := m.MaskRequestWhy(plain, plainModified)
		assert.Contains(t, []MaskCause{MaskCauseShape, MaskCauseLeak}, cause)
	})
	t.Run("a short value whose place cannot be found", func(t *testing.T) {
		t.Parallel()
		original := []byte(`{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"t","inputSchema":{"json":{"type":"object","properties":{"id42":{"type":"string"}}}}}}]}}`)
		modified := []byte(replaceOnce(string(original), "id42", "id##"))
		check(t, NativeMasker{}, original, modified, MaskCausePlaceUnknown)
	})
	t.Run("a response", func(t *testing.T) {
		t.Parallel()
		original := []byte(`{"output":{"message":{"role":"assistant","content":[{"text":"hi ` + nativeMaskEmail + `"}]}}}`)
		masked, cause := NativeMasker{}.MaskResponseWhy(original, pluginRewriteResponse(t, original, nativeMaskEmail, "<EMAIL>"))
		assert.Empty(t, cause)
		assert.NotContains(t, string(masked), nativeMaskEmail)
		_, cause = NativeMasker{}.MaskResponseWhy(original, []byte(`{"output":{"message":{"role":"assistant","content":[{"text":"hi `+nativeMaskEmail+` and more words"}]}}}`))
		assert.Equal(t, MaskCauseNotAReplacement, cause)
	})
}

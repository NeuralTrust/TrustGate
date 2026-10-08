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
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The patcher finds the strings the view reads with rules of its own, because
// it needs their spans. This keeps the two from drifting apart: every body here
// must give the same strings to both.
func TestPatchTargetsAreExactlyWhatTheViewReads(t *testing.T) {
	t.Parallel()
	doc := base64.StdEncoding.EncodeToString([]byte("a text document"))
	bodies := []string{
		`{"messages":[{"role":"user","content":[{"text":"one"},{"cachePoint":{"type":"default"}}]}],"system":[{"text":"sys"}]}`,
		`{"messages":[{"role":"user","content":[{"document":{"format":"txt","name":"the name","source":{"bytes":"` + doc + `"}}},` +
			`{"image":{"format":"png","source":{"bytes":"AAAABBBB"}}}]}]}`,
		`{"anthropic_version":"v","max_tokens":1,"messages":[{"role":"user","content":[{"type":"document","source":{"type":"base64","media_type":"text/plain","data":"` + doc + `"}},` +
			`{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAABBBB"}},{"type":"document","source":{"type":"text","media_type":"text/plain","data":"inline"}}]}]}`,
		`{"messages":[{"role":"assistant","content":[{"toolUse":{"toolUseId":"abc","name":"fn","input":{"city":"Rome"}}}]}],` +
			`"toolConfig":{"tools":[{"toolSpec":{"name":"fn","description":"does a thing","inputSchema":{"json":{"type":"object","properties":{"city":{"type":"string","description":"the city"}}}}}}]}}`,
		`{"anthropic_version":"v","max_tokens":1,"tools":[{"name":"fn","description":"d1","input_schema":{"type":"object","properties":{"q":{"type":"string"}}}}],` +
			`"messages":[{"role":"user","content":[{"type":"tool_use","id":"x","name":"fn","input":{"q":"hello"}},{"type":"tool_result","tool_use_id":"x","content":"res"}]}]}`,
		`{"messages":[{"role":"user","name":"alice","content":"hi"}],"requestMetadata":{"tenant_id":"t-1","note":"a note"},"guardrailConfig":{"guardrailIdentifier":"g"}}`,
		`{"prompt":"p","extra":[["deep"]],"model":"m","role":"r","type":"t","stop_reason":"s"}`,
	}
	for i, body := range bodies {
		root, ok := parseJSON([]byte(body))
		require.True(t, ok, "body %d", i)
		var got []string
		for _, tg := range targets(root) {
			got = append(got, tg.text())
		}

		var tree any
		require.NoError(t, json.Unmarshal([]byte(body), &tree))
		var want []string
		collectStrings(tree, false, &want)
		// The view also reads the keys of a schema's properties; they are not strings
		// a mask can be written into.
		for _, k := range propertyKeys(tree) {
			for j, w := range want {
				if w == k {
					want = append(want[:j], want[j+1:]...)
					break
				}
			}
		}
		sort.Strings(got)
		sort.Strings(want)
		assert.Equal(t, want, got, "body %d", i)
	}
}

func propertyKeys(v any) []string {
	var out []string
	switch t := v.(type) {
	case []any:
		for _, item := range t {
			out = append(out, propertyKeys(item)...)
		}
	case map[string]any:
		for k, val := range t {
			if props, ok := val.(map[string]any); ok && k == "properties" {
				for pk := range props {
					out = append(out, pk)
				}
			}
			out = append(out, propertyKeys(val)...)
		}
	}
	return out
}

func TestOnlyReadStringsChanged(t *testing.T) {
	t.Parallel()
	original := []byte(`{ "messages":[{"role":"user","content":[{"text":"hello"}]}], "guardrailConfig":{"guardrailIdentifier":"g1"}, "n": 1.50 }`)
	cases := map[string]struct {
		masked string
		want   bool
	}{
		"a read string changed":    {`{ "messages":[{"role":"user","content":[{"text":"HELLO"}]}], "guardrailConfig":{"guardrailIdentifier":"g1"}, "n": 1.50 }`, true},
		"nothing changed":          {string(original), true},
		"an identifier changed":    {`{ "messages":[{"role":"user","content":[{"text":"hello"}]}], "guardrailConfig":{"guardrailIdentifier":"g2"}, "n": 1.50 }`, false},
		"a number literal changed": {`{ "messages":[{"role":"user","content":[{"text":"hello"}]}], "guardrailConfig":{"guardrailIdentifier":"g1"}, "n": 1.5 }`, false},
		"spacing changed":          {`{"messages":[{"role":"user","content":[{"text":"hello"}]}], "guardrailConfig":{"guardrailIdentifier":"g1"}, "n": 1.50 }`, false},
		"a role changed":           {`{ "messages":[{"role":"assistant","content":[{"text":"hello"}]}], "guardrailConfig":{"guardrailIdentifier":"g1"}, "n": 1.50 }`, false},
		"a key renamed":            {`{ "messagez":[{"role":"user","content":[{"text":"hello"}]}], "guardrailConfig":{"guardrailIdentifier":"g1"}, "n": 1.50 }`, false},
		"keys reordered":           {`{ "n": 1.50, "messages":[{"role":"user","content":[{"text":"hello"}]}], "guardrailConfig":{"guardrailIdentifier":"g1"} }`, false},
		"not json":                 {`{`, false},
	}
	for name, c := range cases {
		assert.Equal(t, c.want, onlyReadStringsChanged(original, []byte(c.masked)), name)
	}
}

// A patcher that rewrites something it should not is refused by the pipeline
// even when the text it was asked to mask is gone.
func TestNativeMasker_RefusesAPatcherThatChangesWhatTheViewDoesNotRead(t *testing.T) {
	t.Parallel()
	original := []byte(`{"messages":[{"role":"user","content":[{"text":"mail ` + nativeMaskEmail + `"}]}],"guardrailConfig":{"guardrailIdentifier":"g1"}}`)
	modified := pluginRewrite(t, original, nativeMaskEmail, "<EMAIL>")
	changesId := NativeMasker{Patch: func(body []byte, subs []Substitution) ([]byte, error) {
		out, err := patchInPlace(body, subs)
		if err != nil {
			return nil, err
		}
		return []byte(replaceOnce(string(out), `"g1"`, `"g2"`)), nil
	}}
	_, ok := changesId.MaskRequest(original, modified)
	assert.False(t, ok, "an identifier outside the view was changed")
}

func replaceOnce(s, old, new string) string {
	i := indexOf(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + new + s[i+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestPatchInPlace_RefusesToEditASignedBlock(t *testing.T) {
	t.Parallel()
	body := []byte(`{"content":[{"type":"thinking","thinking":"user is john@x.com","signature":"EqQB"}]}`)
	_, err := patchInPlace(body, []Substitution{{From: "john@x.com", To: "<EMAIL>"}})
	assert.ErrorIs(t, err, errSignedBlock)

	// A substitution that does not touch it is fine.
	out, err := patchInPlace(body, []Substitution{{From: "nobody@x.com", To: "<EMAIL>"}})
	require.NoError(t, err)
	assert.Equal(t, string(body), string(out))
}

func TestTreeLeaks_SeesNumbersKeysAndSignedText(t *testing.T) {
	t.Parallel()
	subs := []Substitution{{From: "4111111111111111", To: "[CARD]"}}
	assert.True(t, treeLeaks([]byte(`{"input":{"card":4111111111111111}}`), subs), "the same value as a JSON number")
	assert.True(t, treeLeaks([]byte(`{"4111111111111111":1}`), subs), "as a key")
	assert.True(t, treeLeaks([]byte(`{"content":[{"thinking":"card 4111111111111111","signature":"s"}]}`), subs), "inside a signed block")
	assert.False(t, treeLeaks([]byte(`{"toolUseId":"x4111111111111111y","text":"clean"}`), subs), "an identifier the view does not read is not a leak")
}

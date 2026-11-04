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

package events

import (
	"encoding/json"
	"strings"
	"testing"
)

var jsonHeaders = map[string][]string{"Content-Type": {"application/json"}}

// A string value that holds JSON is parsed, so its credential keys are
// redacted instead of treated as one opaque leaf.
func TestSanitizeBodyRedactsCredentialInsideJSONString(t *testing.T) {
	body := []byte(`{"payload":{"input":"{\"password\":\"FAKE-NESTED\"}","api_key":"FAKE-TOP"}}`)
	got := SanitizeBody(body, jsonHeaders)

	for _, secret := range []string{"FAKE-NESTED", "FAKE-TOP"} {
		if strings.Contains(got, secret) {
			t.Fatalf("%s leaked: %s", secret, got)
		}
	}
	var parsed struct {
		Payload struct {
			Input string `json:"input"`
		} `json:"payload"`
	}
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("sanitized body is not JSON: %v: %s", err, got)
	}
	if parsed.Payload.Input != `{"password":"[REDACTED]"}` {
		t.Fatalf("input = %q, want the JSON kept with the password redacted", parsed.Payload.Input)
	}
}

// A tool call carries its arguments as a JSON string, and the body has no
// credential key outside it, which used to skip redaction altogether.
func TestSanitizeBodyRedactsCredentialInToolCallArguments(t *testing.T) {
	body := []byte(`{"messages":[{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"login","arguments":"{\"user\":\"alice\",\"password\":\"FAKE-ARGS\"}"}}]}]}`)
	got := SanitizeBody(body, jsonHeaders)

	if strings.Contains(got, "FAKE-ARGS") {
		t.Fatalf("tool-call password leaked: %s", got)
	}
	for _, kept := range []string{"login", "alice"} {
		if !strings.Contains(got, kept) {
			t.Fatalf("%q should be kept as evidence: %s", kept, got)
		}
	}
}

// Two levels: a string-encoded envelope whose tool call holds string-encoded
// arguments.
func TestSanitizeBodyRedactsCredentialTwoStringLevelsDown(t *testing.T) {
	args, _ := json.Marshal(map[string]any{"client_secret": "FAKE-L2"})
	envelope, _ := json.Marshal(map[string]any{"function": map[string]any{"arguments": string(args)}})
	body, _ := json.Marshal(map[string]any{"input": string(envelope)})

	got := SanitizeBody(body, jsonHeaders)
	if strings.Contains(got, "FAKE-L2") {
		t.Fatalf("credential two string levels down leaked: %s", got)
	}
}

// A tool result marshalled twice is a string whose JSON text is itself a
// quoted string.
func TestSanitizeBodyRedactsCredentialInDoubleEncodedString(t *testing.T) {
	once, _ := json.Marshal(map[string]any{"password": "FAKE-TWICE", "status": "ok"})
	twice, _ := json.Marshal(string(once))
	body, _ := json.Marshal(map[string]any{"output": string(twice)})

	got := SanitizeBody(body, jsonHeaders)
	if strings.Contains(got, "FAKE-TWICE") {
		t.Fatalf("double-encoded credential leaked: %s", got)
	}
	if !strings.Contains(got, "ok") {
		t.Fatalf("safe content removed: %s", got)
	}
}

// A body without credentials comes back byte for byte, including JSON strings
// with their own spacing and strings that only look like JSON.
func TestSanitizeBodyKeepsJSONStringsWithoutCredentials(t *testing.T) {
	cases := []string{
		`{"input":"\"quoted\""}`,
		`{"input":"\"quoted\" and then prose"}`,
		`{"input":"{\"city\": \"Paris\",  \"days\": 3}"}`,
		`{"input":"[1, 2,  3]"}`,
		`{"input":"{not json, password: FAKE-PROSE}"}`,
		`{"input":"[citation needed]"}`,
		`{"input":"plain text with a password word in it"}`,
	}
	for _, body := range cases {
		if got := SanitizeBody([]byte(body), jsonHeaders); got != body {
			t.Errorf("body altered:\n got  %s\n want %s", got, body)
		}
	}
}

// nestJSONString string-encodes v n times, writing every backslash and quote
// as a \u escape so each level costs only a few bytes more than the last.
func nestJSONString(v string, n int) string {
	const backslash = `\`
	for range n {
		v = strings.ReplaceAll(v, backslash, backslash+"u005c")
		v = strings.ReplaceAll(v, `"`, backslash+"u0022")
		v = `["` + v + `"]`
	}
	return v
}

// Parsing stops at maxJSONStringNesting; past it a JSON-looking string is
// redacted whole, so deep nesting can neither hide a credential nor make the
// export path re-parse the body hundreds of times.
func TestSanitizeBodyRedactsPastJSONStringNestingCap(t *testing.T) {
	for _, levels := range []int{maxJSONStringNesting, maxJSONStringNesting + 1, 300} {
		inner := nestJSONString(`{"password":"FAKE-DEEP"}`, levels-1)
		body, _ := json.Marshal(map[string]any{"input": inner})

		var check any
		if err := json.Unmarshal(body, &check); err != nil {
			t.Fatalf("levels=%d: fixture is not JSON: %v", levels, err)
		}
		got := SanitizeBody(body, jsonHeaders)
		if strings.Contains(got, "FAKE-DEEP") {
			t.Fatalf("levels=%d: credential leaked: %.200s", levels, got)
		}
	}
}

func TestSanitizeExtrasRedactsCredentialInsideJSONString(t *testing.T) {
	got := SanitizeExtras(map[string]any{"arguments": `{"token":"FAKE-EXTRA","q":"weather"}`})

	out, _ := json.Marshal(got)
	if strings.Contains(string(out), "FAKE-EXTRA") {
		t.Fatalf("credential leaked from extras: %s", out)
	}
	if !strings.Contains(string(out), "weather") {
		t.Fatalf("safe content removed from extras: %s", out)
	}
}

// A prompt that pastes a config is a JSON string inside the message content,
// and the body has no credential key outside it.
func TestSanitizeBodyRedactsCredentialInPromptContent(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"{\"api_key\":\"sk-test-FAKE-PROMPT\",\"note\":\"QAM-1\"}"}]}`)
	got := SanitizeBody(body, jsonHeaders)

	if strings.Contains(got, "FAKE-PROMPT") {
		t.Fatalf("prompt api_key leaked: %s", got)
	}
	if !strings.Contains(got, `{\"api_key\":\"[REDACTED]\",\"note\":\"QAM-1\"}`) {
		t.Fatalf("prompt should keep its JSON with the key redacted: %s", got)
	}
}

func TestRedactCredentialsInText(t *testing.T) {
	cases := map[string]string{
		`{"api_key":"sk-FAKE","note":"n"}`:             `{"api_key":"[REDACTED]","note":"n"}`,
		"see config\n{\"api_key\":\"sk-FAKE\"} thanks": "see config\n{\"api_key\":\"[REDACTED]\"} thanks",
		`{"city":"Paris"} and [1, 2]`:                  `{"city":"Paris"} and [1, 2]`,
		`[citation needed] {not json, token: FAKE}`:    `[citation needed] {not json, token: FAKE}`,
		`api_key: sk-FAKE`:                             `api_key: sk-FAKE`,
		`hello there`:                                  `hello there`,
	}
	for in, want := range cases {
		if got := RedactCredentialsInText(in, 200); got != want {
			t.Errorf("RedactCredentialsInText(%q) = %q, want %q", in, got, want)
		}
	}
}

// Past keep runes the text is not read further, so a long prompt costs only
// what the preview shows.
func TestRedactCredentialsInTextStopsAfterKeep(t *testing.T) {
	text := strings.Repeat("a", 50) + ` {"token":"FAKE-LATE"}`
	got := RedactCredentialsInText(text, 10)
	if len(got) != 11 || strings.Contains(got, "FAKE-LATE") {
		t.Fatalf("got %q, want the first 11 runes only", got)
	}
}

// Prose full of brackets costs a bounded scan and still has its JSON redacted.
func TestRedactCredentialsInTextAfterManyBrackets(t *testing.T) {
	text := strings.Repeat("[link] ", 100) + `{"token":"FAKE-AFTER"}`
	got := RedactCredentialsInText(text, len(text))
	if strings.Contains(got, "FAKE-AFTER") {
		t.Fatalf("token after the brackets leaked: %.200s", got)
	}
}

// Once the scan budget is spent the rest of the text is read as prose.
func TestRedactCredentialsInTextStopsParsingPastBudget(t *testing.T) {
	unclosed := `{"a":"` + strings.Repeat("x", maxEmbeddedJSONScanBytes)
	text := unclosed + ` {"city":"Paris"}`
	got := RedactCredentialsInText(text, len(text))
	if got != text {
		t.Fatal("text past the scan budget should come back as is")
	}
}

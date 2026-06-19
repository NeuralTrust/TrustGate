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

package proxy

import (
	"encoding/json"
	"testing"
)

func decodeStreamOptions(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	opts, ok := m["stream_options"].(map[string]any)
	if !ok {
		t.Fatalf("stream_options missing or not an object: %v", m["stream_options"])
	}
	return opts
}

func TestInjectStreamIncludeUsage_AddsWhenAbsent(t *testing.T) {
	body := []byte(`{"model":"gpt-4o-mini","stream":true}`)
	out := injectStreamIncludeUsage(body)
	opts := decodeStreamOptions(t, out)
	if opts["include_usage"] != true {
		t.Fatalf("include_usage should be true, got %v", opts["include_usage"])
	}
}

func TestInjectStreamIncludeUsage_PreservesExistingOptions(t *testing.T) {
	body := []byte(`{"model":"gpt-4o-mini","stream":true,"stream_options":{"some_flag":"x"}}`)
	out := injectStreamIncludeUsage(body)
	opts := decodeStreamOptions(t, out)
	if opts["include_usage"] != true {
		t.Fatalf("include_usage should be true, got %v", opts["include_usage"])
	}
	if opts["some_flag"] != "x" {
		t.Fatalf("existing stream_options keys must be preserved, got %v", opts["some_flag"])
	}
}

func TestInjectStreamIncludeUsage_OverridesFalse(t *testing.T) {
	body := []byte(`{"model":"gpt-4o-mini","stream":true,"stream_options":{"include_usage":false}}`)
	out := injectStreamIncludeUsage(body)
	opts := decodeStreamOptions(t, out)
	if opts["include_usage"] != true {
		t.Fatalf("include_usage should be forced to true, got %v", opts["include_usage"])
	}
}

func TestInjectStreamIncludeUsage_InvalidJSONUnchanged(t *testing.T) {
	body := []byte(`{not json`)
	out := injectStreamIncludeUsage(body)
	if string(out) != string(body) {
		t.Fatalf("invalid JSON body must be returned unchanged, got %s", out)
	}
}

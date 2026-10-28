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
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// htmlHeavy is text where every byte of markup would grow from 1 to 6 bytes
// under encoding/json's default HTML escaping.
func htmlHeavy() string {
	return strings.Repeat("<script>&</script>", 2000)
}

// esc spells the JSON \\u00XX escape without writing it literally.
func esc(hex string) string { return "\\" + "u00" + hex }

func captureEvaluateBody(t *testing.T, req GuardRequest) []byte {
	t.Helper()
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"allow"}`))
	}))
	t.Cleanup(srv.Close)
	c := newTestClient(t, 5*time.Second)
	if _, err := c.Guard(context.Background(), srv.URL, "tok", "", req, false); err != nil {
		t.Fatalf("Guard: %v", err)
	}
	return got
}

func TestGuardBodyIsNotHTMLEscaped(t *testing.T) {
	text := htmlHeavy()
	creq := &adapter.CanonicalRequest{Messages: []adapter.CanonicalMessage{{Role: "user", Content: text}}}
	payload, err := llmRequestPayload(creq)
	if err != nil {
		t.Fatal(err)
	}
	req := sampleRequest()
	req.Payload = payload

	got := captureEvaluateBody(t, req)

	for _, e := range []string{esc("3c"), esc("3e"), esc("26")} {
		if bytes.Contains(got, []byte(e)) {
			t.Fatalf("body contains %s escape", e)
		}
	}
	if !bytes.Contains(got, []byte(`<script>&</script>`)) {
		t.Fatal("literal markup missing from body")
	}
	// Escaped, the markup alone would take 6 bytes per <, > and &.
	if limit := len(text) + 2048; len(got) > limit {
		t.Fatalf("body inflated: %d bytes for %d bytes of text", len(got), len(text))
	}

	// Round trip: the receiving side decodes the identical content.
	var env struct {
		Payload struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(got, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(env.Payload.Messages) != 1 || env.Payload.Messages[0].Content != text {
		t.Fatal("content changed in the round trip")
	}
	if bytes.HasSuffix(got, []byte("\n")) {
		t.Fatal("body carries the trailing newline Encode adds")
	}
}

func TestResponseAndInputPayloadsAreNotHTMLEscaped(t *testing.T) {
	text := htmlHeavy()
	resp, err := llmResponsePayload(&adapter.CanonicalResponse{Content: text}, nil)
	if err != nil {
		t.Fatal(err)
	}
	in, err := llmPayload(text)
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]json.RawMessage{"response": resp, "input": in} {
		if bytes.Contains(p, []byte(esc("3c"))) || bytes.Contains(p, []byte(esc("26"))) {
			t.Errorf("%s payload is HTML escaped", name)
		}
		if bytes.HasSuffix(p, []byte("\n")) {
			t.Errorf("%s payload has a trailing newline", name)
		}
	}
}

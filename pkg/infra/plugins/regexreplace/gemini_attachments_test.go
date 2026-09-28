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

package regexreplace

import (
	"context"
	"net/http"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const (
	googleProvider = "google"
	pngPixel1x1    = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)

func geminiRequestWithAttachments(text string) []byte {
	return []byte(`{"contents":[{"role":"user","parts":[` +
		`{"text":"` + text + `"},` +
		`{"inlineData":{"mimeType":"image/png","data":"` + pngPixel1x1 + `"}},` +
		`{"fileData":{"mimeType":"image/jpeg","fileUri":"gs://attachments-bucket/cat.jpg"}}` +
		`]}]}`)
}

// TestGeminiRequestRewritePreservesAttachments is the RUN-1678 regression
// test: regex_replace deliberately re-encodes the FULL request through the
// canonical model once it rewrites any text (see rewriteRequest / commit
// 53f0d1e2), so it must not use this as an excuse to drop the Gemini
// inlineData/fileData parts sitting next to that text.
func TestGeminiRequestRewritePreservesAttachments(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	set := settings(targetRequest, maskRule("secret", "[REDACTED]"))
	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, set,
		reqCtx(googleProvider, googleProvider, geminiRequestWithAttachments("my secret code")), nil, event)

	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK || res.StopUpstream || len(res.RequestBody) == 0 || res.Body != nil {
		t.Fatalf("expected request rewrite result, got %+v", res)
	}

	creq, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, adapter.FormatGemini)
	if err != nil {
		t.Fatalf("decode rewritten request: %v", err)
	}
	if len(creq.Messages) == 0 {
		t.Fatalf("expected at least one message, got none")
	}
	msg := creq.Messages[len(creq.Messages)-1]
	if msg.Content != "my [REDACTED] code" {
		t.Fatalf("user content = %q, want %q", msg.Content, "my [REDACTED] code")
	}
	if len(msg.Images) != 2 {
		t.Fatalf("expected the inlineData and fileData images to survive the redaction re-encode, got %d images", len(msg.Images))
	}
	if msg.Images[0].Data != pngPixel1x1 {
		t.Fatalf("inline image data = %q, want unchanged %q", msg.Images[0].Data, pngPixel1x1)
	}
	if msg.Images[1].URL != "gs://attachments-bucket/cat.jpg" {
		t.Fatalf("file image URL = %q, want unchanged", msg.Images[1].URL)
	}
	if d := extras(t, span); d.Decision != decisionRewritten || !d.Changed {
		t.Fatalf("extras = %+v, want rewritten+changed", d)
	}
}

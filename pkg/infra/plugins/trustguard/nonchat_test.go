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
	"mime/multipart"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func nonChatRequest(capability, format string, body []byte, contentType string) *infracontext.RequestContext {
	req := requestContext()
	req.ProxyCapability = capability
	req.SourceFormat = format
	req.Body = body
	if contentType != "" {
		req.Headers = map[string][]string{"Content-Type": {contentType}}
	}
	return req
}

func closedSettings() map[string]any {
	s := settings("")
	s["failure_mode"] = pluginutil.FailureModeClosed
	return s
}

// sentTexts reads the text blocks of the one message an evaluate carried.
func sentTexts(t *testing.T, sent GuardRequest) []string {
	t.Helper()
	var payload struct {
		Messages []struct {
			Role    string `json:"role"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(sent.Payload, &payload))
	require.Len(t, payload.Messages, 1)
	texts := make([]string, 0, len(payload.Messages[0].Content))
	for _, c := range payload.Messages[0].Content {
		texts = append(texts, c.Text)
	}
	return texts
}

func TestNonChatRequestsSendTheirText(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, capability, format, body string
		want                           []string
	}{
		{"image prompt", "images", "openai_images", `{"model":"dall-e-3","prompt":"a cat named Jane Doe"}`, []string{"a cat named Jane Doe"}},
		{"speech", "audio_speech", "openai_audio", `{"model":"tts-1","input":"Call 555-0100","instructions":"calm","voice":"alloy"}`, []string{"Call 555-0100", "calm"}},
		{"embeddings string", "embeddings", "openai_embeddings", `{"model":"m","input":"jane@acme.io"}`, []string{"jane@acme.io"}},
		{"embeddings list", "embeddings", "openai_embeddings", `{"model":"m","input":["a","b"]}`, []string{"a", "b"}},
		{"embeddings mixed tokens", "embeddings", "openai_embeddings", `{"model":"m","input":[1,"a"]}`, []string{"a"}},
		{"cohere embed", "embeddings", "cohere_embed", `{"model":"embed","texts":["one","two"],"input_type":"search_query"}`, []string{"one", "two"}},
		{"gemini embed", "embeddings", "gemini_embed", `{"content":{"parts":[{"text":"hola"}]}}`, []string{"hola"}},
		{"rerank", "rerank", "cohere_rerank", `{"query":"who","documents":["d1",{"text":"d2"}]}`, []string{"who", "d1", "d2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
			srv := newServer(t, f)
			p := newTestPlugin(t, adapter.NewRegistry(), srv.URL)
			req := nonChatRequest(tc.capability, tc.format, []byte(tc.body), "application/json")

			res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil))
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Equal(t, 1, f.count(), "the text is sent to TrustGuard")
			assert.Equal(t, tc.want, sentTexts(t, f.captured()))
		})
	}
}

func TestNonChatRequestBlocked(t *testing.T) {
	t.Parallel()
	f := &fakeGuard{response: GuardResponse{Status: statusBlock}}
	srv := newServer(t, f)
	p := newTestPlugin(t, adapter.NewRegistry(), srv.URL)
	req := nonChatRequest("images", "openai_images", []byte(`{"prompt":"bad"}`), "application/json")
	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil))
	var pe *appplugins.PluginError
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
}

func TestNonChatRequestMaskedInPlace(t *testing.T) {
	t.Parallel()
	f := &fakeGuard{response: GuardResponse{Status: statusTransform, TransformedPayload: map[string]any{
		"messages": []any{map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "text", "text": "[EMAIL]"},
			map[string]any{"type": "text", "text": "plain"},
		}}},
	}}}
	srv := newServer(t, f)
	p := newTestPlugin(t, adapter.NewRegistry(), srv.URL)
	req := nonChatRequest("embeddings", "openai_embeddings", []byte(`{"model":"m","input":["jane@acme.io","plain"],"dimensions":256}`), "application/json")

	res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.JSONEq(t, `{"model":"m","input":["[EMAIL]","plain"],"dimensions":256}`, string(res.RequestBody))
}

func multipartForm(t *testing.T, fields map[string]string, file string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		require.NoError(t, w.WriteField(k, v))
	}
	if file != "" {
		part, err := w.CreateFormFile("file", file)
		require.NoError(t, err)
		_, err = part.Write([]byte("binary"))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return buf.Bytes(), w.FormDataContentType()
}

func TestNonChatUploadsUnderFailureModes(t *testing.T) {
	t.Parallel()
	upload, uploadCT := multipartForm(t, map[string]string{"purpose": "batch"}, "data.jsonl")
	audio, audioCT := multipartForm(t, map[string]string{"model": "whisper-1"}, "speech.mp3")
	edit, editCT := multipartForm(t, map[string]string{"prompt": "make it blue"}, "img.png")
	cases := []struct {
		name, capability, format, ct string
		body                         []byte
		closedBlocks                 bool
		inspected                    bool
	}{
		{"file upload", "files", "openai_files", uploadCT, upload, true, false},
		// The audio is not refused: what it says is inspected as the transcript.
		{"transcription audio", "audio_transcription", "openai_audio", audioCT, audio, false, false},
		{"image edit", "images", "openai_images", editCT, edit, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, closed := range []bool{false, true} {
				f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
				srv := newServer(t, f)
				p := newTestPlugin(t, adapter.NewRegistry(), srv.URL)
				set := settings("")
				if closed {
					set = closedSettings()
				}
				req := nonChatRequest(tc.capability, tc.format, tc.body, tc.ct)
				_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, set, req, nil))
				if closed && tc.closedBlocks {
					var pe *appplugins.PluginError
					require.ErrorAs(t, err, &pe, "closed refuses content it cannot read")
					assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
					assert.Zero(t, f.count(), "refused before any call")
					continue
				}
				require.NoError(t, err, "closed=%v", closed)
				if tc.inspected {
					assert.Equal(t, 1, f.count())
					assert.Equal(t, []string{"make it blue"}, sentTexts(t, f.captured()))
				} else {
					assert.Zero(t, f.count())
				}
			}
		})
	}
}

func TestNonChatMultipartMaskIsRefused(t *testing.T) {
	t.Parallel()
	f := &fakeGuard{response: GuardResponse{Status: statusTransform, TransformedPayload: map[string]any{
		"messages": []any{map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": "[X]"}}}},
	}}}
	srv := newServer(t, f)
	p := newTestPlugin(t, adapter.NewRegistry(), srv.URL)
	body, ct := multipartForm(t, map[string]string{"prompt": "Jane Doe"}, "")
	req := nonChatRequest("images", "openai_images", body, ct)
	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil))
	require.Error(t, err, "a mask with nowhere to be written is not forwarded unmasked")
}

func TestTranscriptIsInspectedAndMasked(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, body, want string
		texts            []string
	}{
		{"json", `{"text":"I am Jane"}`, `{"text":"I am [NAME]"}`, []string{"I am Jane"}},
		{"plain", "I am Jane", "I am [NAME]", []string{"I am Jane"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{response: GuardResponse{Status: statusTransform, TransformedPayload: map[string]any{
				"messages": []any{map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "text", "text": "I am [NAME]"}}}},
			}}}
			srv := newServer(t, f)
			p := newTestPlugin(t, adapter.NewRegistry(), srv.URL)
			req := nonChatRequest("audio_transcription", "openai_audio", nil, "")
			resp := &infracontext.ResponseContext{StatusCode: http.StatusOK, Body: []byte(tc.body)}
			res, err := p.Execute(context.Background(), execInput(policy.StagePreResponse, policy.ModeEnforce, settings(""), req, resp))
			require.NoError(t, err)
			assert.Equal(t, tc.texts, sentTexts(t, f.captured()))
			require.NotNil(t, res)
			if tc.name == "json" {
				assert.JSONEq(t, tc.want, string(res.Body))
			} else {
				assert.Equal(t, tc.want, string(res.Body))
			}
		})
	}
}

func TestAttachmentByReferenceUnderClosed(t *testing.T) {
	t.Parallel()
	const body = `{"model":"gpt-4o","messages":[{"role":"user","content":[` +
		`{"type":"text","text":"summarize this"},` +
		`{"type":"file","file":{"file_id":"file-abc123"}}]}]}`
	for _, closed := range []bool{false, true} {
		f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
		srv := newServer(t, f)
		p := newTestPlugin(t, adapter.NewRegistry(), srv.URL)
		req := requestContext()
		req.Body = []byte(body)
		set := settings("")
		if closed {
			set = closedSettings()
		}
		_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, set, req, nil))
		if !closed {
			require.NoError(t, err)
			assert.Equal(t, 1, f.count(), "open inspects the text and counts the file as not inspected")
			continue
		}
		var pe *appplugins.PluginError
		require.ErrorAs(t, err, &pe)
		assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
		assert.Zero(t, f.count())
	}
}

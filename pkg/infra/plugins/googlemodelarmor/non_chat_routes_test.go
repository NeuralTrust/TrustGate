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

package googlemodelarmor

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

func multipartBody(t *testing.T, fields map[string]string, fileField, fileName string, file []byte) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		require.NoError(t, w.WriteField(k, v))
	}
	part, err := w.CreateFormFile(fileField, fileName)
	require.NoError(t, err)
	_, err = part.Write(file)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes(), w.FormDataContentType()
}

// The routes a policy covers include the ones that carry no chat messages:
// image generation, audio and files. Their bodies are not chat JSON, so the
// adapters either have no decoder for them or cannot parse them as one; that is
// the route's shape, not anything the client got wrong, so it must not refuse
// the call.
func TestNonChatRoutesAreNotRefusedInEnforce(t *testing.T) {
	t.Parallel()
	transcription, _ := multipartBody(t, map[string]string{"model": "whisper-1"}, "file", "speech.mp3", []byte("ID3\x03\x00\x00\x00\x00\x00\x21"))
	upload, _ := multipartBody(t, map[string]string{"purpose": "fine-tune"}, "file", "train.jsonl", []byte(`{"prompt":"a","completion":"b"}`))
	cases := []struct {
		name       string
		capability string
		format     string
		body       []byte
	}{
		{"image generation", "images", "openai_images", []byte(`{"model":"dall-e-3","prompt":"a white siamese cat","n":1,"size":"1024x1024"}`)},
		{"speech", "audio_speech", "openai_audio", []byte(`{"model":"tts-1","input":"The quick brown fox jumped over the lazy dog.","voice":"alloy"}`)},
		{"transcription upload", "audio_transcription", "openai_audio", transcription},
		{"file upload", "files", "openai_files", upload},
	}
	for _, tc := range cases {
		for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
			t.Run(tc.name+" "+string(mode), func(t *testing.T) {
				t.Parallel()
				stub := newModelArmorStub(t, http.StatusOK, allowResponse)
				p := pluginWithStub(stub)
				req := reqCtx(tc.body)
				req.SourceFormat = tc.format
				req.ProxyCapability = tc.capability
				event, span := newStreamEvent()
				in := execInput(policy.StagePreRequest, mode, modelArmorSettings(), req, nil)
				in.Event = event

				res, err := p.Execute(context.Background(), in)
				assertPassThrough(t, res, err)
				assert.Zero(t, stub.count())
				data, ok := span.PluginAttrsCopy().Extras.(*Data)
				require.True(t, ok)
				assert.Equal(t, "failed_open", data.Decision)
				assert.Equal(t, "availability", data.FailureClass)
			})
		}
	}
}

func TestMalformedChatBodyStillBlocksOnAChatRoute(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, allowResponse)
	p := pluginWithStub(stub)
	req := reqCtx([]byte(`{"model":"gpt-4o","messages":123}`))
	req.ProxyCapability = "chat"
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), req, nil)

	_, err := p.Execute(context.Background(), in)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
	assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
}

// pre_response also runs on what the upstream answered when it did not produce
// a completion: an error page from a proxy in front of it, a provider error
// envelope, or audio bytes. None of those is content the client steered into
// the guardrail, so none refuses the call.
func TestUninspectableResponsesAreNotRefusedInEnforce(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		status int
		format string
		body   []byte
	}{
		{"html 503", http.StatusServiceUnavailable, "openai", []byte("<html><body><h1>503 Service Unavailable</h1></body></html>")},
		{"plain text envoy error", http.StatusServiceUnavailable, "openai", []byte("upstream connect error or disconnect/reset before headers. reset reason: connection failure")},
		{"cohere 429", http.StatusTooManyRequests, "cohere", []byte(`{"message":"You are using a Trial key, which is limited to 40 API calls / minute."}`)},
		{"speech mp3 on the audio format", http.StatusOK, "openai_audio", []byte("ID3\x03\x00\x00\x00\x00\x00\x21\xff\xfb\x90\x64")},
		{"speech mp3 on a chat format", http.StatusOK, "openai", []byte("ID3\x03\x00\x00\x00\x00\x00\x21\xff\xfb\x90\x64")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stub := newModelArmorStub(t, http.StatusOK, allowResponse)
			p := pluginWithStub(stub)
			req := reqCtx(openAIRequest())
			req.SourceFormat = tc.format
			event, _ := newStreamEvent()
			in := execInput(policy.StagePreResponse, policy.ModeEnforce, modelArmorSettings(), req,
				&infracontext.ResponseContext{StatusCode: tc.status, Body: tc.body})
			in.Event = event

			res, err := p.Execute(context.Background(), in)
			assertPassThrough(t, res, err)
			assert.Zero(t, stub.count())
		})
	}
}

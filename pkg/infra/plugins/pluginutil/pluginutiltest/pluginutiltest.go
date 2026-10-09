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

// Package pluginutiltest holds the fixtures the external guardrails share to
// prove they treat a route that carries no chat the same way: the bodies of the
// routes, the responses that are not completions, and a reader of the skip a
// plugin records.
package pluginutiltest

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

// MalformedChatBody is a body that claims to be a chat request and is not one:
// messages is a number.
var MalformedChatBody = []byte(`{"model":"gpt-4o","messages":123}`)

// MultipartBody builds a multipart/form-data upload body, the shape of the
// audio transcription and file upload routes.
func MultipartBody(t *testing.T, fields map[string]string, fileField, fileName string, file []byte) []byte {
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
	return buf.Bytes()
}

// NonChatRoute is a request to a route that carries no chat messages, with the
// proxy capability and source format the gateway gives it.
type NonChatRoute struct {
	Name       string
	Capability string
	Format     string
	Body       []byte
}

// NonChatRoutes are the image, audio and file routes a policy can cover. The
// bodies follow the OpenAI API reference for each route.
func NonChatRoutes(t *testing.T) []NonChatRoute {
	t.Helper()
	transcription := MultipartBody(t, map[string]string{"model": "whisper-1"}, "file", "speech.mp3", []byte("ID3\x03\x00\x00\x00\x00\x00\x21"))
	upload := MultipartBody(t, map[string]string{"purpose": "fine-tune"}, "file", "train.jsonl", []byte(`{"prompt":"a","completion":"b"}`))
	return []NonChatRoute{
		{"image generation", "images", "openai_images", []byte(`{"model":"dall-e-3","prompt":"a white siamese cat","n":1,"size":"1024x1024"}`)},
		{"speech", "audio_speech", "openai_audio", []byte(`{"model":"tts-1","input":"The quick brown fox jumped over the lazy dog.","voice":"alloy"}`)},
		{"transcription upload", "audio_transcription", "openai_audio", transcription},
		{"file upload", "files", "openai_files", upload},
	}
}

// UninspectableResponse is what pre_response can receive that is not a
// completion, with the skip a guardrail records for it.
type UninspectableResponse struct {
	Name       string
	Status     int
	Format     string
	Body       []byte
	SkipReason string
}

// UninspectableResponses are an error page from a proxy in front of the
// upstream, a provider error envelope and audio bytes.
func UninspectableResponses() []UninspectableResponse {
	mp3 := []byte("ID3\x03\x00\x00\x00\x00\x00\x21\xff\xfb\x90\x64")
	return []UninspectableResponse{
		{"html 503", http.StatusServiceUnavailable, "openai", []byte("<html><body><h1>503 Service Unavailable</h1></body></html>"), pluginutil.SkipReasonNoInspectableOutput},
		{"plain text envoy error", http.StatusServiceUnavailable, "openai", []byte("upstream connect error or disconnect/reset before headers. reset reason: connection failure"), pluginutil.SkipReasonNoInspectableOutput},
		{"cohere 429", http.StatusTooManyRequests, "cohere", []byte(`{"message":"You are using a Trial key, which is limited to 40 API calls / minute."}`), pluginutil.SkipReasonNoInspectableOutput},
		{"speech mp3 on the audio format", http.StatusOK, "openai_audio", mp3, pluginutil.SkipReasonUndecodableResponse},
		{"speech mp3 on a chat format", http.StatusOK, "openai", mp3, pluginutil.SkipReasonUndecodableResponse},
	}
}

// SkipOf reads, from the extras a plugin recorded on its span, whether the leg
// was marked skipped and why. It reads the JSON the console receives, so it
// holds for whatever type the plugin recorded.
func SkipOf(t *testing.T, extras any) (skipped bool, reason string) {
	t.Helper()
	raw, err := json.Marshal(extras)
	require.NoError(t, err)
	var wire struct {
		Skipped    bool   `json:"skipped"`
		SkipReason string `json:"skip_reason"`
	}
	require.NoError(t, json.Unmarshal(raw, &wire))
	return wire.Skipped, wire.SkipReason
}

// FailureOf reads, from the extras a plugin recorded on its span, the failure
// reason and detail the console receives.
func FailureOf(t *testing.T, extras any) (reason, detail string) {
	t.Helper()
	raw, err := json.Marshal(extras)
	require.NoError(t, err)
	var wire struct {
		Reason string `json:"failure_reason"`
		Detail string `json:"failure_detail"`
	}
	require.NoError(t, json.Unmarshal(raw, &wire))
	return wire.Reason, wire.Detail
}

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

package providers_test

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime/multipart"
	"net/url"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsAudioPath(t *testing.T) {
	t.Parallel()
	assert.True(t, providers.IsAudioPath("/v1/audio/speech"))
	assert.True(t, providers.IsAudioPath("/v1/audio/transcriptions"))
	assert.True(t, providers.IsAudioSpeechPath("/v1/audio/speech"))
	assert.True(t, providers.IsAudioTranscriptionPath("/v1/audio/transcriptions"))
	assert.False(t, providers.IsAudioPath("/v1/audio/translations"))
	assert.False(t, providers.IsAudioPath("/v1/audio/speech/extra"))
	assert.False(t, providers.IsAudioPath("/v1/audio"))
	assert.False(t, providers.IsAudioPath("/v1/embeddings"))
}

func TestValidateAudioMethod(t *testing.T) {
	t.Parallel()
	require.NoError(t, providers.ValidateAudioMethod("POST", "/v1/audio/speech"))
	require.NoError(t, providers.ValidateAudioMethod("POST", "/v1/audio/transcriptions"))
	require.Error(t, providers.ValidateAudioMethod("GET", "/v1/audio/speech"))
	require.Error(t, providers.ValidateAudioMethod("GET", "/v1/audio/transcriptions"))
	require.Error(t, providers.ValidateAudioMethod("POST", "/v1/audio/translations"))
}

func TestJoinOpenAIAudioURL(t *testing.T) {
	t.Parallel()
	assert.Equal(t,
		"https://api.openai.com/v1/audio/speech",
		providers.JoinOpenAIAudioURL("https://api.openai.com/v1/", "/v1/audio/speech", nil),
	)
	assert.Equal(t,
		"https://api.groq.com/openai/v1/audio/transcriptions",
		providers.JoinOpenAIAudioURL("https://api.groq.com/openai/v1", "/v1/audio/transcriptions", nil),
	)
	q := url.Values{"user": []string{"alice"}}
	assert.Equal(t,
		"https://host/v1/audio/speech?user=alice",
		providers.JoinOpenAIAudioURL("https://host/v1", "/v1/audio/speech", q),
	)
}

func TestAzureAudioOperation(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "audio/speech", providers.AzureAudioOperation("/v1/audio/speech"))
	assert.Equal(t, "audio/transcriptions", providers.AzureAudioOperation("/v1/audio/transcriptions"))
	assert.Equal(t, "audio/speech", providers.AzureAudioOperation("/v1/audio"))
}

func TestExtractAudioModel(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "tts-1", providers.ExtractAudioModel("application/json", []byte(`{"model":"tts-1","input":"hi"}`)))
	assert.Equal(t, "", providers.ExtractAudioModel("application/json", []byte(`{"input":"hi"}`)))
	assert.Equal(t, "", providers.ExtractAudioModel("application/json", []byte(`not-json`)))

	ct, body := multipartAudioFixture(t, map[string]string{"model": "whisper-1", "language": "en"}, "hi.wav", "RIFF")
	assert.True(t, providers.IsAudioMultipart(ct))
	assert.Equal(t, "whisper-1", providers.ExtractAudioModel(ct, body))
	assert.False(t, providers.IsAudioMultipart("application/json"))
}

func TestMapSpeechVoiceToVoiceID(t *testing.T) {
	t.Parallel()
	assert.JSONEq(t,
		`{"input":"hi","voice":"alloy","voice_id":"alloy"}`,
		string(providers.MapSpeechVoiceToVoiceID([]byte(`{"input":"hi","voice":"alloy"}`))),
	)
	assert.JSONEq(t,
		`{"input":"hi","voice_id":"custom"}`,
		string(providers.MapSpeechVoiceToVoiceID([]byte(`{"input":"hi","voice_id":"custom"}`))),
	)
	assert.Equal(t, []byte("not-json"), providers.MapSpeechVoiceToVoiceID([]byte("not-json")))
}

func TestUnwrapJSONSpeechAudio(t *testing.T) {
	t.Parallel()
	raw := []byte("wav-bytes")
	result, err := providers.UnwrapJSONSpeechAudio(&providers.AudioResult{
		Body:        []byte(`{"audio_data":"` + base64.StdEncoding.EncodeToString(raw) + `"}`),
		ContentType: "application/json",
	}, nil, []byte(`{"response_format":"wav"}`))
	require.NoError(t, err)
	assert.Equal(t, raw, result.Body)
	assert.Equal(t, "audio/wav", result.ContentType)

	passthrough, err := providers.UnwrapJSONSpeechAudio(&providers.AudioResult{
		Body:        raw,
		ContentType: "audio/mpeg",
	}, nil, []byte(`{"response_format":"mp3"}`))
	require.NoError(t, err)
	assert.Equal(t, raw, passthrough.Body)
	assert.Equal(t, "audio/mpeg", passthrough.ContentType)
}

func TestAudioContentTypeForFormat(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "audio/mpeg", providers.AudioContentTypeForFormat("mp3"))
	assert.Equal(t, "audio/wav", providers.AudioContentTypeForFormat("wav"))
	assert.Equal(t, "audio/ogg", providers.AudioContentTypeForFormat("opus"))
	assert.Equal(t, "audio/mpeg", providers.AudioContentTypeForFormat(""))
}

func multipartAudioFixture(t *testing.T, fields map[string]string, filename, contents string) (string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", filename)
	require.NoError(t, err)
	_, err = io.WriteString(part, contents)
	require.NoError(t, err)
	for name, value := range fields {
		require.NoError(t, w.WriteField(name, value))
	}
	require.NoError(t, w.Close())
	return w.FormDataContentType(), buf.Bytes()
}

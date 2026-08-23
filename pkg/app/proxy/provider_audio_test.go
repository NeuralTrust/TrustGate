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

package proxy_test

import (
	"context"
	"iter"
	"net/http"
	"testing"

	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	factorymocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory/mocks"
	providermocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type audioTestClient struct {
	speechFn        func(ctx context.Context, cfg *providers.Config, req providers.AudioRequest) (*providers.AudioResult, error)
	transcriptionFn func(ctx context.Context, cfg *providers.Config, req providers.AudioRequest) (*providers.AudioResult, error)
}

func (c *audioTestClient) Completions(context.Context, *providers.Config, []byte) ([]byte, error) {
	return nil, nil
}

func (c *audioTestClient) CompletionsStream(context.Context, *providers.Config, []byte) (iter.Seq2[[]byte, error], error) {
	return nil, nil
}

func (c *audioTestClient) AudioSpeech(ctx context.Context, cfg *providers.Config, req providers.AudioRequest) (*providers.AudioResult, error) {
	return c.speechFn(ctx, cfg, req)
}

func (c *audioTestClient) AudioTranscription(ctx context.Context, cfg *providers.Config, req providers.AudioRequest) (*providers.AudioResult, error) {
	return c.transcriptionFn(ctx, cfg, req)
}

func TestProviderInvoke_AudioSpeechPassthrough(t *testing.T) {
	var gotReq providers.AudioRequest
	var gotModel string
	client := &audioTestClient{
		speechFn: func(_ context.Context, cfg *providers.Config, req providers.AudioRequest) (*providers.AudioResult, error) {
			gotReq = req
			gotModel = cfg.Model
			return &providers.AudioResult{
				Body:        []byte("mp3-bytes"),
				ContentType: "audio/mpeg",
			}, nil
		},
	}

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
	req := &infracontext.RequestContext{
		Method:          http.MethodPost,
		Path:            "/acme/v1/audio/speech",
		Body:            []byte(`{"model":"tts-1","input":"hello","voice":"alloy"}`),
		Headers:         map[string][]string{"Content-Type": {"application/json"}},
		SourceFormat:    string(adapter.FormatOpenAIAudio),
		ProxyCapability: "audio_speech",
		AllowedModels:   []string{"tts-1"},
	}
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, string(adapter.FormatOpenAIAudio), req.TargetFormat)
	assert.Equal(t, http.MethodPost, gotReq.Method)
	assert.Equal(t, "/v1/audio/speech", gotReq.Path)
	assert.Equal(t, "application/json", gotReq.ContentType)
	assert.JSONEq(t, `{"model":"tts-1","input":"hello","voice":"alloy"}`, string(gotReq.Body))
	assert.Equal(t, []byte("mp3-bytes"), resp.Body)
	assert.Equal(t, []string{"audio/mpeg"}, resp.Headers["Content-Type"])
	assert.Equal(t, "tts-1", gotModel)
	assert.Equal(t, "tts-1", resp.SentModel)
}

func TestProviderInvoke_AudioTranscriptionMultipartPassthrough(t *testing.T) {
	var gotReq providers.AudioRequest
	var gotModel string
	client := &audioTestClient{
		transcriptionFn: func(_ context.Context, cfg *providers.Config, req providers.AudioRequest) (*providers.AudioResult, error) {
			gotReq = req
			gotModel = cfg.Model
			return &providers.AudioResult{
				Body:        []byte(`{"text":"hello"}`),
				ContentType: "application/json",
			}, nil
		},
	}

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
	body := []byte("--abc\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1\r\n--abc\r\nContent-Disposition: form-data; name=\"file\"; filename=\"hi.wav\"\r\nContent-Type: audio/wav\r\n\r\nRIFF\r\n--abc--\r\n")
	req := &infracontext.RequestContext{
		Method:          http.MethodPost,
		Path:            "/acme/v1/audio/transcriptions",
		Body:            body,
		Headers:         map[string][]string{"Content-Type": {"multipart/form-data; boundary=abc"}},
		SourceFormat:    string(adapter.FormatOpenAIAudio),
		ProxyCapability: "audio_transcription",
		AllowedModels:   []string{"whisper-1"},
	}
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, http.MethodPost, gotReq.Method)
	assert.Equal(t, "/v1/audio/transcriptions", gotReq.Path)
	assert.Equal(t, "multipart/form-data; boundary=abc", gotReq.ContentType)
	assert.Equal(t, body, gotReq.Body)
	assert.JSONEq(t, `{"text":"hello"}`, string(resp.Body))
	assert.Equal(t, "whisper-1", gotModel)
}

func TestProviderInvoke_AudioInvalidMethod(t *testing.T) {
	client := &audioTestClient{
		speechFn: func(context.Context, *providers.Config, providers.AudioRequest) (*providers.AudioResult, error) {
			t.Fatal("upstream must not be called")
			return nil, nil
		},
	}

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
	_, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), &infracontext.RequestContext{
		Method:          http.MethodGet,
		Path:            "/acme/v1/audio/speech",
		SourceFormat:    string(adapter.FormatOpenAIAudio),
		ProxyCapability: "audio_speech",
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, appproxy.ErrInvalidRequestPayload)
}

func TestProviderInvoke_AudioUnsupportedClient(t *testing.T) {
	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(providermocks.NewClient(t), nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
	_, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), &infracontext.RequestContext{
		Method:          http.MethodPost,
		Path:            "/acme/v1/audio/speech",
		Body:            []byte(`{"model":"tts-1","input":"hi"}`),
		SourceFormat:    string(adapter.FormatOpenAIAudio),
		ProxyCapability: "audio_speech",
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, appproxy.ErrCapabilityNotSupported)
}

func TestProviderInvoke_AudioModelNotAllowed(t *testing.T) {
	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(&audioTestClient{}, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
	_, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), &infracontext.RequestContext{
		Method:          http.MethodPost,
		Path:            "/acme/v1/audio/speech",
		Body:            []byte(`{"model":"tts-1-hd","input":"hi"}`),
		SourceFormat:    string(adapter.FormatOpenAIAudio),
		ProxyCapability: "audio_speech",
		AllowedModels:   []string{"tts-1"},
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, appproxy.ErrModelNotAllowed)
}

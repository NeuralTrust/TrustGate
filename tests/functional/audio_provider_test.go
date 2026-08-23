//go:build functional

package functional_test

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func speechRequest(model string) map[string]any {
	return map[string]any{
		"model":           model,
		"input":           "Hello from TrustGate",
		"voice":           "alloy",
		"response_format": "mp3",
	}
}

func newAudioUpstream(t *testing.T) (*fakeUpstream, *string) {
	t.Helper()
	lastPath := new(string)
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		*lastPath = r.URL.Path
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/audio/speech"):
			w.Header().Set("Content-Type", "audio/mpeg")
			_, _ = io.WriteString(w, "mp3-bytes")
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/audio/transcriptions"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"text":"hello from fixture"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, `{"error":{"message":"unexpected %s %s"}}`, r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(u.server.Close)
	return u, lastPath
}

func newMistralSpeechUpstream(t *testing.T) (*fakeUpstream, *string) {
	t.Helper()
	lastPath := new(string)
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		*lastPath = r.URL.Path
		if r.Method != http.MethodPost || !strings.Contains(r.URL.Path, "/audio/speech") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, `{"error":{"message":"unexpected %s %s"}}`, r.Method, r.URL.Path)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"audio_data":"bXAzLWJ5dGVz"}`)
	}))
	t.Cleanup(u.server.Close)
	return u, lastPath
}

func setupAudioBase(t *testing.T, payload map[string]any) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("audio-gw")})
	registryID := CreateRegistry(t, gatewayID, payload)
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("audio-cons")})
	AttachRegistry(t, gatewayID, coID, registryID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	return apiKey, "/" + ConsumerSlug(t, coID) + "/v1/audio"
}

func setupAudioSpeechRoute(t *testing.T, payload map[string]any) (string, string) {
	t.Helper()
	apiKey, base := setupAudioBase(t, payload)
	return apiKey, base + "/speech"
}

func setupAudioTranscriptionsRoute(t *testing.T, payload map[string]any) (string, string) {
	t.Helper()
	apiKey, base := setupAudioBase(t, payload)
	return apiKey, base + "/transcriptions"
}

func groqAudioBackendPayload(name, baseURL string) map[string]any {
	return map[string]any{
		"name":             name,
		"provider":         "groq",
		"weight":           1,
		"provider_options": map[string]any{"base_url": baseURL},
		"auth": map[string]any{
			"type":    "api_key",
			"api_key": map[string]any{"api_key": "gsk-test"},
		},
	}
}

func openrouterBackendPayload(name, baseURL string) map[string]any {
	return map[string]any{
		"name":             name,
		"provider":         "openrouter",
		"weight":           1,
		"provider_options": map[string]any{"base_url": baseURL},
		"auth": map[string]any{
			"type":    "api_key",
			"api_key": map[string]any{"api_key": "or-test"},
		},
	}
}

func multipartTranscriptionBody(t *testing.T, model, filename, contents string) (string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	require.NoError(t, w.WriteField("model", model))
	part, err := w.CreateFormFile("file", filename)
	require.NoError(t, err)
	_, err = io.WriteString(part, contents)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return w.FormDataContentType(), buf.Bytes()
}

func TestOpenAIProvider_AudioSpeech(t *testing.T) {
	defer Track(t, "AudioProvider")()

	up, lastPath := newAudioUpstream(t)
	apiKey, path := setupAudioSpeechRoute(t, openaiBackendPayload(uniqueName("oai-audio"), up.URL()+"/v1"))

	status, headers, body := proxyPost(t, apiKey, path, speechRequest("tts-1"))
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "openai", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/v1/audio/speech", *lastPath)
	assert.Equal(t, "mp3-bytes", string(body))
	assert.Contains(t, headers.Get("Content-Type"), "audio/mpeg")
	assert.Equal(t, 1, up.Hits())
}

func TestOpenAIProvider_AudioTranscriptions(t *testing.T) {
	defer Track(t, "AudioProvider")()

	up, lastPath := newAudioUpstream(t)
	apiKey, path := setupAudioTranscriptionsRoute(t, openaiBackendPayload(uniqueName("oai-audio"), up.URL()+"/v1"))
	ct, upload := multipartTranscriptionBody(t, "whisper-1", "hi.wav", "RIFF")

	status, headers, body := proxyRequest(t, http.MethodPost, apiKey, path, map[string]string{"Content-Type": ct}, upload)
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "openai", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/v1/audio/transcriptions", *lastPath)
	assert.JSONEq(t, `{"text":"hello from fixture"}`, string(body))
	assert.Equal(t, 1, up.Hits())
}

func TestAzureProvider_AudioSpeech(t *testing.T) {
	defer Track(t, "AudioProvider")()

	up, lastPath := newAudioUpstream(t)
	apiKey, path := setupAudioSpeechRoute(t, azureBackendPayload(uniqueName("az-audio"), up.URL()))

	status, headers, body := proxyPost(t, apiKey, path, speechRequest("tts-1"))
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "azure", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/openai/deployments/tts-1/audio/speech", *lastPath)
	assert.Equal(t, "mp3-bytes", string(body))
}

func TestAzureProvider_AudioTranscriptions(t *testing.T) {
	defer Track(t, "AudioProvider")()

	up, lastPath := newAudioUpstream(t)
	apiKey, path := setupAudioTranscriptionsRoute(t, azureBackendPayload(uniqueName("az-audio"), up.URL()))
	ct, upload := multipartTranscriptionBody(t, "whisper-1", "hi.wav", "RIFF")

	status, headers, body := proxyRequest(t, http.MethodPost, apiKey, path, map[string]string{"Content-Type": ct}, upload)
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "azure", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/openai/deployments/whisper-1/audio/transcriptions", *lastPath)
	assert.JSONEq(t, `{"text":"hello from fixture"}`, string(body))
}

func TestOpenAICompatibleProvider_AudioSpeech(t *testing.T) {
	defer Track(t, "AudioProvider")()

	up, lastPath := newAudioUpstream(t)
	apiKey, path := setupAudioSpeechRoute(t, openaiCompatibleBackendPayload(uniqueName("compat-audio"), up.URL()+"/v1"))

	status, headers, body := proxyPost(t, apiKey, path, speechRequest("tts-1"))
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "openai_compatible", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/v1/audio/speech", *lastPath)
}

func TestGroqProvider_AudioSpeech(t *testing.T) {
	defer Track(t, "AudioProvider")()

	up, lastPath := newAudioUpstream(t)
	apiKey, path := setupAudioSpeechRoute(t, groqAudioBackendPayload(uniqueName("groq-audio"), up.URL()+"/openai/v1"))

	status, headers, body := proxyPost(t, apiKey, path, speechRequest("playai-tts"))
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "groq", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/openai/v1/audio/speech", *lastPath)
	assert.Equal(t, "mp3-bytes", string(body))
}

func TestOpenRouterProvider_AudioTranscriptions(t *testing.T) {
	defer Track(t, "AudioProvider")()

	up, lastPath := newAudioUpstream(t)
	apiKey, path := setupAudioTranscriptionsRoute(t, openrouterBackendPayload(uniqueName("or-audio"), up.URL()+"/api/v1"))
	ct, upload := multipartTranscriptionBody(t, "openai/whisper-large-v3", "hi.wav", "RIFF")

	status, headers, body := proxyRequest(t, http.MethodPost, apiKey, path, map[string]string{"Content-Type": ct}, upload)
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "openrouter", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/api/v1/audio/transcriptions", *lastPath)
	assert.JSONEq(t, `{"text":"hello from fixture"}`, string(body))
}

func TestMistralProvider_AudioSpeechUnwrapsJSON(t *testing.T) {
	defer Track(t, "AudioProvider")()

	up, lastPath := newMistralSpeechUpstream(t)
	apiKey, path := setupAudioSpeechRoute(t, mistralBackendPayload(uniqueName("mistral-audio"), up.URL()+"/v1"))

	status, headers, body := proxyPost(t, apiKey, path, speechRequest("voxtral-mini-tts-2603"))
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "mistral", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/v1/audio/speech", *lastPath)
	assert.Equal(t, "mp3-bytes", string(body))
	assert.Contains(t, headers.Get("Content-Type"), "audio/mpeg")
}

func TestMistralProvider_AudioTranscriptions(t *testing.T) {
	defer Track(t, "AudioProvider")()

	up, lastPath := newAudioUpstream(t)
	apiKey, path := setupAudioTranscriptionsRoute(t, mistralBackendPayload(uniqueName("mistral-audio"), up.URL()+"/v1"))
	ct, upload := multipartTranscriptionBody(t, "voxtral-mini-latest", "hi.wav", "RIFF")

	status, headers, body := proxyRequest(t, http.MethodPost, apiKey, path, map[string]string{"Content-Type": ct}, upload)
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "mistral", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/v1/audio/transcriptions", *lastPath)
}

func TestAudio_FiltersIncapableProviderFromPool(t *testing.T) {
	defer Track(t, "AudioProvider")()

	capable, lastPath := newAudioUpstream(t)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("audio-mix-gw")})
	openaiID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("oai-audio"), capable.URL()+"/v1"))
	anthropicID := CreateRegistry(t, gatewayID, anthropicBackendPayload(uniqueName("ant-chat")))
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("audio-mix")})
	AttachRegistry(t, gatewayID, coID, openaiID)
	AttachRegistry(t, gatewayID, coID, anthropicID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	path := "/" + ConsumerSlug(t, coID) + "/v1/audio/speech"

	status, headers, body := proxyPost(t, apiKey, path, speechRequest("tts-1"))
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "openai", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/v1/audio/speech", *lastPath)
	assert.Equal(t, 1, capable.Hits())
}

func TestAudio_PinnedIncapableProviderIsTerminal(t *testing.T) {
	defer Track(t, "AudioProvider")()

	capable, _ := newAudioUpstream(t)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("audio-pin-gw")})
	openaiID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("oai-audio"), capable.URL()+"/v1"))
	anthropicID := CreateRegistry(t, gatewayID, anthropicBackendPayload(uniqueName("ant-chat")))
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("audio-pin")})
	AttachRegistry(t, gatewayID, coID, openaiID)
	AttachRegistry(t, gatewayID, coID, anthropicID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	path := "/" + ConsumerSlug(t, coID) + "/v1/audio/speech"

	status, _, body := proxyPost(t, apiKey, path, speechRequest("@anthropic/claude-4"))
	assert.Equal(t, http.StatusBadRequest, status, "body: %s", body)
	assert.Equal(t, 0, capable.Hits(), "pinned incapable provider must not fail over")
	assert.Contains(t, string(body), "does not support this capability")
}

func TestAudio_PinnedIncapableMultipartIsTerminal(t *testing.T) {
	defer Track(t, "AudioProvider")()

	capable, _ := newAudioUpstream(t)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("audio-pin-stt-gw")})
	openaiID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("oai-audio"), capable.URL()+"/v1"))
	anthropicID := CreateRegistry(t, gatewayID, anthropicBackendPayload(uniqueName("ant-chat")))
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("audio-pin-stt")})
	AttachRegistry(t, gatewayID, coID, openaiID)
	AttachRegistry(t, gatewayID, coID, anthropicID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	path := "/" + ConsumerSlug(t, coID) + "/v1/audio/transcriptions"
	ct, upload := multipartTranscriptionBody(t, "@anthropic/claude-4", "hi.wav", "RIFF")

	status, _, body := proxyRequest(t, http.MethodPost, apiKey, path, map[string]string{"Content-Type": ct}, upload)
	assert.Equal(t, http.StatusBadRequest, status, "body: %s", body)
	assert.Equal(t, 0, capable.Hits(), "pinned incapable provider must not fail over")
	assert.Contains(t, string(body), "does not support this capability")
}

func TestAudio_TranslationsAre404(t *testing.T) {
	defer Track(t, "AudioProvider")()

	up, _ := newAudioUpstream(t)
	apiKey, base := setupAudioBase(t, openaiBackendPayload(uniqueName("oai-audio"), up.URL()+"/v1"))

	status, _, body := proxyRequest(t, http.MethodPost, apiKey, base+"/translations", nil, mustJSON(t, speechRequest("whisper-1")))
	assert.Equal(t, http.StatusNotFound, status, "body: %s", body)
	assert.Equal(t, 0, up.Hits())
}

func TestAudio_InvalidMethodIs400(t *testing.T) {
	defer Track(t, "AudioProvider")()

	up, _ := newAudioUpstream(t)
	apiKey, path := setupAudioSpeechRoute(t, openaiBackendPayload(uniqueName("oai-audio"), up.URL()+"/v1"))

	status, _, body := proxyRequest(t, http.MethodGet, apiKey, path, nil, nil)
	assert.Equal(t, http.StatusBadRequest, status, "body: %s", body)
	assert.Equal(t, 0, up.Hits())
}

func TestAudio_EmptyCapablePoolIs503(t *testing.T) {
	defer Track(t, "AudioProvider")()

	apiKey, path := setupAudioSpeechRoute(t, anthropicBackendPayload(uniqueName("ant-only")))

	status, _, body := proxyPost(t, apiKey, path, speechRequest("tts-1"))
	assert.Equal(t, http.StatusServiceUnavailable, status, "body: %s", body)
	assert.Contains(t, string(body), "no_backend_available")
}

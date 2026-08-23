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

func imagesGenerationsRequest(model string) map[string]any {
	return map[string]any{
		"model":  model,
		"prompt": "a minimal TrustGate logo",
		"n":      1,
		"size":   "1024x1024",
	}
}

func newImagesUpstream(t *testing.T) (*fakeUpstream, *string) {
	t.Helper()
	lastPath := new(string)
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		*lastPath = r.URL.Path
		if r.Method != http.MethodPost || !isImagesUpstreamPath(r.URL.Path) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, `{"error":{"message":"unexpected %s %s"}}`, r.Method, r.URL.Path)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"created":1,"data":[{"url":"https://example.test/img.png"}]}`)
	}))
	t.Cleanup(u.server.Close)
	return u, lastPath
}

func isImagesUpstreamPath(path string) bool {
	return strings.Contains(path, "/images/generations") ||
		strings.Contains(path, "/images/edits") ||
		strings.Contains(path, "/images/variations")
}

func setupImagesBase(t *testing.T, payload map[string]any) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("img-gw")})
	registryID := CreateRegistry(t, gatewayID, payload)
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("img-cons")})
	AttachRegistry(t, gatewayID, coID, registryID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	return apiKey, "/" + ConsumerSlug(t, coID) + "/v1/images"
}

func setupImagesRoute(t *testing.T, payload map[string]any) (string, string) {
	t.Helper()
	apiKey, base := setupImagesBase(t, payload)
	return apiKey, base + "/generations"
}

func multipartImagesBody(t *testing.T, fields map[string]string, filename, contents string) (string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for name, value := range fields {
		require.NoError(t, w.WriteField(name, value))
	}
	if filename != "" {
		part, err := w.CreateFormFile("image", filename)
		require.NoError(t, err)
		_, err = io.WriteString(part, contents)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return w.FormDataContentType(), buf.Bytes()
}

func groqBackendPayload(name string) map[string]any {
	return map[string]any{
		"name":     name,
		"provider": "groq",
		"weight":   1,
		"auth": map[string]any{
			"type":    "api_key",
			"api_key": map[string]any{"api_key": "gsk-test"},
		},
	}
}

func TestOpenAIProvider_ImagesGenerations(t *testing.T) {
	defer Track(t, "ImagesProvider")()

	up, lastPath := newImagesUpstream(t)
	apiKey, path := setupImagesRoute(t, openaiBackendPayload(uniqueName("oai-img"), up.URL()+"/v1"))

	status, headers, body := proxyPost(t, apiKey, path, imagesGenerationsRequest("dall-e-3"))
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "openai", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/v1/images/generations", *lastPath)
	assert.Contains(t, string(body), "https://example.test/img.png")
	assert.Equal(t, 1, up.Hits())
}

func TestAzureProvider_ImagesGenerations(t *testing.T) {
	defer Track(t, "ImagesProvider")()

	up, lastPath := newImagesUpstream(t)
	apiKey, path := setupImagesRoute(t, azureBackendPayload(uniqueName("az-img"), up.URL()))

	status, headers, body := proxyPost(t, apiKey, path, imagesGenerationsRequest("dall-e-3"))
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "azure", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/openai/deployments/dall-e-3/images/generations", *lastPath)
}

func TestOpenAICompatibleProvider_ImagesGenerations(t *testing.T) {
	defer Track(t, "ImagesProvider")()

	up, lastPath := newImagesUpstream(t)
	apiKey, path := setupImagesRoute(t, openaiCompatibleBackendPayload(uniqueName("compat-img"), up.URL()+"/v1"))

	status, headers, body := proxyPost(t, apiKey, path, imagesGenerationsRequest("dall-e-3"))
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "openai_compatible", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/v1/images/generations", *lastPath)
}

func TestImages_FiltersIncapableProviderFromPool(t *testing.T) {
	defer Track(t, "ImagesProvider")()

	capable, lastPath := newImagesUpstream(t)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("img-mix-gw")})
	openaiID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("oai-img"), capable.URL()+"/v1"))
	groqID := CreateRegistry(t, gatewayID, groqBackendPayload(uniqueName("groq-chat")))
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("img-mix")})
	AttachRegistry(t, gatewayID, coID, openaiID)
	AttachRegistry(t, gatewayID, coID, groqID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	path := "/" + ConsumerSlug(t, coID) + "/v1/images/generations"

	status, headers, body := proxyPost(t, apiKey, path, imagesGenerationsRequest("dall-e-3"))
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "openai", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/v1/images/generations", *lastPath)
	assert.Equal(t, 1, capable.Hits())
}

func TestImages_PinnedIncapableProviderIsTerminal(t *testing.T) {
	defer Track(t, "ImagesProvider")()

	capable, _ := newImagesUpstream(t)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("img-pin-gw")})
	openaiID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("oai-img"), capable.URL()+"/v1"))
	groqID := CreateRegistry(t, gatewayID, groqBackendPayload(uniqueName("groq-chat")))
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("img-pin")})
	AttachRegistry(t, gatewayID, coID, openaiID)
	AttachRegistry(t, gatewayID, coID, groqID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	path := "/" + ConsumerSlug(t, coID) + "/v1/images/generations"

	status, _, body := proxyPost(t, apiKey, path, imagesGenerationsRequest("@groq/llama-3.1-8b-instant"))
	assert.Equal(t, http.StatusBadRequest, status, "body: %s", body)
	assert.Equal(t, 0, capable.Hits(), "pinned incapable provider must not fail over")
	assert.Contains(t, string(body), "does not support this capability")
}

func TestImages_UnknownSubpathIs404(t *testing.T) {
	defer Track(t, "ImagesProvider")()

	up, _ := newImagesUpstream(t)
	apiKey, path := setupImagesRoute(t, openaiBackendPayload(uniqueName("oai-img"), up.URL()+"/v1"))

	status, _, body := proxyRequest(t, http.MethodPost, apiKey, strings.TrimSuffix(path, "/generations")+"/foo", nil, mustJSON(t, imagesGenerationsRequest("dall-e-3")))
	assert.Equal(t, http.StatusNotFound, status, "body: %s", body)
	assert.Equal(t, 0, up.Hits())
}

func TestImages_InvalidMethodIs400(t *testing.T) {
	defer Track(t, "ImagesProvider")()

	up, _ := newImagesUpstream(t)
	apiKey, path := setupImagesRoute(t, openaiBackendPayload(uniqueName("oai-img"), up.URL()+"/v1"))

	status, _, body := proxyRequest(t, http.MethodGet, apiKey, path, nil, nil)
	assert.Equal(t, http.StatusBadRequest, status, "body: %s", body)
	assert.Equal(t, 0, up.Hits())
}

func TestImages_EmptyCapablePoolIs503(t *testing.T) {
	defer Track(t, "ImagesProvider")()

	apiKey, path := setupImagesRoute(t, groqBackendPayload(uniqueName("groq-only")))

	status, _, body := proxyPost(t, apiKey, path, map[string]any{"prompt": "a cat"})
	assert.Equal(t, http.StatusServiceUnavailable, status, "body: %s", body)
	assert.Contains(t, string(body), "no_backend_available")
}

func TestOpenAIProvider_ImagesEdits(t *testing.T) {
	defer Track(t, "ImagesProvider")()

	up, lastPath := newImagesUpstream(t)
	apiKey, base := setupImagesBase(t, openaiBackendPayload(uniqueName("oai-img"), up.URL()+"/v1"))
	ct, upload := multipartImagesBody(t, map[string]string{
		"model":  "dall-e-2",
		"prompt": "make it blue",
	}, "cat.png", "fakepng")

	status, headers, body := proxyRequest(t, http.MethodPost, apiKey, base+"/edits", map[string]string{"Content-Type": ct}, upload)
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "openai", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/v1/images/edits", *lastPath)
	assert.Contains(t, string(body), "https://example.test/img.png")
	assert.Equal(t, 1, up.Hits())
}

func TestOpenAIProvider_ImagesVariations(t *testing.T) {
	defer Track(t, "ImagesProvider")()

	up, lastPath := newImagesUpstream(t)
	apiKey, base := setupImagesBase(t, openaiBackendPayload(uniqueName("oai-img"), up.URL()+"/v1"))
	ct, upload := multipartImagesBody(t, map[string]string{"model": "dall-e-2"}, "cat.png", "fakepng")

	status, headers, body := proxyRequest(t, http.MethodPost, apiKey, base+"/variations", map[string]string{"Content-Type": ct}, upload)
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "openai", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/v1/images/variations", *lastPath)
	assert.Equal(t, 1, up.Hits())
}

func TestAzureProvider_ImagesEdits(t *testing.T) {
	defer Track(t, "ImagesProvider")()

	up, lastPath := newImagesUpstream(t)
	apiKey, base := setupImagesBase(t, azureBackendPayload(uniqueName("az-img"), up.URL()))
	ct, upload := multipartImagesBody(t, map[string]string{
		"model":  "dall-e-2",
		"prompt": "make it blue",
	}, "cat.png", "fakepng")

	status, headers, body := proxyRequest(t, http.MethodPost, apiKey, base+"/edits", map[string]string{"Content-Type": ct}, upload)
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "azure", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/openai/deployments/dall-e-2/images/edits", *lastPath)
}

func TestImages_PinnedIncapableMultipartIsTerminal(t *testing.T) {
	defer Track(t, "ImagesProvider")()

	capable, _ := newImagesUpstream(t)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("img-pin-mp")})
	openaiID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("oai-img"), capable.URL()+"/v1"))
	groqID := CreateRegistry(t, gatewayID, groqBackendPayload(uniqueName("groq-chat")))
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("img-pin-mp")})
	AttachRegistry(t, gatewayID, coID, openaiID)
	AttachRegistry(t, gatewayID, coID, groqID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	path := "/" + ConsumerSlug(t, coID) + "/v1/images/edits"
	ct, upload := multipartImagesBody(t, map[string]string{
		"model":  "@groq/llama-3.1-8b-instant",
		"prompt": "make it blue",
	}, "cat.png", "fakepng")

	status, _, body := proxyRequest(t, http.MethodPost, apiKey, path, map[string]string{"Content-Type": ct}, upload)
	assert.Equal(t, http.StatusBadRequest, status, "body: %s", body)
	assert.Equal(t, 0, capable.Hits(), "pinned incapable provider must not fail over")
	assert.Contains(t, string(body), "does not support this capability")
}

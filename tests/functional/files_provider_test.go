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

type filesCall struct {
	method      string
	path        string
	query       string
	contentType string
	body        []byte
}

func newFilesUpstream(t *testing.T) (*fakeUpstream, *filesCall) {
	t.Helper()
	last := &filesCall{}
	u := &fakeUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		last.method = r.Method
		last.path = r.URL.Path
		last.query = r.URL.RawQuery
		last.contentType = r.Header.Get("Content-Type")
		last.body = append([]byte(nil), u.LastBody()...)

		tail := filesAPITail(r.URL.Path)
		if tail == "" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, `{"error":{"message":"unexpected path %s"}}`, r.URL.Path)
			return
		}

		switch {
		case r.Method == http.MethodPost && tail == "/files":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"file-1","object":"file","filename":"notes.txt","purpose":"assistants"}`)
		case r.Method == http.MethodGet && tail == "/files":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"object":"list","data":[{"id":"file-1","object":"file"}]}`)
		case r.Method == http.MethodGet && tail == "/files/file-1":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"file-1","object":"file","filename":"notes.txt"}`)
		case r.Method == http.MethodDelete && tail == "/files/file-1":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"file-1","object":"file","deleted":true}`)
		case r.Method == http.MethodGet && tail == "/files/file-1/content":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = io.WriteString(w, "file-bytes")
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, `{"error":{"message":"unexpected %s %s"}}`, r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(u.server.Close)
	return u, last
}

func filesAPITail(path string) string {
	idx := strings.Index(path, "/files")
	if idx < 0 {
		return ""
	}
	return path[idx:]
}

func setupFilesRoute(t *testing.T, payload map[string]any) (string, string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("files-gw")})
	registryID := CreateRegistry(t, gatewayID, payload)
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("files-cons")})
	AttachRegistry(t, gatewayID, coID, registryID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	return apiKey, "/" + ConsumerSlug(t, coID) + "/v1/files"
}

func multipartFilesBody(t *testing.T, filename, contents, purpose string) (string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	require.NoError(t, w.WriteField("purpose", purpose))
	part, err := w.CreateFormFile("file", filename)
	require.NoError(t, err)
	_, err = io.WriteString(part, contents)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return w.FormDataContentType(), buf.Bytes()
}

func TestOpenAIProvider_Files(t *testing.T) {
	defer Track(t, "FilesProvider")()

	up, last := newFilesUpstream(t)
	apiKey, path := setupFilesRoute(t, openaiBackendPayload(uniqueName("oai-files"), up.URL()+"/v1"))

	ct, body := multipartFilesBody(t, "notes.txt", "hello files", "assistants")
	status, headers, resp := proxyRequest(t, http.MethodPost, apiKey, path, map[string]string{"Content-Type": ct}, body)
	assert.Equal(t, http.StatusOK, status, "body: %s", resp)
	assert.Equal(t, "openai", headers.Get("X-Selected-Provider"))
	assert.Equal(t, http.MethodPost, last.method)
	assert.Equal(t, "/v1/files", last.path)
	assert.Contains(t, last.contentType, "multipart/form-data")
	assert.Contains(t, string(last.body), "hello files")
	assert.JSONEq(t, `{"id":"file-1","object":"file","filename":"notes.txt","purpose":"assistants"}`, string(resp))

	status, _, resp = proxyRequest(t, http.MethodGet, apiKey, path+"?purpose=assistants", nil, nil)
	assert.Equal(t, http.StatusOK, status, "body: %s", resp)
	assert.Equal(t, "/v1/files", last.path)
	assert.Contains(t, last.query, "purpose=assistants")
	assert.JSONEq(t, `{"object":"list","data":[{"id":"file-1","object":"file"}]}`, string(resp))

	status, _, resp = proxyRequest(t, http.MethodGet, apiKey, path+"/file-1", nil, nil)
	assert.Equal(t, http.StatusOK, status, "body: %s", resp)
	assert.Equal(t, "/v1/files/file-1", last.path)

	status, headers, resp = proxyRequest(t, http.MethodGet, apiKey, path+"/file-1/content", nil, nil)
	assert.Equal(t, http.StatusOK, status, "body: %s", resp)
	assert.Equal(t, "/v1/files/file-1/content", last.path)
	assert.Equal(t, "file-bytes", string(resp))
	assert.Contains(t, headers.Get("Content-Type"), "application/octet-stream")

	status, _, resp = proxyRequest(t, http.MethodDelete, apiKey, path+"/file-1", nil, nil)
	assert.Equal(t, http.StatusOK, status, "body: %s", resp)
	assert.Equal(t, http.MethodDelete, last.method)
	assert.Equal(t, "/v1/files/file-1", last.path)
	assert.JSONEq(t, `{"id":"file-1","object":"file","deleted":true}`, string(resp))
	assert.Equal(t, 5, up.Hits())
}

func TestAzureProvider_Files(t *testing.T) {
	defer Track(t, "FilesProvider")()

	up, last := newFilesUpstream(t)
	apiKey, path := setupFilesRoute(t, azureBackendPayload(uniqueName("az-files"), up.URL()))

	status, headers, body := proxyRequest(t, http.MethodGet, apiKey, path, nil, nil)
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "azure", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/openai/files", last.path)
	assert.Contains(t, last.query, "api-version=")

	status, _, body = proxyRequest(t, http.MethodGet, apiKey, path+"/file-1", nil, nil)
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "/openai/files/file-1", last.path)

	status, _, body = proxyRequest(t, http.MethodDelete, apiKey, path+"/file-1", nil, nil)
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, http.MethodDelete, last.method)
	assert.Equal(t, "/openai/files/file-1", last.path)
	assert.Equal(t, 3, up.Hits())
}

func TestMistralProvider_Files(t *testing.T) {
	defer Track(t, "FilesProvider")()

	up, last := newFilesUpstream(t)
	apiKey, path := setupFilesRoute(t, mistralBackendPayload(uniqueName("mistral-files"), up.URL()+"/v1"))

	ct, upload := multipartFilesBody(t, "notes.txt", "mistral file", "ocr")
	status, headers, body := proxyRequest(t, http.MethodPost, apiKey, path, map[string]string{"Content-Type": ct}, upload)
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "mistral", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/v1/files", last.path)
	assert.Contains(t, last.contentType, "multipart/form-data")
}

func TestFiles_FiltersIncapableProviderFromPool(t *testing.T) {
	defer Track(t, "FilesProvider")()

	capable, last := newFilesUpstream(t)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("files-mix-gw")})
	openaiID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("oai-files"), capable.URL()+"/v1"))
	anthropicID := CreateRegistry(t, gatewayID, anthropicBackendPayload(uniqueName("ant-chat")))
	compatID := CreateRegistry(t, gatewayID, openaiCompatibleBackendPayload(uniqueName("compat-chat"), capable.URL()+"/v1"))
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("files-mix")})
	AttachRegistry(t, gatewayID, coID, openaiID)
	AttachRegistry(t, gatewayID, coID, anthropicID)
	AttachRegistry(t, gatewayID, coID, compatID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	path := "/" + ConsumerSlug(t, coID) + "/v1/files"

	status, headers, body := proxyRequest(t, http.MethodGet, apiKey, path, nil, nil)
	assert.Equal(t, http.StatusOK, status, "body: %s", body)
	assert.Equal(t, "openai", headers.Get("X-Selected-Provider"))
	assert.Equal(t, "/v1/files", last.path)
	assert.Equal(t, 1, capable.Hits())
}

func TestFiles_PinnedIncapableProviderIsTerminal(t *testing.T) {
	defer Track(t, "FilesProvider")()

	capable, _ := newFilesUpstream(t)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("files-pin-gw")})
	openaiID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("oai-files"), capable.URL()+"/v1"))
	anthropicID := CreateRegistry(t, gatewayID, anthropicBackendPayload(uniqueName("ant-chat")))
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("files-pin")})
	AttachRegistry(t, gatewayID, coID, openaiID)
	AttachRegistry(t, gatewayID, coID, anthropicID)
	apiKey := createAndAttachAPIKey(t, gatewayID, coID)
	path := "/" + ConsumerSlug(t, coID) + "/v1/files"

	status, _, body := proxyPost(t, apiKey, path, map[string]any{"model": "@anthropic/claude-4"})
	assert.Equal(t, http.StatusBadRequest, status, "body: %s", body)
	assert.Equal(t, 0, capable.Hits(), "pinned incapable provider must not fail over")
	assert.Contains(t, string(body), "does not support this capability")
}

func TestFiles_UnknownSubpathIs404(t *testing.T) {
	defer Track(t, "FilesProvider")()

	up, _ := newFilesUpstream(t)
	apiKey, path := setupFilesRoute(t, openaiBackendPayload(uniqueName("oai-files"), up.URL()+"/v1"))

	status, _, body := proxyRequest(t, http.MethodGet, apiKey, path+"/file-1/other", nil, nil)
	assert.Equal(t, http.StatusNotFound, status, "body: %s", body)
	assert.Equal(t, 0, up.Hits())
}

func TestFiles_InvalidMethodIs400(t *testing.T) {
	defer Track(t, "FilesProvider")()

	up, _ := newFilesUpstream(t)
	apiKey, path := setupFilesRoute(t, openaiBackendPayload(uniqueName("oai-files"), up.URL()+"/v1"))

	status, _, body := proxyRequest(t, http.MethodDelete, apiKey, path, nil, nil)
	assert.Equal(t, http.StatusBadRequest, status, "body: %s", body)
	assert.Equal(t, 0, up.Hits())
}

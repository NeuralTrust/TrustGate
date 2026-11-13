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

package watsonx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

type upstreamCall struct {
	path    string
	version string
	auth    string
	body    map[string]any
}

type fakeWatsonx struct {
	srv       *httptest.Server
	calls     chan upstreamCall
	rejectN   atomic.Int32
	status    int
	errorBody string
}

func newFakeWatsonx(t *testing.T) *fakeWatsonx {
	t.Helper()
	f := &fakeWatsonx{calls: make(chan upstreamCall, 8)}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		f.calls <- upstreamCall{path: r.URL.Path, version: r.URL.Query().Get("version"), auth: r.Header.Get("Authorization"), body: body}

		if f.rejectN.Load() > 0 {
			f.rejectN.Add(-1)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"errors":[{"code":"authentication_token_expired","message":"token expired"}],"status_code":401}`)
			return
		}
		if f.status != 0 {
			w.WriteHeader(f.status)
			_, _ = io.WriteString(w, f.errorBody)
			return
		}
		switch r.URL.Path {
		case chatPath:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"chatcmpl-1","model_id":"ibm/granite-4-h-small","created":1763040000,"created_at":"x",
				"choices":[{"index":0,"message":{"role":"assistant","content":"Hallo"},"finish_reason":"stop"}],
				"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}`)
		case chatStreamPath:
			w.Header().Set("Content-Type", "text/event-stream")
			for i, delta := range []string{"Hal", "lo"} {
				_, _ = fmt.Fprintf(w, "id: %d\nevent: message\ndata: {\"id\":\"c\",\"model_id\":\"ibm/granite-4-h-small\",\"created\":1,\"choices\":[{\"index\":0,\"delta\":{\"content\":%q}}]}\n\n", i+1, delta)
			}
			_, _ = io.WriteString(w, "id: 3\nevent: message\ndata: {\"id\":\"c\",\"model_id\":\"ibm/granite-4-h-small\",\"created\":1,\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n")
		case specsPath:
			_, _ = io.WriteString(w, `{"resources":[{"model_id":"ibm/granite-4-h-small","label":"granite-4-h-small","functions":[{"id":"text_chat"}],"lifecycle":[{"id":"available","start_date":"2025-10-02"}]}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeWatsonx) next(t *testing.T) upstreamCall {
	t.Helper()
	select {
	case call := <-f.calls:
		return call
	default:
		t.Fatal("expected an upstream call")
		return upstreamCall{}
	}
}

func testClient(iam *fakeIAM) *client {
	return &client{pool: providers.NewHTTPClientPool(), tokens: newTokenCache(iam.srv.URL)}
}

func testConfig(baseURL string) *providers.Config {
	return &providers.Config{
		Credentials: providers.Credentials{ApiKey: "ibm-key"},
		Model:       "ibm/granite-4-h-small",
		Options: map[string]any{
			"region":     "eu-de",
			"project_id": testProject,
			"base_url":   baseURL,
		},
	}
}

const chatBody = `{"model":"ibm/granite-4-h-small","messages":[{"role":"user","content":"Hi"}],"stream_options":{"include_usage":true}}`

func TestClient_Completions(t *testing.T) {
	iam := newFakeIAM(t)
	wx := newFakeWatsonx(t)
	c := testClient(iam)

	out, err := c.Completions(context.Background(), testConfig(wx.srv.URL), []byte(chatBody))
	require.NoError(t, err)

	call := wx.next(t)
	assert.Equal(t, chatPath, call.path)
	assert.Equal(t, providers.WatsonxDefaultAPIVersion, call.version)
	assert.Equal(t, "Bearer token-1", call.auth)
	assert.Equal(t, "ibm/granite-4-h-small", call.body["model_id"])
	assert.Equal(t, testProject, call.body["project_id"])
	assert.NotContains(t, call.body, "stream_options")

	got := decode(t, out)
	assert.Equal(t, "chat.completion", got["object"])
	assert.Equal(t, "ibm/granite-4-h-small", got["model"])

	_, err = c.Completions(context.Background(), testConfig(wx.srv.URL), []byte(chatBody))
	require.NoError(t, err)
	assert.Equal(t, "Bearer token-1", wx.next(t).auth, "the IAM token is reused across calls")
	assert.EqualValues(t, 1, iam.calls.Load())
}

func TestClient_RetriesOnceWithFreshTokenOn401(t *testing.T) {
	iam := newFakeIAM(t)
	wx := newFakeWatsonx(t)
	wx.rejectN.Store(1)
	c := testClient(iam)

	_, err := c.Completions(context.Background(), testConfig(wx.srv.URL), []byte(chatBody))
	require.NoError(t, err)
	assert.Equal(t, "Bearer token-1", wx.next(t).auth)
	assert.Equal(t, "Bearer token-2", wx.next(t).auth)
	assert.EqualValues(t, 2, iam.calls.Load())
}

func TestClient_PersistentAuthFailureSurfaces(t *testing.T) {
	iam := newFakeIAM(t)
	wx := newFakeWatsonx(t)
	wx.rejectN.Store(5)
	c := testClient(iam)

	_, err := c.Completions(context.Background(), testConfig(wx.srv.URL), []byte(chatBody))
	be, ok := registry.IsBackendError(err)
	require.True(t, ok, "%v", err)
	assert.Equal(t, http.StatusUnauthorized, be.StatusCode)
	assert.Len(t, wx.calls, 2, "one retry, not a loop")
}

func TestClient_BackendErrorIsOpenAIShaped(t *testing.T) {
	iam := newFakeIAM(t)
	wx := newFakeWatsonx(t)
	wx.status = http.StatusBadRequest
	wx.errorBody = `{"errors":[{"code":"json_validation_error","message":"Json document validation error"}],"trace":"t-1","status_code":400}`
	c := testClient(iam)

	_, err := c.Completions(context.Background(), testConfig(wx.srv.URL), []byte(chatBody))
	be, ok := registry.IsBackendError(err)
	require.True(t, ok, "%v", err)
	assert.Equal(t, http.StatusBadRequest, be.StatusCode)
	errObj := decode(t, be.Body)["error"].(map[string]any)
	assert.Equal(t, "json_validation_error", errObj["code"])
	assert.Equal(t, "invalid_request_error", errObj["type"])
}

func TestClient_CompletionsStream(t *testing.T) {
	iam := newFakeIAM(t)
	wx := newFakeWatsonx(t)
	c := testClient(iam)

	seq, err := c.CompletionsStream(context.Background(), testConfig(wx.srv.URL), []byte(chatBody))
	require.NoError(t, err)
	out, err := collect(t, seq)
	require.NoError(t, err)

	call := wx.next(t)
	assert.Equal(t, chatStreamPath, call.path)
	assert.NotContains(t, call.body, "stream")

	var content strings.Builder
	for _, line := range out {
		if !strings.HasPrefix(line, "data: {") {
			continue
		}
		chunk := decode(t, []byte(strings.TrimPrefix(line, "data: ")))
		assert.Equal(t, "chat.completion.chunk", chunk["object"])
		for _, choice := range chunk["choices"].([]any) {
			if text, ok := choice.(map[string]any)["delta"].(map[string]any)["content"].(string); ok {
				content.WriteString(text)
			}
		}
	}
	assert.Equal(t, "Hallo", content.String())
	assert.Equal(t, "data: [DONE]", out[len(out)-2])
}

func TestClient_StreamErrorBeforeFirstByte(t *testing.T) {
	iam := newFakeIAM(t)
	wx := newFakeWatsonx(t)
	wx.status = http.StatusTooManyRequests
	wx.errorBody = `{"errors":[{"code":"rate_limit","message":"slow down"}],"status_code":429}`
	c := testClient(iam)

	_, err := c.CompletionsStream(context.Background(), testConfig(wx.srv.URL), []byte(chatBody))
	be, ok := registry.IsBackendError(err)
	require.True(t, ok, "%v", err)
	assert.Equal(t, http.StatusTooManyRequests, be.StatusCode)
}

func TestClient_InvalidOptionsFailBeforeAnyCall(t *testing.T) {
	iam := newFakeIAM(t)
	c := testClient(iam)
	cfg := testConfig("")
	cfg.Options = map[string]any{"region": "eu-de"}

	_, err := c.Completions(context.Background(), cfg, []byte(chatBody))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project_id")
	assert.Zero(t, iam.calls.Load())
}

func TestClient_MissingAPIKey(t *testing.T) {
	iam := newFakeIAM(t)
	wx := newFakeWatsonx(t)
	c := testClient(iam)
	cfg := testConfig(wx.srv.URL)
	cfg.Credentials.ApiKey = ""

	_, err := c.Completions(context.Background(), cfg, []byte(chatBody))
	assert.ErrorIs(t, err, registry.ErrCredentialAcquisition)
	assert.Empty(t, wx.calls)
}

func TestClient_RegionSelectsEndpoint(t *testing.T) {
	opts, err := providers.DecodeWatsonxOptions(map[string]any{"region": "eu-de", "project_id": testProject})
	require.NoError(t, err)
	assert.Equal(t, "https://eu-de.ml.cloud.ibm.com/ml/v1/text/chat?version="+providers.WatsonxDefaultAPIVersion, endpointURL(opts, chatPath, nil))
}

func TestClient_ListLiveModelsAndProbe(t *testing.T) {
	iam := newFakeIAM(t)
	wx := newFakeWatsonx(t)
	c := testClient(iam)

	models, err := c.ListLiveModels(context.Background(), testConfig(wx.srv.URL))
	require.NoError(t, err)
	require.Len(t, models, 1)
	assert.Equal(t, providers.LiveModel{ID: "ibm/granite-4-h-small", DisplayName: "granite-4-h-small", ProviderModel: "ibm/granite-4-h-small"}, models[0])
	call := wx.next(t)
	assert.Equal(t, specsPath, call.path)
	assert.Equal(t, "Bearer token-1", call.auth)

	result := c.TestConnection(context.Background(), testConfig(wx.srv.URL))
	assert.True(t, result.OK, "%+v", result)
}

func TestClient_ProbeReportsRejectedKey(t *testing.T) {
	iam := newFakeIAM(t)
	iam.status.Store(http.StatusBadRequest)
	wx := newFakeWatsonx(t)
	c := testClient(iam)

	result := c.TestConnection(context.Background(), testConfig(wx.srv.URL))
	assert.False(t, result.OK)
	assert.Equal(t, providers.StageAuthentication, result.Stage)
	assert.Contains(t, result.Message, "rejected the API key")
	assert.Empty(t, wx.calls)

	_, err := c.ListLiveModels(context.Background(), testConfig(wx.srv.URL))
	assert.ErrorIs(t, err, providers.ErrModelListingMisconfigured)
}

func TestClient_ProbeReportsBadOptions(t *testing.T) {
	iam := newFakeIAM(t)
	c := testClient(iam)
	cfg := testConfig("")
	cfg.Options = map[string]any{"region": "mars-1", "project_id": testProject}

	result := c.TestConnection(context.Background(), cfg)
	assert.False(t, result.OK)
	assert.Equal(t, providers.StageConnectivity, result.Stage)
	assert.Contains(t, result.Message, "region")
}

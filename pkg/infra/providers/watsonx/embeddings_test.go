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
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

type embedCall struct {
	auth    string
	version string
	body    watsonxEmbeddingRequest
}

// fakeEmbedder answers each input "t-N" with the vector [N, 0.5] and charges
// two tokens per input, so tests can check order and token totals.
type fakeEmbedder struct {
	srv       *httptest.Server
	mu        sync.Mutex
	calls     []embedCall
	rejectN   atomic.Int32
	status    int
	errorBody string
}

func newFakeEmbedder(t *testing.T) *fakeEmbedder {
	t.Helper()
	f := &fakeEmbedder{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != embeddingsPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var body watsonxEmbeddingRequest
		_ = json.Unmarshal(raw, &body)
		f.mu.Lock()
		f.calls = append(f.calls, embedCall{auth: r.Header.Get("Authorization"), version: r.URL.Query().Get("version"), body: body})
		f.mu.Unlock()

		if f.rejectN.Load() > 0 {
			f.rejectN.Add(-1)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if f.status != 0 {
			w.WriteHeader(f.status)
			_, _ = io.WriteString(w, f.errorBody)
			return
		}
		results := make([]string, 0, len(body.Inputs))
		for _, input := range body.Inputs {
			n, _ := strconv.Atoi(strings.TrimPrefix(input, "t-"))
			results = append(results, fmt.Sprintf(`{"embedding":[%d,0.5]}`, n))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"model_id":%q,"results":[%s],"created_at":"2026-11-15T10:00:00Z","input_token_count":%d}`,
			body.ModelID, strings.Join(results, ","), 2*len(body.Inputs))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeEmbedder) recorded() []embedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]embedCall(nil), f.calls...)
}

func embedConfig(baseURL string) *providers.Config {
	cfg := testConfig(baseURL)
	cfg.Model = "ibm/granite-embedding-278m-multilingual"
	return cfg
}

type embeddingResponse struct {
	Object string `json:"object"`
	Model  string `json:"model"`
	Data   []struct {
		Object    string          `json:"object"`
		Index     int             `json:"index"`
		Embedding json.RawMessage `json:"embedding"`
	} `json:"data"`
	Usage struct {
		PromptTokens int `json:"prompt_tokens"`
		TotalTokens  int `json:"total_tokens"`
	} `json:"usage"`
}

func decodeEmbeddings(t *testing.T, raw []byte) embeddingResponse {
	t.Helper()
	var out embeddingResponse
	require.NoError(t, json.Unmarshal(raw, &out), "%s", raw)
	return out
}

func TestEmbeddings_TranslatesToWatsonxAndBack(t *testing.T) {
	iam := newFakeIAM(t)
	wx := newFakeEmbedder(t)
	c := testClient(iam)

	out, err := c.Embeddings(context.Background(), embedConfig(wx.srv.URL),
		[]byte(`{"model":"ignored-by-config","input":["t-7","t-3"],"encoding_format":"float","user":"u-1"}`))
	require.NoError(t, err)

	calls := wx.recorded()
	require.Len(t, calls, 1)
	assert.Equal(t, "Bearer token-1", calls[0].auth)
	assert.Equal(t, providers.WatsonxDefaultAPIVersion, calls[0].version)
	assert.Equal(t, "ibm/granite-embedding-278m-multilingual", calls[0].body.ModelID)
	assert.Equal(t, testProject, calls[0].body.ProjectID)
	assert.Equal(t, []string{"t-7", "t-3"}, calls[0].body.Inputs)
	assert.False(t, calls[0].body.Parameters.ReturnOptions.InputText, "the input text is not echoed back")

	got := decodeEmbeddings(t, out)
	assert.Equal(t, "list", got.Object)
	assert.Equal(t, "ibm/granite-embedding-278m-multilingual", got.Model)
	require.Len(t, got.Data, 2)
	assert.Equal(t, "embedding", got.Data[0].Object)
	assert.Equal(t, 0, got.Data[0].Index)
	assert.JSONEq(t, `[7,0.5]`, string(got.Data[0].Embedding))
	assert.Equal(t, 1, got.Data[1].Index)
	assert.JSONEq(t, `[3,0.5]`, string(got.Data[1].Embedding))
	assert.Equal(t, 4, got.Usage.PromptTokens)
	assert.Equal(t, 4, got.Usage.TotalTokens)
}

func TestEmbeddings_SingleStringInput(t *testing.T) {
	iam := newFakeIAM(t)
	wx := newFakeEmbedder(t)
	c := testClient(iam)

	out, err := c.Embeddings(context.Background(), embedConfig(wx.srv.URL), []byte(`{"model":"m","input":"t-42"}`))
	require.NoError(t, err)
	assert.Equal(t, []string{"t-42"}, wx.recorded()[0].body.Inputs)
	got := decodeEmbeddings(t, out)
	require.Len(t, got.Data, 1)
	assert.JSONEq(t, `[42,0.5]`, string(got.Data[0].Embedding))
}

func TestEmbeddings_SplitsIntoCallsOfAThousandAndKeepsOrder(t *testing.T) {
	iam := newFakeIAM(t)
	wx := newFakeEmbedder(t)
	c := testClient(iam)

	inputs := make([]string, 2500)
	for i := range inputs {
		inputs[i] = fmt.Sprintf("t-%d", i)
	}
	body, err := json.Marshal(map[string]any{"model": "m", "input": inputs})
	require.NoError(t, err)

	out, err := c.Embeddings(context.Background(), embedConfig(wx.srv.URL), body)
	require.NoError(t, err)

	calls := wx.recorded()
	require.Len(t, calls, 3)
	assert.Len(t, calls[0].body.Inputs, 1000)
	assert.Len(t, calls[1].body.Inputs, 1000)
	assert.Len(t, calls[2].body.Inputs, 500)
	assert.Equal(t, "t-1000", calls[1].body.Inputs[0])
	assert.EqualValues(t, 1, iam.calls.Load(), "one IAM token serves every call")

	got := decodeEmbeddings(t, out)
	require.Len(t, got.Data, 2500)
	for _, i := range []int{0, 999, 1000, 1999, 2000, 2499} {
		assert.Equal(t, i, got.Data[i].Index)
		assert.JSONEq(t, fmt.Sprintf(`[%d,0.5]`, i), string(got.Data[i].Embedding))
	}
	assert.Equal(t, 5000, got.Usage.PromptTokens, "token counts of every call are summed")
}

func TestEmbeddings_Base64IsLittleEndianFloat32(t *testing.T) {
	iam := newFakeIAM(t)
	wx := newFakeEmbedder(t)
	c := testClient(iam)

	out, err := c.Embeddings(context.Background(), embedConfig(wx.srv.URL),
		[]byte(`{"model":"m","input":["t-3"],"encoding_format":"base64"}`))
	require.NoError(t, err)

	got := decodeEmbeddings(t, out)
	require.Len(t, got.Data, 1)
	var encoded string
	require.NoError(t, json.Unmarshal(got.Data[0].Embedding, &encoded), "a base64 embedding is a JSON string")
	raw, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	require.Len(t, raw, 8)
	assert.Equal(t, float32(3), math.Float32frombits(binary.LittleEndian.Uint32(raw[0:4])))
	assert.Equal(t, float32(0.5), math.Float32frombits(binary.LittleEndian.Uint32(raw[4:8])))
}

func TestEmbeddings_RefusesWhatWatsonxCannotServe(t *testing.T) {
	iam := newFakeIAM(t)
	wx := newFakeEmbedder(t)
	c := testClient(iam)

	cases := map[string]struct {
		body string
		want string
	}{
		"token array":       {`{"model":"m","input":[1,2,3]}`, "token arrays"},
		"batch of tokens":   {`{"model":"m","input":[[1,2],[3]]}`, "token arrays"},
		"empty array":       {`{"model":"m","input":[]}`, "must not be empty"},
		"missing input":     {`{"model":"m"}`, "input is required"},
		"dimensions":        {`{"model":"m","input":"t-1","dimensions":256}`, "dimensions is not supported"},
		"unknown encoding":  {`{"model":"m","input":"t-1","encoding_format":"int8"}`, "encoding_format"},
		"not a JSON object": {`["t-1"]`, "JSON object"},
		"malformed JSON":    {`{`, "JSON object"},
		"no model anywhere": {`{"input":"t-1"}`, "model is required"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := embedConfig(wx.srv.URL)
			if name == "no model anywhere" {
				cfg.Model = ""
			}
			_, err := c.Embeddings(context.Background(), cfg, []byte(tc.body))
			be, ok := registry.IsBackendError(err)
			require.True(t, ok, "%v", err)
			assert.Equal(t, http.StatusBadRequest, be.StatusCode)
			errObj := decode(t, be.Body)["error"].(map[string]any)
			assert.Equal(t, "invalid_request_error", errObj["type"])
			assert.Contains(t, errObj["message"], tc.want)
		})
	}
	assert.Empty(t, wx.recorded(), "a refused request never reaches watsonx.ai")
	assert.Zero(t, iam.calls.Load())
}

func TestEmbeddings_RelaysWatsonxErrorsInOpenAIShape(t *testing.T) {
	iam := newFakeIAM(t)
	wx := newFakeEmbedder(t)
	wx.status = http.StatusBadRequest
	wx.errorBody = `{"errors":[{"code":"invalid_input_argument","message":"Token sequence length exceeds the maximum of 512"}],"trace":"t-9","status_code":400}`
	c := testClient(iam)

	_, err := c.Embeddings(context.Background(), embedConfig(wx.srv.URL), []byte(`{"model":"m","input":"t-1"}`))
	be, ok := registry.IsBackendError(err)
	require.True(t, ok, "%v", err)
	assert.Equal(t, http.StatusBadRequest, be.StatusCode)
	errObj := decode(t, be.Body)["error"].(map[string]any)
	assert.Equal(t, "invalid_input_argument", errObj["code"])
	assert.Contains(t, errObj["message"], "exceeds the maximum of 512")
}

func TestEmbeddings_RetriesOnceWithFreshTokenOn401(t *testing.T) {
	iam := newFakeIAM(t)
	wx := newFakeEmbedder(t)
	wx.rejectN.Store(1)
	c := testClient(iam)

	_, err := c.Embeddings(context.Background(), embedConfig(wx.srv.URL), []byte(`{"model":"m","input":"t-1"}`))
	require.NoError(t, err)
	calls := wx.recorded()
	require.Len(t, calls, 2)
	assert.Equal(t, "Bearer token-1", calls[0].auth)
	assert.Equal(t, "Bearer token-2", calls[1].auth)
}

func TestEmbeddings_ShortResponseIsAnError(t *testing.T) {
	iam := newFakeIAM(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"results":[{"embedding":[1]}],"input_token_count":1}`)
	}))
	t.Cleanup(srv.Close)
	c := testClient(iam)

	_, err := c.Embeddings(context.Background(), embedConfig(srv.URL), []byte(`{"model":"m","input":["t-1","t-2"]}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1 vectors for 2 inputs")
}

func TestEmbeddings_GatewayReadsTheUsageForCost(t *testing.T) {
	iam := newFakeIAM(t)
	wx := newFakeEmbedder(t)
	c := testClient(iam)

	out, err := c.Embeddings(context.Background(), embedConfig(wx.srv.URL), []byte(`{"model":"m","input":["t-1","t-2","t-3"]}`))
	require.NoError(t, err)

	resp, err := adapter.NewRegistry().DecodeResponseFor(out, adapter.FormatOpenAIEmbeddings)
	require.NoError(t, err)
	require.NotNil(t, resp.Usage, "the proxy prices the call from these tokens")
	assert.Equal(t, 6, resp.Usage.InputTokens)
}

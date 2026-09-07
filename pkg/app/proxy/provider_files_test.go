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
	"net/url"
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

type filesTestClient struct {
	filesFn func(ctx context.Context, cfg *providers.Config, req providers.FilesRequest) (*providers.FilesResult, error)
}

func (c *filesTestClient) Completions(context.Context, *providers.Config, []byte) ([]byte, error) {
	return nil, nil
}

func (c *filesTestClient) CompletionsStream(context.Context, *providers.Config, []byte) (iter.Seq2[[]byte, error], error) {
	return nil, nil
}

func (c *filesTestClient) Files(ctx context.Context, cfg *providers.Config, req providers.FilesRequest) (*providers.FilesResult, error) {
	return c.filesFn(ctx, cfg, req)
}

func TestProviderInvoke_FilesPassthrough(t *testing.T) {
	var gotReq providers.FilesRequest
	client := &filesTestClient{
		filesFn: func(_ context.Context, _ *providers.Config, req providers.FilesRequest) (*providers.FilesResult, error) {
			gotReq = req
			return &providers.FilesResult{
				Body:        []byte(`{"id":"file-1","object":"file"}`),
				ContentType: "application/json",
			}, nil
		},
	}

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
	req := &infracontext.RequestContext{
		Method:          http.MethodPost,
		Path:            "/acme/v1/files",
		Body:            []byte("multipart-body"),
		Headers:         map[string][]string{"Content-Type": {"multipart/form-data; boundary=abc"}},
		SourceFormat:    string(adapter.FormatOpenAIFiles),
		ProxyCapability: "files",
		AllowedModels:   []string{"gpt-4"},
	}
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, string(adapter.FormatOpenAIFiles), req.TargetFormat)
	assert.Equal(t, http.MethodPost, gotReq.Method)
	assert.Equal(t, "/v1/files", gotReq.Path)
	assert.Equal(t, "multipart/form-data; boundary=abc", gotReq.ContentType)
	assert.Equal(t, []byte("multipart-body"), gotReq.Body)
	assert.JSONEq(t, `{"id":"file-1","object":"file"}`, string(resp.Body))
	assert.Equal(t, []string{"application/json"}, resp.Headers["Content-Type"])
}

func TestProviderInvoke_FilesContentPreservesContentType(t *testing.T) {
	client := &filesTestClient{
		filesFn: func(_ context.Context, _ *providers.Config, req providers.FilesRequest) (*providers.FilesResult, error) {
			assert.Equal(t, http.MethodGet, req.Method)
			assert.Equal(t, "/v1/files/file-1/content", req.Path)
			return &providers.FilesResult{
				Body:        []byte("pdf-bytes"),
				ContentType: "application/octet-stream",
			}, nil
		},
	}

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), &infracontext.RequestContext{
		Method:          http.MethodGet,
		Path:            "/acme/v1/files/file-1/content",
		Query:           url.Values{"purpose": []string{"assistants"}},
		SourceFormat:    string(adapter.FormatOpenAIFiles),
		ProxyCapability: "files",
	})

	require.NoError(t, err)
	assert.Equal(t, []byte("pdf-bytes"), resp.Body)
	assert.Equal(t, []string{"application/octet-stream"}, resp.Headers["Content-Type"])
}

func TestProviderInvoke_FilesInvalidMethod(t *testing.T) {
	client := &filesTestClient{
		filesFn: func(context.Context, *providers.Config, providers.FilesRequest) (*providers.FilesResult, error) {
			t.Fatal("upstream must not be called")
			return nil, nil
		},
	}

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
	_, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), &infracontext.RequestContext{
		Method:          http.MethodPost,
		Path:            "/acme/v1/files/file-1",
		SourceFormat:    string(adapter.FormatOpenAIFiles),
		ProxyCapability: "files",
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, appproxy.ErrInvalidRequestPayload)
}

func TestProviderInvoke_FilesUnsupportedClient(t *testing.T) {
	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(providermocks.NewClient(t), nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
	_, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), &infracontext.RequestContext{
		Method:          http.MethodGet,
		Path:            "/acme/v1/files",
		SourceFormat:    string(adapter.FormatOpenAIFiles),
		ProxyCapability: "files",
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, appproxy.ErrCapabilityNotSupported)
}

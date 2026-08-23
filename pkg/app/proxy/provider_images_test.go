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

type imagesTestClient struct {
	imagesFn func(ctx context.Context, cfg *providers.Config, req providers.ImagesRequest) (*providers.ImagesResult, error)
}

func (c *imagesTestClient) Completions(context.Context, *providers.Config, []byte) ([]byte, error) {
	return nil, nil
}

func (c *imagesTestClient) CompletionsStream(context.Context, *providers.Config, []byte) (iter.Seq2[[]byte, error], error) {
	return nil, nil
}

func (c *imagesTestClient) Images(ctx context.Context, cfg *providers.Config, req providers.ImagesRequest) (*providers.ImagesResult, error) {
	return c.imagesFn(ctx, cfg, req)
}

func TestProviderInvoke_ImagesPassthrough(t *testing.T) {
	var gotReq providers.ImagesRequest
	client := &imagesTestClient{
		imagesFn: func(_ context.Context, _ *providers.Config, req providers.ImagesRequest) (*providers.ImagesResult, error) {
			gotReq = req
			return &providers.ImagesResult{
				Body:        []byte(`{"created":1,"data":[{"url":"https://img"}]}`),
				ContentType: "application/json",
			}, nil
		},
	}

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
	req := &infracontext.RequestContext{
		Method:          http.MethodPost,
		Path:            "/acme/v1/images/generations",
		Body:            []byte(`{"model":"dall-e-3","prompt":"a cat"}`),
		Headers:         map[string][]string{"Content-Type": {"application/json"}},
		SourceFormat:    string(adapter.FormatOpenAIImages),
		ProxyCapability: "images",
		AllowedModels:   []string{"dall-e-3"},
	}
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, string(adapter.FormatOpenAIImages), req.TargetFormat)
	assert.Equal(t, http.MethodPost, gotReq.Method)
	assert.Equal(t, "/v1/images/generations", gotReq.Path)
	assert.Equal(t, "application/json", gotReq.ContentType)
	assert.JSONEq(t, `{"model":"dall-e-3","prompt":"a cat"}`, string(gotReq.Body))
	assert.JSONEq(t, `{"created":1,"data":[{"url":"https://img"}]}`, string(resp.Body))
	assert.Equal(t, "dall-e-3", resp.SentModel)
}

func TestProviderInvoke_ImagesInvalidMethod(t *testing.T) {
	client := &imagesTestClient{
		imagesFn: func(context.Context, *providers.Config, providers.ImagesRequest) (*providers.ImagesResult, error) {
			t.Fatal("upstream must not be called")
			return nil, nil
		},
	}

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
	_, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), &infracontext.RequestContext{
		Method:          http.MethodGet,
		Path:            "/acme/v1/images/generations",
		SourceFormat:    string(adapter.FormatOpenAIImages),
		ProxyCapability: "images",
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, appproxy.ErrInvalidRequestPayload)
}

func TestProviderInvoke_ImagesUnsupportedClient(t *testing.T) {
	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(providermocks.NewClient(t), nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
	_, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), &infracontext.RequestContext{
		Method:          http.MethodPost,
		Path:            "/acme/v1/images/generations",
		Body:            []byte(`{"model":"dall-e-3","prompt":"a cat"}`),
		SourceFormat:    string(adapter.FormatOpenAIImages),
		ProxyCapability: "images",
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, appproxy.ErrCapabilityNotSupported)
}

func TestProviderInvoke_ImagesModelNotAllowed(t *testing.T) {
	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(&imagesTestClient{}, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
	_, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), &infracontext.RequestContext{
		Method:          http.MethodPost,
		Path:            "/acme/v1/images/generations",
		Body:            []byte(`{"model":"dall-e-2","prompt":"a cat"}`),
		SourceFormat:    string(adapter.FormatOpenAIImages),
		ProxyCapability: "images",
		AllowedModels:   []string{"dall-e-3"},
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, appproxy.ErrModelNotAllowed)
}

func TestProviderInvoke_ImagesEditsMultipartPassthrough(t *testing.T) {
	var gotReq providers.ImagesRequest
	var gotModel string
	client := &imagesTestClient{
		imagesFn: func(_ context.Context, cfg *providers.Config, req providers.ImagesRequest) (*providers.ImagesResult, error) {
			gotReq = req
			gotModel = cfg.Model
			return &providers.ImagesResult{
				Body:        []byte(`{"created":1,"data":[{"b64_json":"abc"}]}`),
				ContentType: "application/json",
			}, nil
		},
	}

	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(client, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
	body := []byte("--abc\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\ndall-e-2\r\n--abc\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\nmake it blue\r\n--abc--\r\n")
	req := &infracontext.RequestContext{
		Method:          http.MethodPost,
		Path:            "/acme/v1/images/edits",
		Body:            body,
		Headers:         map[string][]string{"Content-Type": {"multipart/form-data; boundary=abc"}},
		SourceFormat:    string(adapter.FormatOpenAIImages),
		ProxyCapability: "images",
		AllowedModels:   []string{"dall-e-2"},
	}
	resp, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, http.MethodPost, gotReq.Method)
	assert.Equal(t, "/v1/images/edits", gotReq.Path)
	assert.Equal(t, "multipart/form-data; boundary=abc", gotReq.ContentType)
	assert.Equal(t, body, gotReq.Body)
	assert.Equal(t, "dall-e-2", gotModel)
	assert.Equal(t, "dall-e-2", resp.SentModel)
}

func TestProviderInvoke_ImagesMultipartModelNotAllowed(t *testing.T) {
	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get("openai").Return(&imagesTestClient{}, nil).Once()

	inv := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
	_, err := inv.Invoke(context.Background(), apiKeyTarget("openai"), &infracontext.RequestContext{
		Method:          http.MethodPost,
		Path:            "/acme/v1/images/edits",
		Body:            []byte("--abc\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\ndall-e-2\r\n--abc--\r\n"),
		Headers:         map[string][]string{"Content-Type": {"multipart/form-data; boundary=abc"}},
		SourceFormat:    string(adapter.FormatOpenAIImages),
		ProxyCapability: "images",
		AllowedModels:   []string{"dall-e-3"},
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, appproxy.ErrModelNotAllowed)
}

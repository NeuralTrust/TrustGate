package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	domainUpstream "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	infrahttpx "github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	factoryMocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory/mocks"
	providerMocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/valyala/fasthttp"
)

var upstreamErrorJSON = map[string]any{
	"error": map[string]any{
		"message": "Missing required parameter: 'model'.",
		"type":    "invalid_request_error",
		"param":   "model",
		"code":    "missing_required_parameter",
	},
}

func mustMarshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func newFiberCtx(t *testing.T) (*fiber.App, *fiber.Ctx) {
	t.Helper()
	app := fiber.New()
	ctx := app.AcquireCtx(&fasthttp.RequestCtx{})
	t.Cleanup(func() { app.ReleaseCtx(ctx) })
	return app, ctx
}

func newHandlerWithPassthrough(t *testing.T, passthrough bool, locator *factoryMocks.ProviderLocator) *forwardedHandler {
	t.Helper()
	return &forwardedHandler{
		logger:          logrus.New(),
		providerLocator: locator,
		adapterRegistry: adapter.NewRegistry(),
		cfg: &config.Config{
			Upstream: config.UpstreamConfig{
				ErrorPassthrough: passthrough,
				StreamTimeout:    10 * time.Second,
				ReadTimeout:      10 * time.Second,
				WriteTimeout:     10 * time.Second,
			},
		},
	}
}

func setupProviderMocks(t *testing.T) (*factoryMocks.ProviderLocator, *providerMocks.Client) {
	t.Helper()
	locator := factoryMocks.NewProviderLocator(t)
	client := providerMocks.NewClient(t)
	locator.EXPECT().Get("openai").Return(client, nil)
	return locator, client
}

func newErrorUpstreamServer(t *testing.T) (*httptest.Server, string, int) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(upstreamErrorJSON)
	}))
	t.Cleanup(ts.Close)
	u, _ := url.Parse(ts.URL)
	port, _ := strconv.Atoi(u.Port())
	return ts, u.Hostname(), port
}

// --- Case 1: Provider + Non-Stream ---

func TestErrorPassthrough_ProviderNonStream(t *testing.T) {
	upstreamBody := mustMarshal(upstreamErrorJSON)

	t.Run("passthrough_enabled_returns_upstream_response", func(t *testing.T) {
		locator, client := setupProviderMocks(t)
		client.EXPECT().
			Completions(mock.Anything, mock.Anything, mock.Anything).
			Return(nil, domainUpstream.NewUpstreamError(http.StatusBadRequest, upstreamBody))

		h := newHandlerWithPassthrough(t, true, locator)
		_, fCtx := newFiberCtx(t)

		req := &types.RequestContext{
			C:            fCtx,
			Context:      context.Background(),
			Body:         []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`),
			SourceFormat: "openai",
		}
		target := &types.UpstreamTargetDTO{Provider: "openai"}

		resp, err := h.handlerProviderResponse(req, target)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, upstreamBody, resp.Body)
	})

	t.Run("passthrough_disabled_wraps_error", func(t *testing.T) {
		locator, client := setupProviderMocks(t)
		client.EXPECT().
			Completions(mock.Anything, mock.Anything, mock.Anything).
			Return(nil, domainUpstream.NewUpstreamError(http.StatusBadRequest, upstreamBody))

		h := newHandlerWithPassthrough(t, false, locator)
		_, fCtx := newFiberCtx(t)

		req := &types.RequestContext{
			C:            fCtx,
			Context:      context.Background(),
			Body:         []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`),
			SourceFormat: "openai",
		}
		target := &types.UpstreamTargetDTO{Provider: "openai"}

		resp, err := h.handlerProviderResponse(req, target)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "failed to get completions")
	})
}

// --- Case 2: Provider + Stream ---
// Uses app.Test() for a real fiber context (fasthttp.RequestCtx.Done requires a server).

func TestErrorPassthrough_ProviderStream(t *testing.T) {
	upstreamBody := mustMarshal(upstreamErrorJSON)

	t.Run("passthrough_enabled_returns_upstream_response", func(t *testing.T) {
		locator, client := setupProviderMocks(t)
		client.EXPECT().
			CompletionsStream(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(domainUpstream.NewUpstreamError(http.StatusBadRequest, upstreamBody))

		var testResp *types.ResponseContext
		var testErr error

		app := fiber.New()
		app.Post("/test", func(c *fiber.Ctx) error {
			streamResponse := make(chan []byte, 1)
			reqCtx := &types.RequestContext{
				C:            c,
				Context:      context.Background(),
				Body:         []byte(`{"model":"gpt-4","stream":true,"messages":[{"role":"user","content":"hello"}]}`),
				SourceFormat: "openai",
			}
			target := &types.UpstreamTargetDTO{Provider: "openai"}
			testResp, testErr = infrahttpx.HandleProviderStream(
				logrus.New(), locator, adapter.NewRegistry(),
				reqCtx, target, streamResponse, true,
			)
			return nil
		})

		httpReq := httptest.NewRequest("POST", "/test", bytes.NewReader([]byte(`{}`)))
		_, err := app.Test(httpReq, -1)
		assert.NoError(t, err)

		assert.NoError(t, testErr)
		assert.NotNil(t, testResp)
		assert.Equal(t, http.StatusBadRequest, testResp.StatusCode)
		assert.Equal(t, upstreamBody, testResp.Body)
	})

	t.Run("passthrough_disabled_wraps_error", func(t *testing.T) {
		locator, client := setupProviderMocks(t)
		client.EXPECT().
			CompletionsStream(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(domainUpstream.NewUpstreamError(http.StatusBadRequest, upstreamBody))

		var testResp *types.ResponseContext
		var testErr error

		app := fiber.New()
		app.Post("/test", func(c *fiber.Ctx) error {
			streamResponse := make(chan []byte, 1)
			reqCtx := &types.RequestContext{
				C:            c,
				Context:      context.Background(),
				Body:         []byte(`{"model":"gpt-4","stream":true,"messages":[{"role":"user","content":"hello"}]}`),
				SourceFormat: "openai",
			}
			target := &types.UpstreamTargetDTO{Provider: "openai"}
			testResp, testErr = infrahttpx.HandleProviderStream(
				logrus.New(), locator, adapter.NewRegistry(),
				reqCtx, target, streamResponse, false,
			)
			return nil
		})

		httpReq := httptest.NewRequest("POST", "/test", bytes.NewReader([]byte(`{}`)))
		_, err := app.Test(httpReq, -1)
		assert.NoError(t, err)

		assert.Error(t, testErr)
		assert.Nil(t, testResp)
		assert.Contains(t, testErr.Error(), "failed to stream request")
	})
}

// --- Case 3: Non-Provider + Stream ---

func TestErrorPassthrough_NonProviderStream(t *testing.T) {
	_, host, port := newErrorUpstreamServer(t)

	t.Run("HandleHTTPStream_returns_upstream_error_type", func(t *testing.T) {
		_, fCtx := newFiberCtx(t)
		streamResponse := make(chan []byte, 1)

		req := &types.RequestContext{
			C:       fCtx,
			Context: context.Background(),
			Method:  "POST",
			Body:    []byte(`{"key":"value"}`),
			Headers: map[string][]string{"Content-Type": {"application/json"}},
		}
		target := &types.UpstreamTargetDTO{Stream: true}
		upstreamURL := "http://" + host + ":" + strconv.Itoa(port) + "/test"

		resp, err := infrahttpx.HandleHTTPStream(
			logrus.New(), &http.Client{Timeout: 10 * time.Second},
			upstreamURL, req, target, streamResponse,
		)

		assert.Nil(t, resp)
		assert.Error(t, err)

		ue, ok := domainUpstream.IsUpstreamError(err)
		assert.True(t, ok, "expected UpstreamError type")
		assert.Equal(t, http.StatusBadRequest, ue.StatusCode)
		assert.NotEmpty(t, ue.Body)
	})

	t.Run("doForwardRequest_propagates_upstream_error", func(t *testing.T) {
		h := &forwardedHandler{
			logger: logrus.New(),
			cfg: &config.Config{
				Upstream: config.UpstreamConfig{
					ErrorPassthrough: true,
					StreamTimeout:    10 * time.Second,
				},
			},
		}
		_, fCtx := newFiberCtx(t)
		streamResponse := make(chan []byte, 1)

		dto := &forwardedRequestDTO{
			req: &types.RequestContext{
				C:       fCtx,
				Context: context.Background(),
				Method:  "POST",
				Body:    []byte(`{"key":"value"}`),
				Headers: map[string][]string{"Content-Type": {"application/json"}},
			},
			target: &types.UpstreamTargetDTO{
				Protocol: "http",
				Host:     host,
				Port:     port,
				Path:     "/test",
				Stream:   true,
			},
			streamResponse: streamResponse,
		}

		_, err := h.doForwardRequest(context.Background(), dto)

		assert.Error(t, err)
		ue, ok := domainUpstream.IsUpstreamError(err)
		assert.True(t, ok, "expected UpstreamError to propagate from doForwardRequest")
		assert.Equal(t, http.StatusBadRequest, ue.StatusCode)
		assert.NotEmpty(t, ue.Body)
	})
}

// --- Case 4: Non-Provider + Non-Stream ---

func TestErrorPassthrough_NonProviderNonStream(t *testing.T) {
	_, host, port := newErrorUpstreamServer(t)

	t.Run("always_transparent_regardless_of_flag", func(t *testing.T) {
		for _, passthrough := range []bool{true, false} {
			t.Run("passthrough_"+strconv.FormatBool(passthrough), func(t *testing.T) {
				h := &forwardedHandler{
					logger: logrus.New(),
					cfg: &config.Config{
						Upstream: config.UpstreamConfig{
							ErrorPassthrough: passthrough,
							ReadTimeout:      10 * time.Second,
							WriteTimeout:     10 * time.Second,
						},
					},
					client: &fasthttp.Client{
						ReadTimeout:  10 * time.Second,
						WriteTimeout: 10 * time.Second,
					},
				}
				_, fCtx := newFiberCtx(t)

				dto := &forwardedRequestDTO{
					req: &types.RequestContext{
						C:       fCtx,
						Context: context.Background(),
						Method:  "POST",
						Body:    []byte(`{"key":"value"}`),
						Headers: map[string][]string{"Content-Type": {"application/json"}},
					},
					target: &types.UpstreamTargetDTO{
						Protocol: "http",
						Host:     host,
						Port:     port,
						Path:     "/test",
					},
				}

				resp, err := h.doForwardRequest(context.Background(), dto)

				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
				assert.NotEmpty(t, resp.Body)
			})
		}
	})
}

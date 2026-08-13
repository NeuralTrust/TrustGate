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

package oauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	appoauthmocks "github.com/NeuralTrust/TrustGate/pkg/app/oauth/mocks"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
)

const apiKeyConnectTestSecret = "raw-super-secret-key"

type gatewayResolverFunc func(*fiber.Ctx) (*gatewaydomain.Gateway, error)

func (f gatewayResolverFunc) Resolve(c *fiber.Ctx) (*gatewaydomain.Gateway, error) {
	return f(c)
}

func TestAPIKeyConnectHandlerGet_RendersValidatedTarget(t *testing.T) {
	t.Parallel()

	gateway := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	service := appoauthmocks.NewAPIKeyConnectService(t)
	service.EXPECT().
		ValidateTarget(mock.Anything, gateway.ID, "tools").
		Return(nil).
		Once()
	handler := NewAPIKeyConnectHandler(
		gatewayResolverFunc(func(c *fiber.Ctx) (*gatewaydomain.Gateway, error) {
			if got := string(c.Request().Host()); got != "acme.mcp.example.com" {
				t.Fatalf("Host = %q, want direct request host", got)
			}
			return gateway, nil
		}),
		service,
	)

	res := performAPIKeyConnectRequest(t, handler, fiber.MethodGet, "/tools/connect", "", "")
	body := readAPIKeyConnectBody(t, res)

	if res.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want %d", res.StatusCode, fiber.StatusOK)
	}
	if !strings.Contains(body, `action="/tools/connect"`) {
		t.Fatalf("form action missing from body: %s", body)
	}
	if !strings.Contains(body, `type="password"`) || strings.Contains(body, `value=`) {
		t.Fatalf("form does not preserve blank password behavior: %s", body)
	}
	assertAPIKeyConnectNoStore(t, res)
	assertAPIKeyConnectSecretAbsent(t, res, body)
}

func TestAPIKeyConnectHandlerGet_StatusMapping(t *testing.T) {
	t.Parallel()

	operationalErr := errors.New("dependency unavailable")
	tests := []struct {
		name       string
		resolveErr error
		targetErr  error
		wantStatus int
	}{
		{
			name:       "invalid host",
			resolveErr: appauth.ErrInvalidAuthRequest,
			wantStatus: fiber.StatusNotFound,
		},
		{
			name:       "unknown target",
			targetErr:  appoauth.ErrAPIKeyConnectUnauthorized,
			wantStatus: fiber.StatusNotFound,
		},
		{
			name:       "resolver failure",
			resolveErr: operationalErr,
			wantStatus: fiber.StatusInternalServerError,
		},
		{
			name:       "target dependency failure",
			targetErr:  operationalErr,
			wantStatus: fiber.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gateway := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind]()}
			service := appoauthmocks.NewAPIKeyConnectService(t)
			if tt.resolveErr == nil {
				service.EXPECT().
					ValidateTarget(mock.Anything, gateway.ID, "tools").
					Return(tt.targetErr).
					Once()
			}
			handler := NewAPIKeyConnectHandler(
				gatewayResolverFunc(func(*fiber.Ctx) (*gatewaydomain.Gateway, error) {
					return gateway, tt.resolveErr
				}),
				service,
			)

			res := performAPIKeyConnectRequest(t, handler, fiber.MethodGet, "/tools/connect", "", "")
			body := readAPIKeyConnectBody(t, res)

			if res.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", res.StatusCode, tt.wantStatus)
			}
			if body != http.StatusText(tt.wantStatus) {
				t.Fatalf("body = %q, want generic %q", body, http.StatusText(tt.wantStatus))
			}
			assertAPIKeyConnectNoStore(t, res)
			assertAPIKeyConnectSecretAbsent(t, res, body)
		})
	}
}

func TestAPIKeyConnectHandlerPost_UsesBodyOnlyAfterHostResolution(t *testing.T) {
	t.Parallel()

	gateway := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind]()}
	events := make([]string, 0, 2)
	service := appoauthmocks.NewAPIKeyConnectService(t)
	service.EXPECT().
		CreateTicket(mock.Anything, gateway.ID, "tools", apiKeyConnectTestSecret).
		Run(func(context.Context, ids.GatewayID, string, string) {
			events = append(events, "create-ticket")
			if len(events) != 2 || events[0] != "resolve-host" {
				t.Fatalf("call order = %v, want host resolution before service", events)
			}
		}).
		Return("ticket value&?", nil).
		Once()
	handler := NewAPIKeyConnectHandler(
		gatewayResolverFunc(func(*fiber.Ctx) (*gatewaydomain.Gateway, error) {
			events = append(events, "resolve-host")
			return gateway, nil
		}),
		service,
	)

	res := performAPIKeyConnectRequest(
		t,
		handler,
		fiber.MethodPost,
		"/tools/connect?api_key=query-secret",
		fiber.MIMEApplicationForm+"; charset=UTF-8",
		"api_key="+apiKeyConnectTestSecret,
	)
	body := readAPIKeyConnectBody(t, res)

	if res.StatusCode != fiber.StatusSeeOther {
		t.Fatalf("status = %d, want %d", res.StatusCode, fiber.StatusSeeOther)
	}
	if got, want := res.Header.Get(fiber.HeaderLocation), "/tools/mcp/connect?ticket=ticket+value%26%3F"; got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
	assertAPIKeyConnectNoStore(t, res)
	assertAPIKeyConnectSecretAbsent(t, res, body)
}

func TestAPIKeyConnectHandlerPost_IgnoresQueryAndHeaderCredentials(t *testing.T) {
	t.Parallel()

	gateway := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind]()}
	service := appoauthmocks.NewAPIKeyConnectService(t)
	service.EXPECT().
		CreateTicket(mock.Anything, gateway.ID, "tools", "").
		Return("", appoauth.ErrAPIKeyConnectUnauthorized).
		Once()
	handler := NewAPIKeyConnectHandler(
		gatewayResolverFunc(func(*fiber.Ctx) (*gatewaydomain.Gateway, error) {
			return gateway, nil
		}),
		service,
	)

	app := apiKeyConnectTestApp(handler)
	req := httptest.NewRequest(
		fiber.MethodPost,
		"/tools/connect?api_key=query-secret",
		strings.NewReader("other=value"),
	)
	req.Host = "acme.mcp.example.com"
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationForm)
	req.Header.Set("X-AG-API-Key", "header-secret")
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	body := readAPIKeyConnectBody(t, res)

	if res.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", res.StatusCode, fiber.StatusUnauthorized)
	}
	assertAPIKeyConnectNoStore(t, res)
	assertAPIKeyConnectSecretAbsent(t, res, body)
}

func TestAPIKeyConnectHandlerPost_AcceptsRepeatedParametersAtBodyLimit(t *testing.T) {
	t.Parallel()

	gateway := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind]()}
	service := appoauthmocks.NewAPIKeyConnectService(t)
	service.EXPECT().
		CreateTicket(mock.Anything, gateway.ID, "tools", apiKeyConnectTestSecret).
		Return("bounded-ticket", nil).
		Once()
	handler := NewAPIKeyConnectHandler(
		gatewayResolverFunc(func(*fiber.Ctx) (*gatewaydomain.Gateway, error) {
			return gateway, nil
		}),
		service,
	)

	res := performAPIKeyConnectRequest(
		t,
		handler,
		fiber.MethodPost,
		"/tools/connect",
		fiber.MIMEApplicationForm,
		apiKeyConnectFormAtLimit(t),
	)
	body := readAPIKeyConnectBody(t, res)

	if res.StatusCode != fiber.StatusSeeOther {
		t.Fatalf("status = %d, want %d", res.StatusCode, fiber.StatusSeeOther)
	}
	if got, want := res.Header.Get(fiber.HeaderLocation), "/tools/mcp/connect?ticket=bounded-ticket"; got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
	assertAPIKeyConnectNoStore(t, res)
	assertAPIKeyConnectSecretAbsent(t, res, body)
}

func TestAPIKeyConnectHandlerPost_RejectsBodyAboveLimitBeforeLookup(t *testing.T) {
	t.Parallel()

	resolverCalled := false
	service := appoauthmocks.NewAPIKeyConnectService(t)
	handler := NewAPIKeyConnectHandler(
		gatewayResolverFunc(func(*fiber.Ctx) (*gatewaydomain.Gateway, error) {
			resolverCalled = true
			return &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind]()}, nil
		}),
		service,
	)

	oversizedBody := apiKeyConnectFormAtLimit(t) + "x"
	res := performAPIKeyConnectRequest(
		t,
		handler,
		fiber.MethodPost,
		"/tools/connect",
		fiber.MIMEApplicationForm,
		oversizedBody,
	)
	body := readAPIKeyConnectBody(t, res)

	if res.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("status = %d, want %d", res.StatusCode, fiber.StatusBadRequest)
	}
	if body != http.StatusText(fiber.StatusBadRequest) {
		t.Fatalf("body = %q, want generic %q", body, http.StatusText(fiber.StatusBadRequest))
	}
	if resolverCalled {
		t.Fatal("gateway resolver was called for an oversized form")
	}
	assertAPIKeyConnectNoStore(t, res)
	assertAPIKeyConnectSecretAbsent(t, res, body)
}

func TestAPIKeyConnectHandlerPost_StatusMapping(t *testing.T) {
	t.Parallel()

	operationalErr := errors.New("dependency failed with " + apiKeyConnectTestSecret)
	tests := []struct {
		name        string
		contentType string
		body        string
		resolveErr  error
		serviceErr  error
		wantStatus  int
	}{
		{
			name:        "unsupported media type",
			contentType: fiber.MIMEApplicationJSON,
			body:        `{"api_key":"` + apiKeyConnectTestSecret + `"}`,
			wantStatus:  fiber.StatusUnsupportedMediaType,
		},
		{
			name:        "malformed media type",
			contentType: fiber.MIMEApplicationForm + "; charset=",
			body:        "api_key=" + apiKeyConnectTestSecret,
			wantStatus:  fiber.StatusUnsupportedMediaType,
		},
		{
			name:        "malformed form",
			contentType: fiber.MIMEApplicationForm,
			body:        "api_key=%zz",
			wantStatus:  fiber.StatusBadRequest,
		},
		{
			name:        "invalid host",
			contentType: fiber.MIMEApplicationForm,
			body:        "api_key=" + apiKeyConnectTestSecret,
			resolveErr:  appauth.ErrInvalidAuthRequest,
			wantStatus:  fiber.StatusUnauthorized,
		},
		{
			name:        "authorization miss",
			contentType: fiber.MIMEApplicationForm,
			body:        "api_key=" + apiKeyConnectTestSecret,
			serviceErr:  appoauth.ErrAPIKeyConnectUnauthorized,
			wantStatus:  fiber.StatusUnauthorized,
		},
		{
			name:        "resolver failure",
			contentType: fiber.MIMEApplicationForm,
			body:        "api_key=" + apiKeyConnectTestSecret,
			resolveErr:  operationalErr,
			wantStatus:  fiber.StatusInternalServerError,
		},
		{
			name:        "ticket dependency failure",
			contentType: fiber.MIMEApplicationForm,
			body:        "api_key=" + apiKeyConnectTestSecret,
			serviceErr:  operationalErr,
			wantStatus:  fiber.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gateway := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind]()}
			service := appoauthmocks.NewAPIKeyConnectService(t)
			if tt.wantStatus != fiber.StatusUnsupportedMediaType &&
				tt.wantStatus != fiber.StatusBadRequest &&
				tt.resolveErr == nil {
				service.EXPECT().
					CreateTicket(mock.Anything, gateway.ID, "tools", apiKeyConnectTestSecret).
					Return("", tt.serviceErr).
					Once()
			}
			handler := NewAPIKeyConnectHandler(
				gatewayResolverFunc(func(*fiber.Ctx) (*gatewaydomain.Gateway, error) {
					return gateway, tt.resolveErr
				}),
				service,
			)

			res := performAPIKeyConnectRequest(
				t,
				handler,
				fiber.MethodPost,
				"/tools/connect",
				tt.contentType,
				tt.body,
			)
			body := readAPIKeyConnectBody(t, res)

			if res.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", res.StatusCode, tt.wantStatus)
			}
			if body != http.StatusText(tt.wantStatus) {
				t.Fatalf("body = %q, want generic %q", body, http.StatusText(tt.wantStatus))
			}
			assertAPIKeyConnectNoStore(t, res)
			assertAPIKeyConnectSecretAbsent(t, res, body)
		})
	}
}

func TestAPIKeyConnectHandlerPost_AuthorizationMissesAreIndistinguishable(t *testing.T) {
	t.Parallel()

	gateway := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind]()}
	invalidHostHandler := NewAPIKeyConnectHandler(
		gatewayResolverFunc(func(*fiber.Ctx) (*gatewaydomain.Gateway, error) {
			return nil, appauth.ErrInvalidAuthRequest
		}),
		appoauthmocks.NewAPIKeyConnectService(t),
	)
	service := appoauthmocks.NewAPIKeyConnectService(t)
	service.EXPECT().
		CreateTicket(mock.Anything, gateway.ID, "tools", apiKeyConnectTestSecret).
		Return("", appoauth.ErrAPIKeyConnectUnauthorized).
		Once()
	invalidKeyHandler := NewAPIKeyConnectHandler(
		gatewayResolverFunc(func(*fiber.Ctx) (*gatewaydomain.Gateway, error) {
			return gateway, nil
		}),
		service,
	)

	hostMiss := performAPIKeyConnectRequest(
		t,
		invalidHostHandler,
		fiber.MethodPost,
		"/tools/connect",
		fiber.MIMEApplicationForm,
		"api_key="+apiKeyConnectTestSecret,
	)
	keyMiss := performAPIKeyConnectRequest(
		t,
		invalidKeyHandler,
		fiber.MethodPost,
		"/tools/connect",
		fiber.MIMEApplicationForm,
		"api_key="+apiKeyConnectTestSecret,
	)
	hostBody := readAPIKeyConnectBody(t, hostMiss)
	keyBody := readAPIKeyConnectBody(t, keyMiss)

	if hostMiss.StatusCode != keyMiss.StatusCode || hostBody != keyBody {
		t.Fatalf(
			"authorization misses differ: host=(%d,%q) key=(%d,%q)",
			hostMiss.StatusCode,
			hostBody,
			keyMiss.StatusCode,
			keyBody,
		)
	}
}

func apiKeyConnectTestApp(handler *APIKeyConnectHandler) *fiber.App {
	app := fiber.New()
	app.Get("/:slug/connect", handler.Get)
	app.Post("/:slug/connect", handler.Post)
	return app
}

func performAPIKeyConnectRequest(
	t *testing.T,
	handler *APIKeyConnectHandler,
	method string,
	target string,
	contentType string,
	body string,
) *http.Response {
	t.Helper()

	app := apiKeyConnectTestApp(handler)
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = "acme.mcp.example.com"
	if contentType != "" {
		req.Header.Set(fiber.HeaderContentType, contentType)
	}
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return res
}

func readAPIKeyConnectBody(t *testing.T, res *http.Response) string {
	t.Helper()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatalf("close response body: %v", err)
	}
	return string(body)
}

func assertAPIKeyConnectNoStore(t *testing.T, res *http.Response) {
	t.Helper()

	if got := res.Header.Get(fiber.HeaderCacheControl); !strings.Contains(got, "no-store") {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func assertAPIKeyConnectSecretAbsent(t *testing.T, res *http.Response, body string) {
	t.Helper()

	if strings.Contains(body, apiKeyConnectTestSecret) {
		t.Fatalf("response body contains API key: %q", body)
	}
	for name, values := range res.Header {
		for _, value := range values {
			if strings.Contains(value, apiKeyConnectTestSecret) {
				t.Fatalf("response header %s contains API key", name)
			}
		}
	}
}

func apiKeyConnectFormAtLimit(t *testing.T) string {
	t.Helper()

	var body strings.Builder
	body.Grow(apiKeyConnectMaxFormBodyBytes)
	body.WriteString("api_key=" + apiKeyConnectTestSecret + "&api_key=ignored&")
	for body.Len()+len("noise=x&")+len("padding=") <= apiKeyConnectMaxFormBodyBytes {
		body.WriteString("noise=x&")
	}
	body.WriteString("padding=")
	body.WriteString(strings.Repeat("z", apiKeyConnectMaxFormBodyBytes-body.Len()))
	if body.Len() != apiKeyConnectMaxFormBodyBytes {
		t.Fatalf("form body length = %d, want %d", body.Len(), apiKeyConnectMaxFormBodyBytes)
	}
	return body.String()
}

var _ resolver.GatewayResolver = gatewayResolverFunc(nil)

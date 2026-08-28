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
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/gofiber/fiber/v2"
)

type stubConnectService struct {
	page        *appoauth.ConnectPage
	err         error
	gotProvider string
	gotBaseURL  string
}

func (s *stubConnectService) CreateTicket(context.Context, ids.GatewayID, string, string) (string, error) {
	return "t", nil
}

func (s *stubConnectService) CreateAPIKeyTicket(
	context.Context,
	ids.GatewayID,
	string,
	string,
	ids.ConsumerID,
	ids.AuthID,
	[]string,
) (string, error) {
	return "t", nil
}

func (s *stubConnectService) Page(context.Context, string) (*appoauth.ConnectPage, error) {
	return s.page, s.err
}

func (s *stubConnectService) Statuses(context.Context, ids.GatewayID, string, string) ([]appoauth.ProviderStatus, error) {
	return nil, nil
}

func (s *stubConnectService) Start(_ context.Context, baseURL, _, provider string) (string, error) {
	s.gotBaseURL = baseURL
	s.gotProvider = provider
	return "https://github.com/login/oauth/authorize?x=1", nil
}

func (s *stubConnectService) Callback(_ context.Context, baseURL, _, _, _, _, _ string) (string, error) {
	s.gotBaseURL = baseURL
	return "t", nil
}

func (s *stubConnectService) Disconnect(context.Context, string, string) error { return nil }

func (s *stubConnectService) RefreshAuth(context.Context, ids.GatewayID, *registrydomain.Registry) (*registrydomain.MCPAuth, error) {
	return nil, nil
}

func (s *stubConnectService) ChainURL(context.Context, string, ids.GatewayID, string, string, string) (string, error) {
	return "", nil
}

func TestConnectPage_RouteMatchesNestedConsumerPaths(t *testing.T) {
	t.Parallel()
	h := NewConnectHandler(&stubConnectService{page: &appoauth.ConnectPage{
		ConsumerPath: "/v1/mcp/dev",
		Providers:    []appoauth.ProviderStatus{{Provider: "github", Registry: "github-mcp"}},
	}}, nil, "")
	app := fiber.New()
	app.Get("/+/connect", h.Page)

	res, err := app.Test(httptest.NewRequest("GET", "/v1/mcp/dev/connect?ticket=abc", nil))
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	if res.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "github") || !strings.Contains(string(body), "/oauth/connect/github?ticket=abc") {
		t.Fatalf("page body missing provider button: %s", body)
	}
}

func TestConnectPage_MissingTicketIs401(t *testing.T) {
	t.Parallel()
	h := NewConnectHandler(&stubConnectService{}, nil, "")
	app := fiber.New()
	app.Get("/+/connect", h.Page)
	res, err := app.Test(httptest.NewRequest("GET", "/v1/mcp/dev/connect", nil))
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	if res.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
}

func TestConnectPage_ExpiredTicketIs401(t *testing.T) {
	t.Parallel()
	h := NewConnectHandler(&stubConnectService{err: appoauth.ErrTicketNotFound}, nil, "")
	app := fiber.New()
	app.Get("/+/connect", h.Page)
	res, err := app.Test(httptest.NewRequest("GET", "/x/connect?ticket=stale", nil))
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	if res.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
}

func TestConnectStart_RedirectsToProvider(t *testing.T) {
	t.Parallel()
	h := NewConnectHandler(&stubConnectService{}, nil, "")
	app := fiber.New()
	app.Get(ConnectStartPath, h.Start)
	res, err := app.Test(httptest.NewRequest("GET", "/oauth/connect/github?ticket=abc", nil))
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	if res.StatusCode != fiber.StatusFound {
		t.Fatalf("status = %d, want 302", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); !strings.HasPrefix(loc, "https://github.com/") {
		t.Fatalf("Location = %q", loc)
	}
}

func TestConnectStart_ProviderWithSlash(t *testing.T) {
	t.Parallel()
	stub := &stubConnectService{}
	h := NewConnectHandler(stub, nil, "")
	app := fiber.New()
	app.Get(ConnectStartPath, h.Start)
	res, err := app.Test(httptest.NewRequest("GET", "/oauth/connect/app.linear/mcp?ticket=abc", nil))
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	if res.StatusCode != fiber.StatusFound {
		t.Fatalf("status = %d, want 302", res.StatusCode)
	}
	if stub.gotProvider != "app.linear/mcp" {
		t.Fatalf("provider = %q, want app.linear/mcp", stub.gotProvider)
	}
}

func TestConnectStart_UsesConfiguredPublicBaseURL(t *testing.T) {
	t.Parallel()
	stub := &stubConnectService{}
	h := NewConnectHandler(stub, nil, "https://oauth.mcp.example.com/")
	app := fiber.New()
	app.Get(ConnectStartPath, h.Start)
	req := httptest.NewRequest("GET", "/oauth/connect/com.google.workspace/calendar?ticket=abc", nil)
	req.Host = "gw-tenant.mcp.example.com"
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	if res.StatusCode != fiber.StatusFound {
		t.Fatalf("status = %d, want 302", res.StatusCode)
	}
	if stub.gotBaseURL != "https://oauth.mcp.example.com" {
		t.Fatalf("baseURL = %q, want fixed public base", stub.gotBaseURL)
	}
	if stub.gotProvider != "com.google.workspace/calendar" {
		t.Fatalf("provider = %q", stub.gotProvider)
	}
}

func TestConnectCallback_UsesConfiguredPublicBaseURL(t *testing.T) {
	t.Parallel()
	stub := &stubConnectService{page: &appoauth.ConnectPage{
		ConsumerPath: "/tools/mcp",
		Providers:    []appoauth.ProviderStatus{{Provider: "github", Registry: "g", Linked: true}},
	}}
	h := NewConnectHandler(stub, nil, "https://oauth.mcp.example.com")
	app := fiber.New()
	app.Get(ConnectCallbackPath, h.Callback)
	req := httptest.NewRequest("GET", "/oauth/callback/github?state=s&code=c", nil)
	req.Host = "gw-tenant.mcp.example.com"
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	if res.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if stub.gotBaseURL != "https://oauth.mcp.example.com" {
		t.Fatalf("baseURL = %q, want fixed public base", stub.gotBaseURL)
	}
}

func TestConnectStart_FallsBackToRequestBaseURL(t *testing.T) {
	t.Parallel()
	stub := &stubConnectService{}
	h := NewConnectHandler(stub, nil, "")
	app := fiber.New()
	app.Get(ConnectStartPath, h.Start)
	req := httptest.NewRequest("GET", "/oauth/connect/github?ticket=abc", nil)
	req.Host = "gw-tenant.mcp.example.com"
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	if res.StatusCode != fiber.StatusFound {
		t.Fatalf("status = %d, want 302", res.StatusCode)
	}
	if stub.gotBaseURL != "http://gw-tenant.mcp.example.com" {
		t.Fatalf("baseURL = %q, want request origin", stub.gotBaseURL)
	}
}

package oauth

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/gofiber/fiber/v2"
)

type stubConnectService struct {
	page *appoauth.ConnectPage
	err  error
}

func (s *stubConnectService) CreateTicket(context.Context, ids.GatewayID, string, string) (string, error) {
	return "t", nil
}

func (s *stubConnectService) Page(context.Context, string) (*appoauth.ConnectPage, error) {
	return s.page, s.err
}

func (s *stubConnectService) Start(context.Context, string, string, string) (string, error) {
	return "https://github.com/login/oauth/authorize?x=1", nil
}

func (s *stubConnectService) Callback(context.Context, string, string, string, string, string, string) (string, error) {
	return "t", nil
}

func (s *stubConnectService) Disconnect(context.Context, string, string) error { return nil }

func (s *stubConnectService) RefreshAuth(context.Context, ids.GatewayID, *registrydomain.Registry) (*registrydomain.MCPAuth, error) {
	return nil, nil
}

func (s *stubConnectService) ChainURL(context.Context, string, ids.GatewayID, string, string, string) (string, error) {
	return "", nil
}

// The connect page route uses Fiber's greedy "+" wildcard so it works for any
// consumer path depth ({consumer_path}/connect).
func TestConnectPage_RouteMatchesNestedConsumerPaths(t *testing.T) {
	t.Parallel()
	h := NewConnectHandler(&stubConnectService{page: &appoauth.ConnectPage{
		ConsumerPath: "/v1/mcp/dev",
		Providers:    []appoauth.ProviderStatus{{Provider: "github", Registry: "github-mcp"}},
	}})
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
	h := NewConnectHandler(&stubConnectService{})
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
	h := NewConnectHandler(&stubConnectService{err: appoauth.ErrTicketNotFound})
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
	h := NewConnectHandler(&stubConnectService{})
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

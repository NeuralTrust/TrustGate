package resolver

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

func TestParseGatewaySlugFromHost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		host    string
		want    string
		wantErr bool
	}{
		{name: "valid host", host: "acme.gw.neuraltrust.ai", want: "acme"},
		{name: "valid host with port", host: "Acme.gw.neuraltrust.ai:443", want: "acme"},
		{name: "missing host", host: "", wantErr: true},
		{name: "wrong domain", host: "acme.example.com", wantErr: true},
		{name: "too many labels", host: "blue.acme.gw.neuraltrust.ai", wantErr: true},
		{name: "invalid slug", host: "-bad.gw.neuraltrust.ai", wantErr: true},
		{name: "malformed port", host: "acme.gw.neuraltrust.ai:https", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseGatewaySlugFromHost(tt.host, defaultGatewayBaseDomain)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("slug = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseGatewaySlugFromHost_CustomBaseDomain(t *testing.T) {
	t.Parallel()
	got, err := parseGatewaySlugFromHost("acme.gw.agentgateway.sandbox:8081", "gw.agentgateway.sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "acme" {
		t.Fatalf("slug = %q, want acme", got)
	}
	if _, err := parseGatewaySlugFromHost("acme.gw.neuraltrust.ai", "gw.agentgateway.sandbox"); err == nil {
		t.Fatal("expected error for host outside the configured base domain")
	}
}

func TestSubdomainGatewayResolver_UsesHostNotForwardedHost(t *testing.T) {
	t.Parallel()
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	finder := fakeGatewayFinder{bySlug: map[string]*gatewaydomain.Gateway{"acme": gw}}
	resolver := NewSubdomainGatewayResolver(&finder, "")

	var (
		got *gatewaydomain.Gateway
		err error
	)
	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		got, err = resolver.Resolve(c)
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set("X-Forwarded-Host", "evil.gw.neuraltrust.ai")
	resp, testErr := app.Test(req)
	if testErr != nil {
		t.Fatalf("app.Test: %v", testErr)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if got != gw {
		t.Fatal("resolver did not return gateway selected by direct Host")
	}
	if finder.lastSlug != "acme" {
		t.Fatalf("finder slug = %q, want acme", finder.lastSlug)
	}
}

func TestSubdomainGatewayResolver_ErrorMapping(t *testing.T) {
	t.Parallel()
	infraErr := errors.New("database is down")
	tests := []struct {
		name           string
		finder         fakeGatewayFinder
		wantInvalidReq bool
		wantWrapped    error
	}{
		{
			name:           "unknown slug maps to invalid auth request",
			finder:         fakeGatewayFinder{},
			wantInvalidReq: true,
		},
		{
			name:        "infra failure propagates without auth mapping",
			finder:      fakeGatewayFinder{err: infraErr},
			wantWrapped: infraErr,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resolver := NewSubdomainGatewayResolver(&tt.finder, "")

			var resolveErr error
			app := fiber.New()
			app.Get("/", func(c *fiber.Ctx) error {
				_, resolveErr = resolver.Resolve(c)
				return c.SendStatus(fiber.StatusOK)
			})
			req := httptest.NewRequest(fiber.MethodGet, "/", nil)
			req.Host = "acme.gw.neuraltrust.ai"
			if _, err := app.Test(req); err != nil {
				t.Fatalf("app.Test: %v", err)
			}

			if resolveErr == nil {
				t.Fatal("expected error, got nil")
			}
			if got := errors.Is(resolveErr, appauth.ErrInvalidAuthRequest); got != tt.wantInvalidReq {
				t.Fatalf("errors.Is(err, ErrInvalidAuthRequest) = %v, want %v (err: %v)", got, tt.wantInvalidReq, resolveErr)
			}
			if tt.wantWrapped != nil && !errors.Is(resolveErr, tt.wantWrapped) {
				t.Fatalf("err = %v, want it to wrap %v", resolveErr, tt.wantWrapped)
			}
		})
	}
}

func TestHeaderGatewayResolver(t *testing.T) {
	t.Parallel()
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}

	tests := []struct {
		name     string
		header   string
		host     string
		wantGW   bool
		wantSlug string
		wantErr  bool
	}{
		{name: "header carries the slug", header: "acme", host: "localhost:8081", wantGW: true, wantSlug: "acme"},
		{name: "header is normalized", header: "  ACME  ", host: "localhost:8081", wantGW: true, wantSlug: "acme"},
		{name: "no header falls back to host", host: "acme.gw.neuraltrust.ai", wantGW: true, wantSlug: "acme"},
		{name: "header takes precedence over a valid host", header: "unknown", host: "acme.gw.neuraltrust.ai", wantErr: true, wantSlug: "unknown"},
		{name: "invalid header slug", header: "-bad-", host: "localhost:8081", wantErr: true},
		{name: "unknown header slug", header: "ghost", host: "localhost:8081", wantErr: true, wantSlug: "ghost"},
		{name: "no header and non-subdomain host", host: "localhost:8081", wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			finder := fakeGatewayFinder{bySlug: map[string]*gatewaydomain.Gateway{"acme": gw}}
			resolver := NewGatewayResolver(&finder, "header", "")

			var (
				got        *gatewaydomain.Gateway
				resolveErr error
			)
			app := fiber.New()
			app.Get("/", func(c *fiber.Ctx) error {
				got, resolveErr = resolver.Resolve(c)
				return c.SendStatus(fiber.StatusOK)
			})
			req := httptest.NewRequest(fiber.MethodGet, "/", nil)
			req.Host = tt.host
			if tt.header != "" {
				req.Header.Set(HeaderGatewaySlug, tt.header)
			}
			if _, err := app.Test(req); err != nil {
				t.Fatalf("app.Test: %v", err)
			}

			if tt.wantErr {
				if resolveErr == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(resolveErr, appauth.ErrInvalidAuthRequest) {
					t.Fatalf("err = %v, want ErrInvalidAuthRequest", resolveErr)
				}
			} else {
				if resolveErr != nil {
					t.Fatalf("Resolve error: %v", resolveErr)
				}
				if !tt.wantGW || got != gw {
					t.Fatal("resolver did not return the expected gateway")
				}
			}
			if tt.wantSlug != "" && finder.lastSlug != tt.wantSlug {
				t.Fatalf("finder slug = %q, want %q", finder.lastSlug, tt.wantSlug)
			}
		})
	}
}

func TestNewGatewayResolver_SubdomainModeIgnoresHeader(t *testing.T) {
	t.Parallel()
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	finder := fakeGatewayFinder{bySlug: map[string]*gatewaydomain.Gateway{"acme": gw}}
	resolver := NewGatewayResolver(&finder, "subdomain", "")

	var resolveErr error
	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		_, resolveErr = resolver.Resolve(c)
		return c.SendStatus(fiber.StatusOK)
	})
	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Host = "localhost:8081"
	req.Header.Set(HeaderGatewaySlug, "acme")
	if _, err := app.Test(req); err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if resolveErr == nil {
		t.Fatal("subdomain mode must ignore the slug header and fail on a non-subdomain host")
	}
	if !errors.Is(resolveErr, appauth.ErrInvalidAuthRequest) {
		t.Fatalf("err = %v, want ErrInvalidAuthRequest", resolveErr)
	}
}

type fakeGatewayFinder struct {
	bySlug   map[string]*gatewaydomain.Gateway
	err      error
	lastSlug string
}

func (f *fakeGatewayFinder) FindByID(_ context.Context, _ ids.GatewayID) (*gatewaydomain.Gateway, error) {
	return nil, gatewaydomain.ErrNotFound
}

func (f *fakeGatewayFinder) FindBySlug(_ context.Context, slug string) (*gatewaydomain.Gateway, error) {
	f.lastSlug = slug
	if f.err != nil {
		return nil, f.err
	}
	if gw, ok := f.bySlug[slug]; ok {
		return gw, nil
	}
	return nil, gatewaydomain.ErrNotFound
}

func (f *fakeGatewayFinder) List(_ context.Context, _ gatewaydomain.ListFilter) ([]*gatewaydomain.Gateway, int, error) {
	return nil, 0, nil
}

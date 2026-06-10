package middleware

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
			got, err := parseGatewaySlugFromHost(tt.host, cloudGatewayBaseDomain)
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

func TestSubdomainGatewayResolver_UsesHostNotForwardedHost(t *testing.T) {
	t.Parallel()
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	finder := fakeGatewayFinder{bySlug: map[string]*gatewaydomain.Gateway{"acme": gw}}
	resolver := NewSubdomainGatewayResolver(&finder)

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
			resolver := NewSubdomainGatewayResolver(&tt.finder)

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

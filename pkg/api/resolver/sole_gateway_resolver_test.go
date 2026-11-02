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

package resolver

import (
	"errors"
	"net/http/httptest"
	"testing"

	"context"

	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

// listingFinder is a fakeGatewayFinder whose List returns a fixed set.
type listingFinder struct {
	fakeGatewayFinder
	all     []*gatewaydomain.Gateway
	listErr error
}

func (f *listingFinder) List(_ context.Context, _ gatewaydomain.ListFilter) ([]*gatewaydomain.Gateway, int, error) {
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	page := f.all
	if len(page) > 2 {
		page = page[:2]
	}
	return page, len(f.all), nil
}

func resolveSole(t *testing.T, finder *listingFinder, host, header string) (*gatewaydomain.Gateway, error) {
	t.Helper()
	r := WithSoleGatewayFallback(NewGatewayResolver(finder, testBaseDomain), finder)
	var (
		got        *gatewaydomain.Gateway
		resolveErr error
	)
	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		got, resolveErr = r.Resolve(c)
		return c.SendStatus(fiber.StatusOK)
	})
	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Host = host
	if header != "" {
		req.Header.Set(HeaderGatewaySlug, header)
	}
	if _, err := app.Test(req); err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return got, resolveErr
}

func TestSoleGatewayResolver(t *testing.T) {
	t.Parallel()
	only := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "only"}
	other := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "other"}
	planeHost := "0123456789abcdef.mcp.dp.eu.example.com"

	t.Run("a plane holding one gateway serves it on a host without the slug", func(t *testing.T) {
		t.Parallel()
		finder := &listingFinder{all: []*gatewaydomain.Gateway{only}}
		got, err := resolveSole(t, finder, planeHost, "")
		if err != nil || got != only {
			t.Fatalf("Resolve = %v, %v; want the plane's only gateway", got, err)
		}
	})
	t.Run("a named slug is never overridden", func(t *testing.T) {
		t.Parallel()
		finder := &listingFinder{all: []*gatewaydomain.Gateway{only}}
		if got, err := resolveSole(t, finder, planeHost, "someone-else"); err == nil {
			t.Fatalf("Resolve = %v; an unknown header slug must still fail", got)
		}
	})
	t.Run("a named slug still resolves first", func(t *testing.T) {
		t.Parallel()
		finder := &listingFinder{all: []*gatewaydomain.Gateway{only, other}}
		finder.bySlug = map[string]*gatewaydomain.Gateway{"other": other}
		got, err := resolveSole(t, finder, planeHost, "other")
		if err != nil || got != other {
			t.Fatalf("Resolve = %v, %v; want the named gateway", got, err)
		}
	})
	t.Run("a plane holding several gateways keeps failing", func(t *testing.T) {
		t.Parallel()
		finder := &listingFinder{all: []*gatewaydomain.Gateway{only, other}}
		if got, err := resolveSole(t, finder, planeHost, ""); err == nil {
			t.Fatalf("Resolve = %v; want an error with two gateways", got)
		}
	})
	t.Run("an empty plane keeps failing", func(t *testing.T) {
		t.Parallel()
		if got, err := resolveSole(t, &listingFinder{}, planeHost, ""); err == nil {
			t.Fatalf("Resolve = %v; want an error with no gateway", got)
		}
	})
	t.Run("a listing error keeps the original error", func(t *testing.T) {
		t.Parallel()
		finder := &listingFinder{all: []*gatewaydomain.Gateway{only}, listErr: errors.New("boom")}
		if got, err := resolveSole(t, finder, planeHost, ""); err == nil {
			t.Fatalf("Resolve = %v; want the resolver error", got)
		}
	})
}

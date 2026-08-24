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
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

func renderToString(t *testing.T, handler fiber.Handler) string {
	t.Helper()
	app := fiber.New()
	app.Get("/page", handler)
	res, err := app.Test(httptest.NewRequest("GET", "/page", nil))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	return string(body)
}

func TestRenderedPagesAreNotCacheable(t *testing.T) {
	t.Parallel()
	app := fiber.New()
	app.Get("/page", func(c *fiber.Ctx) error {
		return renderConnectPage(c, &appoauth.ConnectPage{
			ConsumerPath: "/v1/mcp/dev",
			Providers:    []appoauth.ProviderStatus{{Provider: "linear", Registry: "linear-mcp"}},
		}, "tk", "", nil)
	})
	res, err := app.Test(httptest.NewRequest("GET", "/page", nil))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if got := res.Header.Get(fiber.HeaderCacheControl); !strings.Contains(got, "no-store") {
		t.Fatalf("connect page must send a no-store Cache-Control, got %q", got)
	}
}

func TestAPIKeyConnectPage_RendersSecureForm(t *testing.T) {
	t.Parallel()
	const formAction = "/virtual-mcp/connect?next=one&mode=two"

	app := fiber.New()
	app.Get("/page", func(c *fiber.Ctx) error {
		return renderAPIKeyConnectPage(c, formAction)
	})
	res, err := app.Test(httptest.NewRequest("GET", "/page", nil))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := string(bodyBytes)

	if !strings.Contains(body, `action="/virtual-mcp/connect?next=one&amp;mode=two"`) {
		t.Fatalf("form action must be escaped, body:\n%s", body)
	}
	if !strings.Contains(body, `method="post"`) {
		t.Fatalf("API-key form must submit with POST, body:\n%s", body)
	}
	if !strings.Contains(body, `id="api-key" name="api_key" type="password" autocomplete="off" required`) {
		t.Fatalf("missing secure API-key field attributes, body:\n%s", body)
	}
	if strings.Contains(body, "value=") {
		t.Fatalf("API-key field must not render a value, body:\n%s", body)
	}
	if got := res.Header.Get(fiber.HeaderCacheControl); !strings.Contains(got, "no-store") {
		t.Fatalf("API-key connect page must send a no-store Cache-Control, got %q", got)
	}
}

func TestConnectPage_RendersCustomSchemeResume(t *testing.T) {
	t.Parallel()
	body := renderToString(t, func(c *fiber.Ctx) error {
		return renderConnectPage(c, &appoauth.ConnectPage{
			ConsumerPath: "/v1/mcp/dev",
			Providers:    []appoauth.ProviderStatus{{Provider: "linear", Registry: "linear-mcp", Linked: true}},
			ResumeURL:    "cursor://anysphere.cursor-mcp/oauth/callback?code=abc&state=s",
		}, "tk", "", nil)
	})
	if strings.Contains(body, "ZgotmplZ") {
		t.Fatal("resume URL was sanitized away")
	}
	if !strings.Contains(body, `href="cursor://anysphere.cursor-mcp/oauth/callback?code=abc&amp;state=s"`) {
		t.Fatalf("missing continue link, body:\n%s", body)
	}
	if !strings.Contains(body, "Connected") || !strings.Contains(body, "/oauth/disconnect/linear?ticket=tk") {
		t.Fatal("linked provider must render status and revoke action")
	}
}

func TestConnectPage_NoResumeNoContinue(t *testing.T) {
	t.Parallel()
	body := renderToString(t, func(c *fiber.Ctx) error {
		return renderConnectPage(c, &appoauth.ConnectPage{
			ConsumerPath: "/v1/mcp/dev",
			Providers:    []appoauth.ProviderStatus{{Provider: "linear", Registry: "linear-mcp"}},
		}, "tk", "denied by provider", nil)
	})
	if strings.Contains(body, "Continue") {
		t.Fatal("continue button must only render during chained consent")
	}
	if !strings.Contains(body, "/oauth/connect/linear?ticket=tk") {
		t.Fatal("unlinked provider must render connect action")
	}
	if !strings.Contains(body, "denied by provider") {
		t.Fatal("flash message must render")
	}
}

func TestDeepLinkPage_RendersCustomScheme(t *testing.T) {
	t.Parallel()
	body := renderToString(t, func(c *fiber.Ctx) error {
		return renderDeepLinkPage(c, "cursor://anysphere.cursor-mcp/oauth/callback?code=abc")
	})
	if strings.Contains(body, "ZgotmplZ") {
		t.Fatal("deep link was sanitized away")
	}
	if !strings.Contains(body, `href="cursor://anysphere.cursor-mcp/oauth/callback?code=abc"`) {
		t.Fatal("missing fallback button link")
	}
	if !strings.Contains(body, `var target = "cursor:`) {
		t.Fatalf("missing JS auto-redirect target, body:\n%s", body)
	}
	if !strings.Contains(body, "Open Cursor") {
		t.Fatal("known scheme must render the product name")
	}
}

func TestConnectPage_UsesAppDesignTokens(t *testing.T) {
	t.Parallel()
	body := renderToString(t, func(c *fiber.Ctx) error {
		return renderConnectPage(c, &appoauth.ConnectPage{
			ConsumerPath: "/v1/mcp/dev",
			Providers: []appoauth.ProviderStatus{
				{Provider: "linear", Registry: "linear-mcp", Linked: true},
				{Provider: "github", Registry: "github-mcp"},
			},
			ResumeURL: "cursor://anysphere.cursor-mcp/oauth/callback?code=abc",
		}, "tk", "", nil)
	})
	for _, want := range []string{
		`family=Inter`,
		`font-family:var(--font-sans)`,
		`--bg-canvas:#03020f`,
		`--brand:#9053ff`,
		`--badge-green:#00fe18`,
		`font-size:1.125rem;line-height:1.75rem`,
		`class="btn secondary"`,
		`class="btn primary"`,
		`class="badge green"`,
		`width="40" height="40"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("connect page must use app DS token %q", want)
		}
	}
}

func TestConnectPage_RendersCatalogLogo(t *testing.T) {
	t.Parallel()
	body := renderToString(t, func(c *fiber.Ctx) error {
		return renderConnectPage(c, &appoauth.ConnectPage{
			ConsumerPath: "/v1/mcp/dev",
			Providers: []appoauth.ProviderStatus{{
				Provider: "app.linear/mcp",
				Registry: "linear-mcp",
				Code:     "app.linear/mcp",
			}},
		}, "tk", "", mustMCPCatalog(t))
	})
	if !strings.Contains(body, `src="/oauth/brands/mcp/linear.svg"`) {
		t.Fatalf("missing Linear logo, body:\n%s", body)
	}
	if !strings.Contains(body, "Linear") {
		t.Fatalf("catalog display name must render, body:\n%s", body)
	}
	if !strings.Contains(body, `class="logo"`) {
		t.Fatal("provider row must use the branded logo tile")
	}
}

func TestConnectPage_UnknownProviderUsesGenericMark(t *testing.T) {
	t.Parallel()
	body := renderToString(t, func(c *fiber.Ctx) error {
		return renderConnectPage(c, &appoauth.ConnectPage{
			ConsumerPath: "/v1/mcp/dev",
			Providers:    []appoauth.ProviderStatus{{Provider: "custom-acme", Registry: "acme-mcp"}},
		}, "tk", "", nil)
	})
	if !strings.Contains(body, `src="/oauth/brands/mcp.svg"`) {
		t.Fatalf("unknown provider must fall back to the MCP mark, body:\n%s", body)
	}
}

func TestServeBrandAsset_ReturnsLogo(t *testing.T) {
	t.Parallel()
	app := fiber.New()
	app.Get(BrandAssetPath, ServeBrandAsset)

	res, err := app.Test(httptest.NewRequest("GET", "/oauth/brands/mcp/linear.svg", nil))
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	if res.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get(fiber.HeaderContentType), "image/svg") {
		t.Fatalf("content-type = %q", res.Header.Get(fiber.HeaderContentType))
	}
	if !strings.Contains(res.Header.Get(fiber.HeaderCacheControl), "max-age=") {
		t.Fatalf("brand assets should be cacheable, got %q", res.Header.Get(fiber.HeaderCacheControl))
	}

	blocked, err := app.Test(httptest.NewRequest("GET", "/oauth/brands/../embed.go", nil))
	if err != nil {
		t.Fatalf("traversal: %v", err)
	}
	if blocked.StatusCode != fiber.StatusNotFound {
		t.Fatalf("traversal status = %d, want 404", blocked.StatusCode)
	}
}

func mustMCPCatalog(t *testing.T) appcatalog.MCPServerCatalog {
	t.Helper()
	catalog, err := appcatalog.NewMCPServerCatalog()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	return catalog
}

func TestDeepLinkPage_UnknownSchemeFallsBackToGenericName(t *testing.T) {
	t.Parallel()
	body := renderToString(t, func(c *fiber.Ctx) error {
		return renderDeepLinkPage(c, "someapp://callback?code=abc")
	})
	if !strings.Contains(body, "Open your application") {
		t.Fatalf("unknown scheme must fall back to a generic name, body:\n%s", body)
	}
}

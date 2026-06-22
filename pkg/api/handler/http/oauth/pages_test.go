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

func TestConnectPage_RendersCustomSchemeResume(t *testing.T) {
	t.Parallel()
	body := renderToString(t, func(c *fiber.Ctx) error {
		return renderConnectPage(c, &appoauth.ConnectPage{
			ConsumerPath: "/v1/mcp/dev",
			Providers:    []appoauth.ProviderStatus{{Provider: "linear", Registry: "linear-mcp", Linked: true}},
			ResumeURL:    "cursor://anysphere.cursor-mcp/oauth/callback?code=abc&state=s",
		}, "tk", "")
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
		}, "tk", "denied by provider")
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

func TestDeepLinkPage_UnknownSchemeFallsBackToGenericName(t *testing.T) {
	t.Parallel()
	body := renderToString(t, func(c *fiber.Ctx) error {
		return renderDeepLinkPage(c, "someapp://callback?code=abc")
	})
	if !strings.Contains(body, "Open your application") {
		t.Fatalf("unknown scheme must fall back to a generic name, body:\n%s", body)
	}
}

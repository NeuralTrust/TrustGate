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
	domaincatalog "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
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
			Providers:    []appoauth.ProviderStatus{{Provider: "linear", Registry: "linear-mcp", Linked: true, AccountRef: "ada@linear.app"}},
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
	if !strings.Contains(body, "ada@linear.app") {
		t.Fatal("linked provider must render the stored account identity")
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
		`--bg-canvas:#f6f6f9`,
		`--brand:#9053ff`,
		`--badge-green:#00b211`,
		`font-size:1.125rem;line-height:1.75rem`,
		`class="btn secondary"`,
		`class="btn primary"`,
		`class="badge green"`,
		`class="grid"`,
		`class="tile"`,
		`id="filter"`,
		`width="40" height="40"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("connect page must use app DS token %q", want)
		}
	}
}

func TestPages_AreLightOnly(t *testing.T) {
	t.Parallel()
	// These are standalone hosted pages, not app surfaces: one light palette,
	// no dark ramp and no forced theme class from the app shell.
	body := renderToString(t, func(c *fiber.Ctx) error {
		return renderConnectPage(c, &appoauth.ConnectPage{
			ConsumerPath: "/v1/mcp/dev",
			Code:         "app.linear/mcp",
			Providers: []appoauth.ProviderStatus{
				{Provider: "app.linear/mcp", Code: "app.linear/mcp", Registry: "linear-mcp"},
			},
		}, "tk", "", mustMCPCatalog(t))
	})
	for _, want := range []string{
		`color-scheme:light`,
		`--bg-canvas:#f6f6f9`,
		`--card-bg:#fff`,
		`--fg-title:#1a1d21`,
		`--brand:#9053ff`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("page must use the light palette, missing %q", want)
		}
	}
	for _, unwanted := range []string{
		`prefers-color-scheme`,
		`color-scheme:dark`,
		`#03020f`,
		`class="dark"`,
	} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("page must carry no dark palette, found %q", unwanted)
		}
	}
}

func TestSingleConnectPage_UsesFocusedCardChrome(t *testing.T) {
	t.Parallel()
	body := renderToString(t, func(c *fiber.Ctx) error {
		return renderConnectPage(c, &appoauth.ConnectPage{
			ConsumerPath: "/v1/mcp/dev",
			Code:         "app.linear/mcp",
			Providers: []appoauth.ProviderStatus{
				{Provider: "app.linear/mcp", Code: "app.linear/mcp", Registry: "linear-mcp"},
			},
			ResumeURL: "cursor://anysphere.cursor-mcp/oauth/callback?code=abc",
		}, "tk", "", mustMCPCatalog(t))
	})
	for _, want := range []string{
		`<body class="dotted">`,
		`class="card flush"`,
		`class="card-hero"`,
		`class="pair"`,
		`class="mark-tile nt"`,
		`class="card-body"`,
		`<h1 class="title">Connect your Linear account</h1>`,
		`Issues, projects, cycles, and teams in Linear.`,
		`class="eyebrow">Access requested<`,
		`class="chip">read<`,
		`class="note"`,
		`class="card-foot"`,
		`class="btn primary block"`,
		`class="secured"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("focused connect page missing %q, body:\n%s", want, body)
		}
	}
}

func TestSingleConnectPage_ConnectedStateLeadsWithStatus(t *testing.T) {
	t.Parallel()
	body := renderToString(t, func(c *fiber.Ctx) error {
		return renderConnectPage(c, &appoauth.ConnectPage{
			ConsumerPath: "/v1/mcp/dev",
			Code:         "app.linear/mcp",
			Providers: []appoauth.ProviderStatus{{
				Provider:   "app.linear/mcp",
				Code:       "app.linear/mcp",
				Registry:   "linear-mcp",
				Linked:     true,
				AccountRef: "someone@example.com",
				Scopes:     []string{"read"},
			}},
		}, "tk", "", mustMCPCatalog(t))
	})
	if !strings.Contains(body, `<h1 class="title">Linear is connected</h1>`) {
		t.Fatalf("connected page must lead with the connected headline, body:\n%s", body)
	}
	if !strings.Contains(body, `class="account"`) || !strings.Contains(body, "someone@example.com") {
		t.Fatalf("connected page must show the status chip and account ref, body:\n%s", body)
	}
	if !strings.Contains(body, `/oauth/disconnect/app.linear/mcp?ticket=tk`) {
		t.Fatalf("connected page must offer disconnect, body:\n%s", body)
	}
	if !strings.Contains(body, `class="eyebrow">Access granted<`) {
		t.Fatalf("connected page must label the access list as granted, body:\n%s", body)
	}
}

func TestAccessSummary(t *testing.T) {
	t.Parallel()
	catalogued := domaincatalog.MCPServer{
		OAuth: &domaincatalog.MCPOAuth{Scopes: []string{"declared.a", "declared.b"}},
		Tools: []domaincatalog.MCPTool{{Name: "search"}},
	}

	// Before linking there is no grant, so the catalog's declaration stands in
	// and is labelled as a request.
	label, items, more := accessSummary(catalogued, nil, false)
	if label != "Access requested" || len(items) != 2 || items[0] != "declared.a" || more != 0 {
		t.Fatalf("unlinked must show the declared scopes: %q %v %d", label, items, more)
	}

	// Once linked, only what the upstream actually granted may be shown — the
	// catalog's declaration must never be relabelled as granted.
	label, items, _ = accessSummary(catalogued, []string{"granted.a"}, true)
	if label != "Access granted" || len(items) != 1 || items[0] != "granted.a" {
		t.Fatalf("linked must show the granted scopes: %q %v", label, items)
	}

	// A provider whose token response omitted "scope" leaves nothing granted to
	// report, so the card falls back to the tool preview rather than passing the
	// declaration off as a grant.
	label, items, _ = accessSummary(catalogued, nil, true)
	if label != "Tools the agent can call" || len(items) != 1 || items[0] != "search" {
		t.Fatalf("linked with no recorded grant must not claim one: %q %v", label, items)
	}

	// The tool fallback caps and counts the remainder, skipping blank names.
	tools := make([]domaincatalog.MCPTool, 0, 7)
	for _, n := range []string{"a", "b", "c", "d", "e", "f", ""} {
		tools = append(tools, domaincatalog.MCPTool{Name: n})
	}
	label, items, more = accessSummary(domaincatalog.MCPServer{Tools: tools}, nil, false)
	if label != "Tools the agent can call" || len(items) != maxAccessItems || more != 2 {
		t.Fatalf("tool fallback must cap and count the rest: %q %v %d", label, items, more)
	}

	// A server the catalog knows nothing about renders no access block at all.
	if label, items, more := accessSummary(domaincatalog.MCPServer{}, nil, false); label != "" || items != nil || more != 0 {
		t.Fatalf("an empty entry must produce no access block: %q %v %d", label, items, more)
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
	if !strings.Contains(body, "Issues, projects, cycles, and teams in Linear.") {
		t.Fatalf("catalog description must render on the store tile, body:\n%s", body)
	}
	if !strings.Contains(body, `class="logo"`) {
		t.Fatal("provider tile must use the branded logo")
	}
	if !strings.Contains(body, `class="tile"`) {
		t.Fatal("providers must render as store tiles")
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
	catalog, err := appcatalog.NewMCPServerCatalog(nil)
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

// The Connect / Reconnect controls submit a POST: a GET link is prefetchable
// by browsers, and a prefetched start plus the real click leaves the IdP with
// two pending approvals (Linear rejects the first callback with "Invalid
// approval").
func TestConnectPage_StartIsAPostNotALink(t *testing.T) {
	body := renderToString(t, func(c *fiber.Ctx) error {
		return renderConnectPage(c, &appoauth.ConnectPage{
			ConsumerPath: "/v1/mcp/dev",
			Providers: []appoauth.ProviderStatus{
				{Provider: "linear", Registry: "linear-mcp", Instance: "reg-1"},
			},
		}, "tk", "", nil)
	})
	if strings.Contains(body, `href="/oauth/connect/`) {
		t.Fatalf("connect start must not be a GET link:\n%s", body)
	}
	// The instance rides along so a provider with two of them connects the one
	// whose tile was pressed.
	if !strings.Contains(body, `<form method="post" action="/oauth/connect/linear?ticket=tk&amp;instance=reg-1">`) {
		t.Fatalf("connect start must be a POST form naming the instance:\n%s", body)
	}
}

// The request form is where the person who wants the server says why, so the
// page has to ask them for it in words an approver will read.
func TestConfigurePage_AsksTheRequesterWhy(t *testing.T) {
	t.Parallel()
	html := renderToString(t, func(c *fiber.Ctx) error {
		return renderConfigurePage(c, &appoauth.ConfigurePage{
			Code: "com.ahrefs/mcp", ServerName: "Ahrefs", AskReason: true,
		})
	})
	for _, want := range []string{
		"Request access to Ahrefs",
		"in your own words",
		`name="` + appoauth.ReasonFormField + `"`,
		"<textarea",
		"required",
		"Send request",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("the request form must contain %q: %s", want, html)
		}
	}
}

// Once it is sent, the page reports what happened instead of offering the field
// again — a second submit would file a second request.
func TestConfigurePage_ASentRequestSaysSoAndStopsAsking(t *testing.T) {
	t.Parallel()
	html := renderToString(t, func(c *fiber.Ctx) error {
		return renderConfigurePage(c, &appoauth.ConfigurePage{
			Code: "com.ahrefs/mcp", ServerName: "Ahrefs",
			AskReason: true, Saved: true, Pending: true,
		})
	})
	if strings.Contains(html, "<textarea") || strings.Contains(html, "<form") {
		t.Fatalf("a sent request must not re-offer the form: %s", html)
	}
	if !strings.Contains(html, "An administrator has to approve it") {
		t.Fatalf("a sent request must say it is waiting on an approver: %s", html)
	}
	// The confirmation is titled by what the form was. Dropping the flag on save
	// left someone who had just asked for access looking at "Configure Ahrefs —
	// enter your setup values", which is neither what they did nor what happened.
	if !strings.Contains(html, "Request access to Ahrefs") {
		t.Fatalf("a sent request must still be titled a request: %s", html)
	}
	if strings.Contains(html, "Enter your setup values") {
		t.Fatalf("a sent request must not read as a configuration form: %s", html)
	}
}

// A configure form is unchanged: it asks for the server's own values and says
// nothing about requests.
func TestConfigurePage_StillConfiguresWithoutAskingTheReason(t *testing.T) {
	t.Parallel()
	html := renderToString(t, func(c *fiber.Ctx) error {
		return renderConfigurePage(c, &appoauth.ConfigurePage{
			Code: "snowflake", ServerName: "Snowflake",
			Variables: []appoauth.ConfigureVariable{{Name: "account_url", Required: true}},
		})
	})
	if strings.Contains(html, "<textarea") || strings.Contains(html, "Request access") {
		t.Fatalf("a configure form must not ask for a reason: %s", html)
	}
	if !strings.Contains(html, `name="account_url"`) || !strings.Contains(html, "Configure Snowflake") {
		t.Fatalf("a configure form must still collect its variables: %s", html)
	}
}

// A closed variable is a choice the vendor publishes, and the submit refuses
// anything outside it. A text box would let someone type a value the save can
// only reject, so the form offers the set and nothing else.
func TestConfigurePage_ClosedVariableIsOfferedAsAChoice(t *testing.T) {
	t.Parallel()
	html := renderToString(t, func(c *fiber.Ctx) error {
		return renderConfigurePage(c, &appoauth.ConfigurePage{
			Code: "com.vanta/mcp", ServerName: "Vanta",
			Variables: []appoauth.ConfigureVariable{{
				Name: "host", Required: true,
				Options: []appoauth.ConfigureVariableOption{
					{Value: "mcp.vanta.com", Label: "United States"},
					{Value: "mcp.eu.vanta.com", Label: "Europe"},
				},
			}},
		})
	})
	if !strings.Contains(html, `<select id="host" name="host" required>`) {
		t.Fatalf("a closed variable must be a picker: %s", html)
	}
	for _, want := range []string{
		`<option value="mcp.vanta.com">United States</option>`,
		`<option value="mcp.eu.vanta.com">Europe</option>`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("the form must offer %s: %s", want, html)
		}
	}
	if strings.Contains(html, `<input id="host"`) {
		t.Fatalf("a closed variable must not also be typeable: %s", html)
	}
}

// Options are the exception. A variable without them is still the text box every
// other catalog entry depends on.
func TestConfigurePage_OpenVariableStaysATextBox(t *testing.T) {
	t.Parallel()
	html := renderToString(t, func(c *fiber.Ctx) error {
		return renderConfigurePage(c, &appoauth.ConfigurePage{
			Code: "snowflake", ServerName: "Snowflake",
			Variables: []appoauth.ConfigureVariable{{Name: "account_url", Required: true}},
		})
	})
	if strings.Contains(html, "<select") {
		t.Fatalf("an open variable must not become a picker: %s", html)
	}
	if !strings.Contains(html, `<input id="account_url"`) {
		t.Fatalf("an open variable must stay typeable: %s", html)
	}
}

// Connecting is the end of the page but not of the task: the tools the user
// came for are somewhere else, and whether they show up depends on a client
// this page cannot see. Saying nothing left people staring at a green badge,
// unsure whether it had worked.
func TestSingleConnectPage_ConnectedStateSaysWhatToDoNext(t *testing.T) {
	t.Parallel()
	body := renderToString(t, func(c *fiber.Ctx) error {
		return renderConnectPage(c, &appoauth.ConnectPage{
			ConsumerPath: "/v1/mcp/dev",
			Code:         "app.linear/mcp",
			Providers: []appoauth.ProviderStatus{{
				Provider: "app.linear/mcp", Code: "app.linear/mcp", Registry: "linear-mcp", Linked: true,
			}},
		}, "tk", "", mustMCPCatalog(t))
	})
	for _, want := range []string{
		// The task is over, and the panel says so before it says anything else.
		`class="done"`,
		"All set",
		// With nowhere to send them, the window is what they close.
		"you can close this window",
		"the new tools appear on their own",
		// A client that only reads tools/list at session start is why the badge
		// alone is not enough, and the user can act on that.
		"start a new conversation",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("the connected card must say %q, body:\n%s", want, body)
		}
	}
}

// With a resume link the button is the instruction; telling them to close the
// window on top of it points two ways at once.
func TestSingleConnectPage_ResumeLinkReplacesTheCloseInstruction(t *testing.T) {
	t.Parallel()
	body := renderToString(t, func(c *fiber.Ctx) error {
		return renderConnectPage(c, &appoauth.ConnectPage{
			ConsumerPath: "/v1/mcp/dev",
			Code:         "app.linear/mcp",
			Providers: []appoauth.ProviderStatus{{
				Provider: "app.linear/mcp", Code: "app.linear/mcp", Registry: "linear-mcp", Linked: true,
			}},
			ResumeURL: "cursor://anysphere.cursor-mcp/oauth/callback?code=abc",
		}, "tk", "", mustMCPCatalog(t))
	})
	if strings.Contains(body, "you can close this window") {
		t.Fatalf("a page offering a way back must not also say to close it, body:\n%s", body)
	}
	if !strings.Contains(body, "head back to your app") {
		t.Fatalf("a page offering a way back must point at it, body:\n%s", body)
	}
	if !strings.Contains(body, "the new tools appear on their own") {
		t.Fatalf("the tools guidance holds either way, body:\n%s", body)
	}
}

// Before connecting there is nothing to go back for, so the line must not
// appear on the page that is still asking.
func TestSingleConnectPage_UnconnectedStateDoesNotSendThemBack(t *testing.T) {
	t.Parallel()
	body := renderToString(t, func(c *fiber.Ctx) error {
		return renderConnectPage(c, &appoauth.ConnectPage{
			ConsumerPath: "/v1/mcp/dev",
			Code:         "app.linear/mcp",
			Providers: []appoauth.ProviderStatus{{
				Provider: "app.linear/mcp", Code: "app.linear/mcp", Registry: "linear-mcp",
			}},
		}, "tk", "", mustMCPCatalog(t))
	})
	if strings.Contains(body, "the new tools appear on their own") {
		t.Fatalf("an unconnected card must not talk about new tools, body:\n%s", body)
	}
}

// Without an account to name, the old pill said only "Connected" — the same
// thing the headline and the done panel already say, in the quietest of the
// three. It is shown now only when it carries the account it connected as.
func TestSingleConnectPage_NoEmptyConnectedPill(t *testing.T) {
	t.Parallel()
	body := renderToString(t, func(c *fiber.Ctx) error {
		return renderConnectPage(c, &appoauth.ConnectPage{
			ConsumerPath: "/v1/mcp/dev",
			Code:         "app.linear/mcp",
			Providers: []appoauth.ProviderStatus{{
				Provider: "app.linear/mcp", Code: "app.linear/mcp", Registry: "linear-mcp", Linked: true,
			}},
		}, "tk", "", mustMCPCatalog(t))
	})
	if strings.Contains(body, `class="account"`) {
		t.Fatalf("a pill with nothing but the word Connected is noise: %s", body)
	}
	// The done panel still says it, and says what to do next.
	if !strings.Contains(body, `class="done"`) {
		t.Fatalf("the connected card must still report success: %s", body)
	}
}

func renderPathToString(t *testing.T, target string, handler fiber.Handler) string {
	t.Helper()
	app := fiber.New()
	app.Get("/store/mcp/connect", handler)
	res, err := app.Test(httptest.NewRequest("GET", target, nil))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	return string(body)
}

// RUN-1635: a server connected for the first time was shelved a moment ago and
// may not have reached this plane yet. The page said it needed no connection
// until the user happened to reload; it now says it is getting ready and reloads
// itself, one attempt further on each time.
func TestSingleConnectPage_WaitsForAServerNotHereYet(t *testing.T) {
	t.Parallel()
	notHereYet := func(c *fiber.Ctx) error {
		return renderConnectPage(c, &appoauth.ConnectPage{ConsumerPath: "/store/mcp", Code: "app.linear/mcp"}, "tk", "", mustMCPCatalog(t))
	}

	body := renderPathToString(t, "/store/mcp/connect?ticket=tk", notHereYet)
	for _, want := range []string{
		`<meta http-equiv="refresh" content="2;url=/store/mcp/connect?ticket=tk&amp;wait=1">`,
		`<h1 class="title">Getting Linear ready</h1>`,
		`href="/store/mcp/connect?ticket=tk&amp;wait=1"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("waiting page missing %q, body:\n%s", want, body)
		}
	}
	if strings.Contains(body, "does not need an account connection") {
		t.Fatal("a server that is still arriving must not be called connection-free")
	}

	next := renderPathToString(t, "/store/mcp/connect?ticket=tk&wait=3", notHereYet)
	if !strings.Contains(next, `wait=4`) {
		t.Fatalf("each reload is one attempt further on, body:\n%s", next)
	}
}

func TestSingleConnectPage_StopsWaitingAfterTheLastAttempt(t *testing.T) {
	t.Parallel()
	body := renderPathToString(t, "/store/mcp/connect?ticket=tk&wait=8", func(c *fiber.Ctx) error {
		return renderConnectPage(c, &appoauth.ConnectPage{ConsumerPath: "/store/mcp", Code: "app.linear/mcp"}, "tk", "", mustMCPCatalog(t))
	})
	if strings.Contains(body, `http-equiv="refresh"`) {
		t.Fatal("the page must stop reloading once the attempts are spent")
	}
	if !strings.Contains(body, "does not need an account connection") {
		t.Fatalf("after waiting, the page says what it can, body:\n%s", body)
	}
}

func TestSingleConnectPage_DoesNotWaitWhenTheServerIsHere(t *testing.T) {
	t.Parallel()
	body := renderPathToString(t, "/store/mcp/connect?ticket=tk", func(c *fiber.Ctx) error {
		return renderConnectPage(c, &appoauth.ConnectPage{
			ConsumerPath: "/store/mcp",
			Code:         "app.linear/mcp",
			Providers:    []appoauth.ProviderStatus{{Provider: "app.linear/mcp", Code: "app.linear/mcp", Registry: "linear-mcp"}},
		}, "tk", "", mustMCPCatalog(t))
	})
	if strings.Contains(body, `http-equiv="refresh"`) || strings.Contains(body, "Getting Linear ready") {
		t.Fatal("a server that is here is connected, not waited for")
	}
}

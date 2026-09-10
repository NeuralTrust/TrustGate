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
	"bytes"
	"html/template"
	"net/url"
	"strings"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	domaincatalog "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	"github.com/gofiber/fiber/v2"
)

type providerView struct {
	Provider string
	// Instance is the registry id the row's connect/revoke acts on. Two
	// instances of one catalog code render as two tiles sharing a Provider, and
	// without it every tile would connect whichever instance came first.
	Instance string
	// InstanceName tells those two tiles apart: the registry's own name, set
	// only when it says something the catalog's display name does not.
	InstanceName   string
	DisplayName    string
	Subtitle       string
	Description    string
	LogoURL        template.URL
	Linked         bool
	AccountRef     string
	NeedsReconnect bool
}

type connectPageView struct {
	ConsumerPath string
	Flash        string
	Ticket       string
	Providers    []providerView
	ResumeURL    template.URL
}

func renderConnectPage(c *fiber.Ctx, page *appoauth.ConnectPage, ticket, flash string, catalog appcatalog.MCPServerCatalog) error {
	// A ticket minted for one server (e.g. a Store install) shows the focused
	// single-server page instead of the full provider grid.
	if strings.TrimSpace(page.Code) != "" {
		return renderSingleConnectPage(c, page, ticket, flash, catalog)
	}
	return renderHTML(c, connectPageTmpl, connectPageView{
		ConsumerPath: page.ConsumerPath,
		Flash:        flash,
		Ticket:       ticket,
		Providers:    decorateProviders(catalog, page.Providers),
		ResumeURL:    template.URL(page.ResumeURL), // #nosec G203 -- gateway-built from the registered redirect_uri, never user input
	})
}

type singleConnectView struct {
	ServerName string
	Provider   string
	// Instance and InstanceName pin the page to one instance of the server, so a
	// code with several does not connect whichever came first (see providerView).
	Instance       string
	InstanceName   string
	Ticket         string
	Flash          string
	LogoURL        template.URL
	Linked         bool
	AccountRef     string
	NeedsReconnect bool
	Found          bool
	ResumeURL      template.URL
	// Description is the catalog one-liner for the server, shown under the
	// headline so the card says what the user is connecting to.
	Description string
	// AccessLabel names what Items lists: the scopes the upstream granted
	// (linked), the scopes the catalog declares the gateway will ask for
	// (not linked), or — when neither is known — the tools the server
	// advertises. Empty when none of the three is available.
	AccessLabel string
	Items       []string
	ItemsMore   int
}

// providerRowsForPage narrows a page's rows to the server it is scoped to: the
// instance the ticket names when that instance is still there, else every row of
// the code.
//
// An install records the instance it wrote, so a ticket minted from it points at
// one row of a code that may have several. Should that instance be gone by the
// time the user opens the link, the code's rows are better than an empty page.
func providerRowsForPage(page *appoauth.ConnectPage) []appoauth.ProviderStatus {
	ofCode := make([]appoauth.ProviderStatus, 0, len(page.Providers))
	for _, p := range page.Providers {
		if p.Code != page.Code {
			continue
		}
		if page.Instance != "" && p.Instance == page.Instance {
			return []appoauth.ProviderStatus{p}
		}
		ofCode = append(ofCode, p)
	}
	return ofCode
}

// renderSingleConnectPage renders the focused, one-server connect page. It picks
// the provider the ticket is scoped to (by catalog code, and by instance when it
// names one) out of the consumer's providers; if none matches, the server needs
// no connection (or is not on this consumer) and the page says so.
func renderSingleConnectPage(c *fiber.Ctx, page *appoauth.ConnectPage, ticket, flash string, catalog appcatalog.MCPServerCatalog) error {
	view := singleConnectView{
		Ticket:    ticket,
		Flash:     flash,
		ResumeURL: template.URL(page.ResumeURL), // #nosec G203 -- gateway-built from the registered redirect_uri, never user input
	}
	var granted []string
	for _, p := range providerRowsForPage(page) {
		decorated := decorateProvider(catalog, p)
		granted = p.Scopes
		view.ServerName = decorated.DisplayName
		view.Provider = p.Provider
		view.Instance = p.Instance
		view.InstanceName = decorated.InstanceName
		view.LogoURL = decorated.LogoURL
		view.Linked = p.Linked
		view.AccountRef = p.AccountRef
		view.NeedsReconnect = p.NeedsReconnect
		view.Found = true
		break
	}
	if view.ServerName == "" {
		view.ServerName = serverDisplayName(catalog, page.Code)
	}
	if catalog != nil {
		if server, ok := lookupCatalogServer(catalog, page.Code, view.Provider); ok {
			view.Description = strings.TrimSpace(server.Description)
			view.AccessLabel, view.Items, view.ItemsMore = accessSummary(server, granted, view.Linked)
		}
	}
	return renderHTML(c, singleConnectPageTmpl, view)
}

// maxAccessItems caps the access list so a server with dozens of scopes or
// tools does not turn the consent card into a wall of chips.
const maxAccessItems = 4

// accessSummary describes what the connection grants, and only ever claims
// what the gateway can actually stand behind.
//
// Once linked, that is the scope set the upstream returned with the token, so
// "granted" is literally true. Before linking there is no grant yet, so the
// catalog's declared scopes stand in as what the gateway will ask for — those
// are the values the install prefills onto the registry's auth config and the
// values applyCatalogScopes forces on the non-DCR path, but an operator can
// edit them afterwards, so this is a declaration and is labelled as one.
// With neither in hand, the advertised tools stand in as a capability preview.
func accessSummary(server domaincatalog.MCPServer, granted []string, linked bool) (label string, items []string, more int) {
	declared := []string(nil)
	if server.OAuth != nil {
		declared = server.OAuth.Scopes
	}
	switch {
	case linked && len(granted) > 0:
		label = "Access granted"
		items = granted
	case !linked && len(declared) > 0:
		label = "Access requested"
		items = declared
	}
	if len(items) == 0 && len(server.Tools) > 0 {
		label = "Tools the agent can call"
		items = make([]string, 0, len(server.Tools))
		for _, t := range server.Tools {
			if name := strings.TrimSpace(t.Name); name != "" {
				items = append(items, name)
			}
		}
	}
	if len(items) == 0 {
		return "", nil, 0
	}
	if len(items) > maxAccessItems {
		return label, items[:maxAccessItems], len(items) - maxAccessItems
	}
	return label, items, 0
}

// serverDisplayName resolves a friendly name for a catalog code for the header
// when the server is not among the connectable providers.
func serverDisplayName(catalog appcatalog.MCPServerCatalog, code string) string {
	if catalog != nil {
		if server, ok := catalog.GetByCode(code); ok && strings.TrimSpace(server.DisplayName) != "" {
			return server.DisplayName
		}
	}
	return code
}

func decorateProviders(catalog appcatalog.MCPServerCatalog, providers []appoauth.ProviderStatus) []providerView {
	out := make([]providerView, 0, len(providers))
	for _, p := range providers {
		out = append(out, decorateProvider(catalog, p))
	}
	return out
}

func decorateProvider(catalog appcatalog.MCPServerCatalog, p appoauth.ProviderStatus) providerView {
	display := strings.TrimSpace(p.Registry)
	if display == "" {
		display = p.Provider
	}
	vendor := ""
	desc := ""
	if catalog != nil {
		if server, ok := lookupCatalogServer(catalog, p.Code, p.Provider); ok {
			if server.DisplayName != "" {
				display = server.DisplayName
			}
			vendor = server.Vendor
			desc = strings.TrimSpace(server.Description)
		}
	}
	subtitle := p.Registry
	if subtitle == "" || subtitle == display {
		subtitle = p.Provider
	}
	if desc == "" {
		desc = subtitle
	}
	instanceName := strings.TrimSpace(p.Registry)
	if instanceName == display {
		instanceName = ""
	}
	return providerView{
		Provider:       p.Provider,
		Instance:       p.Instance,
		InstanceName:   instanceName,
		DisplayName:    display,
		Subtitle:       subtitle,
		Description:    desc,
		LogoURL:        template.URL(appcatalog.BrandIconURL(vendor, display, p.Provider, p.Registry, p.Code)), // #nosec G203 -- path is chosen from the bundled brand map
		Linked:         p.Linked,
		AccountRef:     p.AccountRef,
		NeedsReconnect: p.NeedsReconnect,
	}
}

func lookupCatalogServer(catalog appcatalog.MCPServerCatalog, keys ...string) (domaincatalog.MCPServer, bool) {
	for _, key := range keys {
		if key == "" {
			continue
		}
		if server, ok := catalog.GetByCode(key); ok {
			return server, true
		}
	}
	return domaincatalog.MCPServer{}, false
}

type configureVarView struct {
	Name        string
	Description string
	Required    bool
	Secret      bool
	Set         bool
}

type configurePageView struct {
	ServerName string
	Variables  []configureVarView
	Saved      bool
	Pending    bool
	// AskReason renders the "why do you need this?" field: the install is
	// outside this user's access, so submitting files a request an administrator
	// decides on, and this is what they read.
	AskReason      bool
	ReasonField    string
	ReasonMaxChars int
}

func renderConfigurePage(c *fiber.Ctx, page *appoauth.ConfigurePage) error {
	vars := make([]configureVarView, 0, len(page.Variables))
	for _, v := range page.Variables {
		vars = append(vars, configureVarView{
			Name:        v.Name,
			Description: v.Description,
			Required:    v.Required,
			Secret:      v.Secret,
			Set:         v.Set,
		})
	}
	return renderHTML(c, configurePageTmpl, configurePageView{
		ServerName:     page.ServerName,
		Variables:      vars,
		Saved:          page.Saved,
		Pending:        page.Pending,
		AskReason:      page.AskReason,
		ReasonField:    appoauth.ReasonFormField,
		ReasonMaxChars: installationdomain.MaxReasonLength,
	})
}

type apiKeyConnectPageView struct {
	FormAction string
}

func renderAPIKeyConnectPage(c *fiber.Ctx, formAction string) error {
	return renderHTML(c, apiKeyConnectPageTmpl, apiKeyConnectPageView{
		FormAction: formAction,
	})
}

var knownSchemeApps = map[string]string{
	"cursor":          "Cursor",
	"vscode":          "VS Code",
	"vscode-insiders": "VS Code Insiders",
	"windsurf":        "Windsurf",
	"zed":             "Zed",
	"claude":          "Claude",
	"jetbrains":       "your JetBrains IDE",
	"chatgpt":         "ChatGPT",
	"cline":           "Cline",
}

func appNameForLocation(location string) string {
	u, err := url.Parse(location)
	if err != nil {
		return "your application"
	}
	if name, ok := knownSchemeApps[strings.ToLower(u.Scheme)]; ok {
		return name
	}
	return "your application"
}

type deepLinkView struct {
	AppName  string
	Location template.URL
}

func renderDeepLinkPage(c *fiber.Ctx, location string) error {
	return renderHTML(c, deepLinkPageTmpl, deepLinkView{
		AppName:  appNameForLocation(location),
		Location: template.URL(location), // #nosec G203 -- redirect target validated against the client's registered redirect_uris
	})
}

func renderHTML(c *fiber.Ctx, tmpl *template.Template, data any) error {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return err
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	c.Set(fiber.HeaderCacheControl, "no-store, must-revalidate")
	c.Set(fiber.HeaderPragma, "no-cache")
	return c.Status(fiber.StatusOK).Send(buf.Bytes())
}

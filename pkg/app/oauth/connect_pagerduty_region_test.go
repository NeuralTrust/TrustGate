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
	"slices"
	"strings"
	"testing"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

const (
	pagerdutyCode      = "com.pagerduty/mcp"
	pagerdutyUSURL     = "https://mcp.pagerduty.com/mcp"
	pagerdutyEUURL     = "https://mcp.eu.pagerduty.com/mcp"
	pagerdutyAuthorize = "https://app.pagerduty.com/global/oauth/authorize"
	pagerdutyToken     = "https://app.pagerduty.com/global/oauth/token"
)

// An admin row created before the catalog templated the host stores the fixed
// US URL and no url_variables. applyCatalog must still recognize that URL as
// the United States option, keep the catalog scopes, and hand finalizeAuthURLs
// a concrete resource. An unresolved "{host}" would refuse the redirect.
func TestApplyCatalog_ExistingPagerDutyUSRowKeepsScopesAndResolvedResource(t *testing.T) {
	t.Parallel()
	cat, entry := pagerdutyCatalog(t)
	cfg := &registrydomain.MCPAuth{
		Mode:         registrydomain.MCPAuthModeForwarded,
		Provider:     pagerdutyCode,
		Registration: registrydomain.RegistrationManual,
		ClientID:     "cid",
		ClientSecret: "secret",
		AuthorizeURL: pagerdutyAuthorize,
		TokenURL:     pagerdutyToken,
		Scopes:       []string{"stale"},
		Resource:     "https://old.pagerduty.example/mcp",
	}
	reg := &registrydomain.Registry{
		GatewayID: ids.New[ids.GatewayKind](),
		MCPTarget: &registrydomain.MCPTarget{
			Code: pagerdutyCode,
			URL:  pagerdutyUSURL,
			Auth: cfg,
		},
	}
	res := upstreamResolution{url: pagerdutyUSURL, ready: true}

	if !catalogServerMatches(entry, res) {
		t.Fatal("existing US row did not match the catalog")
	}
	if !catalogServerMatches(entry, upstreamResolution{url: pagerdutyUSURL + "/", ready: true}) {
		t.Fatal("a trailing slash hid the US match")
	}
	got := applyCatalog(cfg, reg, cat, res)
	assertPagerDutyCatalogAuth(t, got, entry, pagerdutyUSURL)

	finalized, err := (&connectService{catalog: cat}).finalizeAuthURLs(
		context.Background(), reg.GatewayID, "alice", reg, got, nil, res,
	)
	if err != nil {
		if errors.Is(err, ErrUnresolvedOAuthPlaceholder) {
			t.Fatalf("existing US row hit an unresolved placeholder: %v", err)
		}
		t.Fatalf("finalizeAuthURLs: %v", err)
	}
	assertPagerDutyCatalogAuth(t, finalized, entry, pagerdutyUSURL)
	if !slices.Equal(cfg.Scopes, []string{"stale"}) || cfg.Resource != "https://old.pagerduty.example/mcp" {
		t.Fatal("applyCatalog mutated the stored auth")
	}
}

// A new install that picks Europe fills {host} and must resolve both the
// upstream URL and the resource to the EU host. Authorize and token stay on
// the global PagerDuty endpoints.
func TestApplyCatalog_PagerDutyEURowResolvesHostAndKeepsGlobalEndpoints(t *testing.T) {
	t.Parallel()
	cat, entry := pagerdutyCatalog(t)
	values := map[string]string{"host": "mcp.eu.pagerduty.com"}
	vars := make([]registrydomain.MCPURLVariable, 0, len(entry.URLVariables))
	for _, variable := range entry.URLVariables {
		vars = append(vars, toRegistryURLVar(variable))
	}
	resolvedURL, err := registrydomain.ResolveURL(entry.URL, vars, values)
	if err != nil {
		t.Fatalf("ResolveURL: %v", err)
	}
	if resolvedURL != pagerdutyEUURL {
		t.Fatalf("resolved URL = %q, want %s", resolvedURL, pagerdutyEUURL)
	}

	cfg := &registrydomain.MCPAuth{
		Mode:         registrydomain.MCPAuthModeForwarded,
		Provider:     pagerdutyCode,
		Registration: registrydomain.RegistrationManual,
		ClientID:     "cid",
		ClientSecret: "secret",
		AuthorizeURL: pagerdutyAuthorize,
		TokenURL:     pagerdutyToken,
		Scopes:       []string{"stale"},
		Resource:     entry.OAuth.Resource,
	}
	reg := &registrydomain.Registry{
		GatewayID: ids.New[ids.GatewayKind](),
		MCPTarget: &registrydomain.MCPTarget{
			Code:           pagerdutyCode,
			URL:            entry.URL,
			URLVariables:   vars,
			InstanceConfig: values,
			Auth:           cfg,
		},
	}
	res := upstreamResolution{url: resolvedURL, values: values, ready: true}

	if !catalogServerMatches(entry, res) {
		t.Fatal("EU row did not match the catalog")
	}
	got := applyCatalog(cfg, reg, cat, res)
	assertPagerDutyCatalogAuth(t, got, entry, pagerdutyEUURL)

	finalized, err := (&connectService{catalog: cat}).finalizeAuthURLs(
		context.Background(), reg.GatewayID, "alice", reg, got, nil, res,
	)
	if err != nil {
		t.Fatalf("finalizeAuthURLs: %v", err)
	}
	assertPagerDutyCatalogAuth(t, finalized, entry, pagerdutyEUURL)
}

// A host outside the listed options is not the catalog server. Guessing an
// option, or accepting any host, would send the hosted resource to a
// self-hosted install.
func TestCatalogServerMatches_PagerDutyDoesNotWidenTheHost(t *testing.T) {
	t.Parallel()
	cat, entry := pagerdutyCatalog(t)
	cfg := &registrydomain.MCPAuth{
		Provider:     pagerdutyCode,
		AuthorizeURL: pagerdutyAuthorize,
		TokenURL:     pagerdutyToken,
		Scopes:       []string{"stored"},
		Resource:     "https://self.example/mcp",
	}
	reg := &registrydomain.Registry{MCPTarget: &registrydomain.MCPTarget{
		Code: pagerdutyCode,
		URL:  "https://self.example/mcp",
		Auth: cfg,
	}}
	res := upstreamResolution{url: "https://self.example/mcp", ready: true}
	if catalogServerMatches(entry, res) {
		t.Fatal("a host outside the listed options matched")
	}
	got := applyCatalog(cfg, reg, cat, res)
	if got != cfg {
		t.Fatalf("non-matching row was rewritten: %+v", got)
	}

	supplied := upstreamResolution{
		url:    pagerdutyUSURL,
		values: map[string]string{"host": "mcp.eu.pagerduty.com"},
		ready:  true,
	}
	if catalogServerMatches(entry, supplied) {
		t.Fatal("a supplied host that does not produce the row URL matched")
	}
	if catalogServerMatches(entry, upstreamResolution{url: pagerdutyUSURL}) {
		t.Fatal("a not-ready resolution matched")
	}
}

// An open variable has no listed host to try. A fixed URL must keep today's
// behaviour: no match, stored scopes and resource left as written.
func TestCatalogServerMatches_OpenVariableIsNotInferred(t *testing.T) {
	t.Parallel()
	entry := catalogdomain.MCPServer{
		Code: "com.example/mcp",
		URL:  "https://{host}/mcp",
		URLVariables: []catalogdomain.MCPURLVariable{{
			Name:     "host",
			Required: true,
		}},
		OAuth: &catalogdomain.MCPOAuth{
			Scopes:   []string{"catalog"},
			Resource: "https://{host}/mcp",
		},
	}
	cfg := &registrydomain.MCPAuth{
		Scopes:       []string{"stored"},
		Resource:     "https://mcp.example.com/mcp",
		AuthorizeURL: "https://auth.example/authorize",
		TokenURL:     "https://auth.example/token",
	}
	reg := &registrydomain.Registry{MCPTarget: &registrydomain.MCPTarget{
		Code: entry.Code,
		URL:  "https://mcp.example.com/mcp",
		Auth: cfg,
	}}
	res := upstreamResolution{url: "https://mcp.example.com/mcp", ready: true}
	if catalogServerMatches(entry, res) {
		t.Fatal("an open variable was inferred from the row URL")
	}
	got := applyCatalog(cfg, reg, fixedAuthCatalog{entry: entry}, res)
	if got != cfg {
		t.Fatalf("open variable changed the row: %+v", got)
	}
}

// Two listed options that canonicalize to the same URL are not a unique
// match, so neither is applied.
func TestCatalogServerMatches_ClosedOptionMustBeUnique(t *testing.T) {
	t.Parallel()
	entry := catalogdomain.MCPServer{
		Code: "com.example/mcp",
		URL:  "https://{host}/mcp",
		URLVariables: []catalogdomain.MCPURLVariable{{
			Name:     "host",
			Required: true,
			Options: []catalogdomain.MCPURLVariableOption{
				{Value: "mcp.example.com", Label: "Lower"},
				{Value: "MCP.example.com", Label: "Upper"},
			},
		}},
		OAuth: &catalogdomain.MCPOAuth{
			Scopes:   []string{"catalog"},
			Resource: "https://{host}/mcp",
		},
	}
	cfg := &registrydomain.MCPAuth{
		Scopes:   []string{"stored"},
		Resource: "https://old.example/mcp",
	}
	reg := &registrydomain.Registry{MCPTarget: &registrydomain.MCPTarget{
		Code: entry.Code,
		URL:  "https://mcp.example.com/mcp",
		Auth: cfg,
	}}
	res := upstreamResolution{url: "https://mcp.example.com/mcp", ready: true}
	if catalogServerMatches(entry, res) {
		t.Fatal("two options resolved to the same URL and still matched")
	}
	got := applyCatalog(cfg, reg, fixedAuthCatalog{entry: entry}, res)
	if got != cfg {
		t.Fatalf("ambiguous options changed the row: %+v", got)
	}
}

func assertPagerDutyCatalogAuth(t *testing.T, got *registrydomain.MCPAuth, entry catalogdomain.MCPServer, resource string) {
	t.Helper()
	if got == nil {
		t.Fatal("auth is nil")
	}
	if !slices.Equal(got.Scopes, entry.OAuth.Scopes) {
		t.Fatalf("scopes = %q, want catalog scopes %q", got.Scopes, entry.OAuth.Scopes)
	}
	if got.Resource != resource {
		t.Fatalf("resource = %q, want %s", got.Resource, resource)
	}
	if strings.ContainsAny(got.Resource, "{}") {
		t.Fatalf("resource %q is still a template", got.Resource)
	}
	if got.AuthorizeURL != pagerdutyAuthorize || got.TokenURL != pagerdutyToken {
		t.Fatalf("endpoints = %s %s, want the global authorize and token URLs", got.AuthorizeURL, got.TokenURL)
	}
}

func pagerdutyCatalog(t *testing.T) (authCatalog, catalogdomain.MCPServer) {
	t.Helper()
	cat, err := appcatalog.NewMCPServerCatalog(nil)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	entry, ok := cat.GetByCode(pagerdutyCode)
	if !ok || entry.OAuth == nil {
		t.Fatalf("missing catalog entry %s", pagerdutyCode)
	}
	return cat, entry
}

type fixedAuthCatalog struct {
	entry catalogdomain.MCPServer
}

func (c fixedAuthCatalog) GetByCode(code string) (catalogdomain.MCPServer, bool) {
	if code != c.entry.Code {
		return catalogdomain.MCPServer{}, false
	}
	return c.entry, true
}

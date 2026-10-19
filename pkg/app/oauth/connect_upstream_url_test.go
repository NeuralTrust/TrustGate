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
	"sort"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type recordingRegistrar struct{ discovered []string }

func (r *recordingRegistrar) Discover(_ context.Context, upstreamURL string) (*UpstreamAuthServer, error) {
	r.discovered = append(r.discovered, upstreamURL)
	return &UpstreamAuthServer{}, nil
}

func (r *recordingRegistrar) EnsureClient(context.Context, string, *UpstreamAuthServer, string) (*RegisteredClient, error) {
	return &RegisteredClient{}, nil
}

func (r *recordingRegistrar) CachedClient(context.Context, string) (*RegisteredClient, error) {
	return nil, nil
}

func (r *recordingRegistrar) DropCachedClient(context.Context, string, string) error { return nil }

type staticURLValues map[string]map[string]string

func (v staticURLValues) Values(_ context.Context, _ ids.GatewayID, principalSub string, _ *registrydomain.Registry) (map[string]string, error) {
	return v[principalSub], nil
}

func awsRegistry() *registrydomain.Registry {
	return &registrydomain.Registry{MCPTarget: &registrydomain.MCPTarget{
		Code:         "com.amazon.aws/mcp",
		URL:          "https://aws-mcp.{region}.api.aws/mcp",
		URLVariables: []registrydomain.MCPURLVariable{{Name: "region", Required: true}},
	}}
}

// RUN-1636: discovery was handed the template, so every {variable} server failed
// with "bad upstream url" however its values had been given.
func TestDiscoverResolvesTheTemplateForThePrincipal(t *testing.T) {
	registrar := &recordingRegistrar{}
	s := &connectService{registrar: registrar, urlValues: staticURLValues{"ana": {"region": "eu-west-1"}}}

	if _, err := s.discover(context.Background(), ids.New[ids.GatewayKind](), "ana", awsRegistry(), upstreamResolution{}); err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(registrar.discovered) != 1 || registrar.discovered[0] != "https://aws-mcp.eu-west-1.api.aws/mcp" {
		t.Fatalf("discovered %v, want the resolved URL", registrar.discovered)
	}
}

func TestDiscoverReadsARegistryThatCarriesItsOwnValues(t *testing.T) {
	registrar := &recordingRegistrar{}
	s := &connectService{registrar: registrar}
	reg := awsRegistry()
	reg.MCPTarget.InstanceConfig = map[string]string{"region": "us-east-1"}

	if _, err := s.discover(context.Background(), ids.New[ids.GatewayKind](), "ana", reg, upstreamResolution{}); err != nil {
		t.Fatalf("discover: %v", err)
	}
	if registrar.discovered[0] != "https://aws-mcp.us-east-1.api.aws/mcp" {
		t.Fatalf("discovered %v", registrar.discovered)
	}
}

func TestDiscoverAsksForSetupWhenAValueIsMissing(t *testing.T) {
	registrar := &recordingRegistrar{}
	s := &connectService{registrar: registrar, urlValues: staticURLValues{}}

	_, err := s.discover(context.Background(), ids.New[ids.GatewayKind](), "ana", awsRegistry(), upstreamResolution{})
	if !errors.Is(err, ErrUpstreamSetupRequired) || !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("want ErrUpstreamSetupRequired (validation), got %v", err)
	}
	if len(registrar.discovered) != 0 {
		t.Fatalf("nothing may be fetched without an address, discovered %v", registrar.discovered)
	}
}

// Discovery fetches from the resolved host, so it is held to the dial path's
// SSRF gate: a value cannot point it at the cluster.
func TestDiscoverRefusesAPrivateResolvedHost(t *testing.T) {
	registrar := &recordingRegistrar{}
	s := &connectService{registrar: registrar, urlValues: staticURLValues{"ana": {"domain": "localhost"}}}
	reg := &registrydomain.Registry{MCPTarget: &registrydomain.MCPTarget{
		URL:          "https://{domain}/mcp",
		URLVariables: []registrydomain.MCPURLVariable{{Name: "domain", Required: true}},
	}}

	if _, err := s.discover(context.Background(), ids.New[ids.GatewayKind](), "ana", reg, upstreamResolution{}); err == nil {
		t.Fatal("want the resolved host refused")
	}
	if len(registrar.discovered) != 0 {
		t.Fatalf("discovered %v, want nothing fetched", registrar.discovered)
	}
}

func TestUserChosenHostNames(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw    string
		chosen bool
		names  []string
	}{
		{raw: "https://{account_url}/mcp", chosen: true, names: []string{"account_url"}},
		{raw: "https://{workspace_host}/api/2.0/mcp/{path}", chosen: true, names: []string{"workspace_host"}},
		{raw: "https://{cube_host}/api/mcp", chosen: true, names: []string{"cube_host"}},
		{raw: "https://{account_url}:8443/mcp", chosen: true, names: []string{"account_url"}},
		{raw: "https://mcp.{domain}/token", chosen: true, names: []string{"domain"}},
		{raw: "https://mcp.{domain}.com/token", chosen: true, names: []string{"domain"}},
		{raw: "https://api-{domain}/token", chosen: true, names: []string{"domain"}},
		{raw: "https://{a}.{b}.com/token", chosen: true, names: []string{"a", "b"}},
		{raw: "https://{tenant}.github.io/token", chosen: true, names: []string{"tenant"}},
		{raw: "https://{tenant}.co.uk/token", chosen: true, names: []string{"tenant"}},
		{raw: "https://{domain}.aha.io/oauth/token", chosen: false},
		{raw: "https://{tenant}-be.glean.com/mcp/{server}", chosen: false},
		{raw: "https://acme.{region}.vendor.com/token", chosen: false},
		{raw: "https://mcp.example.com/{org}/oauth/authorize?realm={org}", chosen: false},
		{raw: "https://mcp.example.com/oauth/token", chosen: false},
	}
	for _, tc := range cases {
		names, chosen := userChosenHostNames(tc.raw)
		if chosen != tc.chosen {
			t.Fatalf("%s chosen = %v, want %v", tc.raw, chosen, tc.chosen)
		}
		if !tc.chosen {
			continue
		}
		if len(names) != len(tc.names) {
			t.Fatalf("%s names = %v, want %v", tc.raw, names, tc.names)
		}
		for i := range names {
			if names[i] != tc.names[i] {
				t.Fatalf("%s names = %v, want %v", tc.raw, names, tc.names)
			}
		}
	}
}

func TestNormalizeHostSuffix(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"*.snowflakecomputing.com": "snowflakecomputing.com",
		" .Cloud.Databricks.com. ": "cloud.databricks.com",
		"*.us1.dbt.com":            "us1.dbt.com",
		"com":                      "",
		"*.com":                    "",
		"co.uk":                    "",
		"*.co.uk":                  "",
		"github.io":                "",
		"localhost":                "",
		"":                         "",
		"*.{x}.com":                "",
		"vendor.com/path":          "",
	}
	for raw, want := range cases {
		if got := normalizeHostSuffix(raw); got != want {
			t.Fatalf("normalizeHostSuffix(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestPublicSuffixHost(t *testing.T) {
	t.Parallel()
	for _, host := range []string{"com", "co.uk", "github.io", "GITHUB.IO."} {
		if !publicSuffixHost(host) {
			t.Fatalf("%s should be a public suffix", host)
		}
	}
	for _, host := range []string{"acme.github.io", "evil.example", "mcp.vendor.com", "127.0.0.1", "localhost", "unused", ""} {
		if publicSuffixHost(host) {
			t.Fatalf("%s should not be a public suffix", host)
		}
	}
}

func TestSubstituteContactURLRejectsPublicSuffixHost(t *testing.T) {
	t.Parallel()
	vars := []registrydomain.MCPURLVariable{{
		Name:    "host",
		Options: []registrydomain.MCPURLVariableOption{{Value: "github.io", Label: "Pages"}},
	}}
	got, err := substituteContactURL("https://{host}/oauth/token", "https://github.io/mcp", vars, map[string]string{"host": "github.io"})
	if !errors.Is(err, ErrOAuthURLHost) || got != "" {
		t.Fatalf("closed public-suffix host: got %q err %v", got, err)
	}
	if strings.Contains(err.Error(), "github.io") {
		t.Fatalf("error names the rejected host: %v", err)
	}
}

func TestDeclaredSuffixMatchesIgnoresPublicSuffixHost(t *testing.T) {
	t.Parallel()
	vars := []registrydomain.MCPURLVariable{{
		Name:       "host",
		HostSuffix: []string{"*.github.io", "*.co.uk", "com"},
	}}
	if declaredSuffixMatches("github.io", []string{"host"}, vars) || declaredSuffixMatches("co.uk", []string{"host"}, vars) {
		t.Fatal("a public-suffix host matched a suffix")
	}
}

func TestSameContactOrigin(t *testing.T) {
	t.Parallel()
	cases := []struct {
		contact  string
		upstream string
		same     bool
	}{
		{contact: "https://acme.aha.io/oauth/token", upstream: "https://acme.aha.io/api/v1/mcp", same: true},
		{contact: "https://acme.aha.io:443/oauth/token", upstream: "https://acme.aha.io/api/v1/mcp", same: true},
		{contact: "https://ACME.aha.io/oauth/token", upstream: "https://acme.aha.io/mcp", same: true},
		{contact: "https://acme.aha.io:8443/oauth/token", upstream: "https://acme.aha.io/api/v1/mcp", same: false},
		{contact: "http://acme.aha.io/oauth/token", upstream: "https://acme.aha.io/api/v1/mcp", same: false},
		{contact: "https://evil.test/oauth/token", upstream: "https://acme.aha.io/mcp", same: false},
		{contact: "https://user:pass@acme.aha.io/oauth/token", upstream: "https://acme.aha.io/mcp", same: false},
	}
	for _, tc := range cases {
		if got := sameContactOrigin(tc.contact, tc.upstream); got != tc.same {
			t.Fatalf("sameContactOrigin(%q, %q) = %v, want %v", tc.contact, tc.upstream, got, tc.same)
		}
	}
}

func TestDeclaredSuffixMatches(t *testing.T) {
	t.Parallel()
	vars := []registrydomain.MCPURLVariable{{
		Name:       "account_url",
		HostSuffix: []string{"*.vendor.com", "com", "*.other.example"},
	}}
	if !declaredSuffixMatches("acme.vendor.com", []string{"account_url"}, vars) {
		t.Fatal("expected a subdomain of the declared suffix")
	}
	if !declaredSuffixMatches("vendor.com", []string{"account_url"}, vars) {
		t.Fatal("expected the suffix itself")
	}
	if !declaredSuffixMatches("acme.other.example", []string{"account_url"}, vars) {
		t.Fatal("expected a later suffix in the list")
	}
	if declaredSuffixMatches("evilvendor.com", []string{"account_url"}, vars) ||
		declaredSuffixMatches("evil.example", []string{"account_url"}, vars) ||
		declaredSuffixMatches("evil.com", []string{"account_url"}, vars) {
		t.Fatal("suffix matched a host outside it")
	}
}

type suffixCatalog struct {
	entry catalogdomain.MCPServer
	ok    bool
}

func (c suffixCatalog) GetByCode(code string) (catalogdomain.MCPServer, bool) {
	if !c.ok || code != c.entry.Code {
		return catalogdomain.MCPServer{}, false
	}
	return c.entry, true
}

func TestHostBoundURLVariables_UsesCatalogWhenStoredSuffixIsEmpty(t *testing.T) {
	t.Parallel()
	reg := &registrydomain.Registry{MCPTarget: &registrydomain.MCPTarget{
		Code: "com.snowflake/mcp",
		URLVariables: []registrydomain.MCPURLVariable{{
			Name: "account_url",
		}},
	}}
	s := &connectService{catalog: suffixCatalog{
		ok: true,
		entry: catalogdomain.MCPServer{
			Code: "com.snowflake/mcp",
			URLVariables: []catalogdomain.MCPURLVariable{{
				Name:       "account_url",
				HostSuffix: []string{" *.snowflakecomputing.com ", "com"},
			}},
		},
	}}

	got := s.hostBoundURLVariables(reg)
	if len(got) != 1 || len(got[0].HostSuffix) != 1 || got[0].HostSuffix[0] != "snowflakecomputing.com" {
		t.Fatalf("fallback suffixes = %+v", got)
	}
	if len(reg.MCPTarget.URLVariables[0].HostSuffix) != 0 {
		t.Fatalf("stored suffix was written: %+v", reg.MCPTarget.URLVariables[0].HostSuffix)
	}
}

func snowflakeSuffixCatalog(suffixes ...string) suffixCatalog {
	return suffixCatalog{
		ok: true,
		entry: catalogdomain.MCPServer{
			Code: "com.snowflake/mcp",
			URLVariables: []catalogdomain.MCPURLVariable{{
				Name:       "account_url",
				HostSuffix: suffixes,
			}},
		},
	}
}

func storedSuffixRegistry(suffixes ...string) *registrydomain.Registry {
	return &registrydomain.Registry{MCPTarget: &registrydomain.MCPTarget{
		Code: "com.snowflake/mcp",
		URLVariables: []registrydomain.MCPURLVariable{{
			Name:       "account_url",
			HostSuffix: suffixes,
		}},
	}}
}

func TestHostBoundURLVariables_StoredSuffixCannotWiden(t *testing.T) {
	t.Parallel()
	s := &connectService{catalog: snowflakeSuffixCatalog("*.snowflakecomputing.com")}

	got := s.hostBoundURLVariables(storedSuffixRegistry("*.stored.example", "*.snowflakecomputing.com"))
	if len(got) != 1 || len(got[0].HostSuffix) != 1 || got[0].HostSuffix[0] != "snowflakecomputing.com" {
		t.Fatalf("stored suffix widened the catalog: %+v", got)
	}

	got = s.hostBoundURLVariables(storedSuffixRegistry("*.stored.example"))
	if len(got) != 1 || len(got[0].HostSuffix) != 0 {
		t.Fatalf("a stored suffix outside the catalog must leave none: %+v", got)
	}
}

func TestHostBoundURLVariables_StoredSuffixNarrows(t *testing.T) {
	t.Parallel()
	s := &connectService{catalog: snowflakeSuffixCatalog("*.snowflakecomputing.com")}

	got := s.hostBoundURLVariables(storedSuffixRegistry("*.privatelink.snowflakecomputing.com"))
	if len(got) != 1 || len(got[0].HostSuffix) != 1 || got[0].HostSuffix[0] != "privatelink.snowflakecomputing.com" {
		t.Fatalf("narrower stored suffix = %+v", got)
	}
}

func TestHostBoundURLVariables_CatalogWithoutSuffixIgnoresStored(t *testing.T) {
	t.Parallel()
	s := &connectService{catalog: snowflakeSuffixCatalog()}

	got := s.hostBoundURLVariables(storedSuffixRegistry("*.snowflakecomputing.com"))
	if len(got) != 1 || len(got[0].HostSuffix) != 0 {
		t.Fatalf("stored suffix used without a catalog suffix: %+v", got)
	}
}

type prmRegistrar struct {
	recordingRegistrar
	resource string
}

func (r *prmRegistrar) Discover(ctx context.Context, upstreamURL string) (*UpstreamAuthServer, error) {
	_, _ = r.recordingRegistrar.Discover(ctx, upstreamURL)
	return &UpstreamAuthServer{Resource: r.resource}, nil
}

func TestDiscoverDropsAMismatchedProtectedResource(t *testing.T) {
	t.Parallel()
	reg := &registrydomain.Registry{MCPTarget: &registrydomain.MCPTarget{URL: "https://mcp.linear.app/mcp"}}

	s := &connectService{registrar: &prmRegistrar{resource: "https://evil.example/mcp"}}
	meta, err := s.discover(context.Background(), ids.New[ids.GatewayKind](), "", reg, upstreamResolution{})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if meta.Resource != "" {
		t.Fatalf("mismatched resource kept: %q", meta.Resource)
	}

	s = &connectService{registrar: &prmRegistrar{resource: "https://MCP.linear.app:443/mcp"}}
	meta, err = s.discover(context.Background(), ids.New[ids.GatewayKind](), "", reg, upstreamResolution{})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if meta.Resource == "" {
		t.Fatal("matching resource dropped")
	}
}

func TestHostBoundURLVariables_SkipsARegistryWithoutACatalogCode(t *testing.T) {
	t.Parallel()
	reg := &registrydomain.Registry{MCPTarget: &registrydomain.MCPTarget{
		URLVariables: []registrydomain.MCPURLVariable{{Name: "account_url"}},
	}}
	s := &connectService{catalog: suffixCatalog{
		ok: true,
		entry: catalogdomain.MCPServer{
			Code: "com.snowflake/mcp",
			URLVariables: []catalogdomain.MCPURLVariable{{
				Name:       "account_url",
				HostSuffix: []string{"*.snowflakecomputing.com"},
			}},
		},
	}}
	got := s.hostBoundURLVariables(reg)
	if len(got) != 1 || len(got[0].HostSuffix) != 0 {
		t.Fatalf("suffix applied without a catalog code: %+v", got)
	}
}

func TestDiscoverLeavesAFixedURLAlone(t *testing.T) {
	registrar := &recordingRegistrar{}
	s := &connectService{registrar: registrar}
	reg := &registrydomain.Registry{MCPTarget: &registrydomain.MCPTarget{URL: "https://mcp.linear.app/mcp"}}

	if _, err := s.discover(context.Background(), ids.New[ids.GatewayKind](), "", reg, upstreamResolution{}); err != nil {
		t.Fatalf("discover: %v", err)
	}
	if registrar.discovered[0] != "https://mcp.linear.app/mcp" {
		t.Fatalf("discovered %v", registrar.discovered)
	}
}

// TestCrossDomainContactEligibleIsFreshworksOnly walks the real seed catalog.
// A new entry needs a security review before it is added to this set.
func TestCrossDomainContactEligibleIsFreshworksOnly(t *testing.T) {
	cat, err := catalog.NewMCPServerCatalog(nil)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	var got []string
	for _, entry := range cat.ListMCPServers() {
		if crossDomainContactEligible(entry) {
			got = append(got, entry.Code)
		}
	}
	sort.Strings(got)
	want := []string{"com.freshworks/mcp"}
	if !slices.Equal(got, want) {
		t.Fatalf("cross-domain contact hosts = %v, want %v", got, want)
	}
}

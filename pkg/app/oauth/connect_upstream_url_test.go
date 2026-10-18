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
	"testing"

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

	if _, err := s.discover(context.Background(), ids.New[ids.GatewayKind](), "ana", awsRegistry()); err != nil {
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

	if _, err := s.discover(context.Background(), ids.New[ids.GatewayKind](), "ana", reg); err != nil {
		t.Fatalf("discover: %v", err)
	}
	if registrar.discovered[0] != "https://aws-mcp.us-east-1.api.aws/mcp" {
		t.Fatalf("discovered %v", registrar.discovered)
	}
}

func TestDiscoverAsksForSetupWhenAValueIsMissing(t *testing.T) {
	registrar := &recordingRegistrar{}
	s := &connectService{registrar: registrar, urlValues: staticURLValues{}}

	_, err := s.discover(context.Background(), ids.New[ids.GatewayKind](), "ana", awsRegistry())
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

	if _, err := s.discover(context.Background(), ids.New[ids.GatewayKind](), "ana", reg); err == nil {
		t.Fatal("want the resolved host refused")
	}
	if len(registrar.discovered) != 0 {
		t.Fatalf("discovered %v, want nothing fetched", registrar.discovered)
	}
}

func TestWholeHostVariableNames(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw   string
		whole bool
		name  string
	}{
		{raw: "https://{account_url}/mcp", whole: true, name: "account_url"},
		{raw: "https://{workspace_host}/api/2.0/mcp/{path}", whole: true, name: "workspace_host"},
		{raw: "https://{cube_host}/api/mcp", whole: true, name: "cube_host"},
		{raw: "https://{account_url}:8443/mcp", whole: true, name: "account_url"},
		{raw: "https://{domain}.aha.io/oauth/token", whole: false},
		{raw: "https://{tenant}-be.glean.com/mcp/{server}", whole: false},
		{raw: "https://aws-mcp.{region}.api.aws/mcp", whole: false},
		{raw: "https://mcp.example.com/{org}/oauth/authorize?realm={org}", whole: false},
		{raw: "https://mcp.example.com/oauth/token", whole: false},
	}
	for _, tc := range cases {
		names, whole := wholeHostVariableNames(tc.raw)
		if whole != tc.whole {
			t.Fatalf("%s whole = %v, want %v", tc.raw, whole, tc.whole)
		}
		if !tc.whole {
			continue
		}
		if len(names) != 1 || names[0] != tc.name {
			t.Fatalf("%s names = %v, want %s", tc.raw, names, tc.name)
		}
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
		HostSuffix: []string{"*.vendor.com", "*.other.example"},
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
	if declaredSuffixMatches("evilvendor.com", []string{"account_url"}, vars) || declaredSuffixMatches("evil.example", []string{"account_url"}, vars) {
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
				HostSuffix: []string{" *.snowflakecomputing.com ", "*.snowflakecomputing.cn"},
			}},
		},
	}}

	got := s.hostBoundURLVariables(reg)
	if len(got) != 1 || len(got[0].HostSuffix) != 2 || got[0].HostSuffix[0] != "*.snowflakecomputing.com" {
		t.Fatalf("fallback suffixes = %+v", got)
	}
	if len(reg.MCPTarget.URLVariables[0].HostSuffix) != 0 {
		t.Fatalf("stored suffix was written: %+v", reg.MCPTarget.URLVariables[0].HostSuffix)
	}
}

func TestHostBoundURLVariables_KeepsStoredSuffix(t *testing.T) {
	t.Parallel()
	reg := &registrydomain.Registry{MCPTarget: &registrydomain.MCPTarget{
		Code: "com.snowflake/mcp",
		URLVariables: []registrydomain.MCPURLVariable{{
			Name:       "account_url",
			HostSuffix: []string{"*.stored.example"},
		}},
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
	if len(got) != 1 || len(got[0].HostSuffix) != 1 || got[0].HostSuffix[0] != "*.stored.example" {
		t.Fatalf("stored suffix replaced: %+v", got)
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

	if _, err := s.discover(context.Background(), ids.New[ids.GatewayKind](), "", reg); err != nil {
		t.Fatalf("discover: %v", err)
	}
	if registrar.discovered[0] != "https://mcp.linear.app/mcp" {
		t.Fatalf("discovered %v", registrar.discovered)
	}
}

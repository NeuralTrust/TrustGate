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

package registry_test

import (
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/require"
)

func forwardedRegistry(t *testing.T, name, url, provider, resource string) *domain.Registry {
	t.Helper()
	reg, err := domain.NewMCPRegistry(ids.New[ids.GatewayKind](), name, "", &domain.MCPTarget{
		URL:  url,
		Code: "app.linear/mcp",
		Auth: &domain.MCPAuth{
			Mode:         domain.MCPAuthModeForwarded,
			Provider:     provider,
			Resource:     resource,
			ClientID:     "cid",
			AuthorizeURL: "https://idp.example.com/a",
			TokenURL:     "https://idp.example.com/t",
		},
	})
	require.NoError(t, err)
	return reg
}

func TestForwardedVaultProvider_SeparatesInstancesOfOneCode(t *testing.T) {
	t.Parallel()
	// Two instances of the same catalog code, each pointing at its own
	// deployment: one credential per workspace, so the token minted for one is
	// never forwarded to the other.
	develop := forwardedRegistry(t, "Linear Develop", "https://develop.linear.app/mcp", "app.linear/mcp", "")
	prod := forwardedRegistry(t, "Linear Prod", "https://prod.linear.app/mcp", "app.linear/mcp", "")

	require.NotEqual(t, domain.ForwardedVaultProvider(develop), domain.ForwardedVaultProvider(prod))
	for _, reg := range []*domain.Registry{develop, prod} {
		key := domain.ForwardedVaultProvider(reg)
		require.True(t, strings.HasPrefix(key, "app.linear/mcp|"), "key %q keeps the provider readable", key)
		require.Equal(t, "app.linear/mcp", domain.ForwardedVaultProviderName(key))
	}
}

func TestForwardedVaultProvider_SharesOneDeployment(t *testing.T) {
	t.Parallel()
	// Same deployment, two registries (different toolkits, say): one credential,
	// so the user connects once and both instances work.
	full := forwardedRegistry(t, "Linear", "https://mcp.linear.app/mcp", "app.linear/mcp", "")
	readOnly := forwardedRegistry(t, "Linear read-only", "https://mcp.linear.app/mcp/", "app.linear/mcp", "")

	require.Equal(t, domain.ForwardedVaultProvider(full), domain.ForwardedVaultProvider(readOnly))
}

func TestForwardedVaultProvider_PrefersTheDeclaredResource(t *testing.T) {
	t.Parallel()
	// The OAuth resource is what the token is issued for, so it wins over the
	// URL the gateway happens to dial.
	viaAlias := forwardedRegistry(t, "Linear alias", "https://alias.linear.app/mcp", "app.linear/mcp", "https://mcp.linear.app/mcp")
	direct := forwardedRegistry(t, "Linear", "https://mcp.linear.app/mcp", "app.linear/mcp", "https://MCP.linear.app:443/mcp/")

	require.Equal(t, domain.ForwardedVaultProvider(viaAlias), domain.ForwardedVaultProvider(direct))
}

func TestForwardedVaultProvider_IgnoresWhatDoesNotForward(t *testing.T) {
	t.Parallel()
	reg, err := domain.NewMCPRegistry(ids.New[ids.GatewayKind](), "static", "", &domain.MCPTarget{
		URL:  "https://mcp.linear.app/mcp",
		Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer k"},
	})
	require.NoError(t, err)

	require.Empty(t, domain.ForwardedVaultProvider(reg))
	require.Empty(t, domain.ForwardedCredentialResource(reg))
	require.Nil(t, reg.ForwardedAuth())
}

func pagerDutyHostOptions() []domain.MCPURLVariable {
	return []domain.MCPURLVariable{{
		Name:     "host",
		Required: true,
		Options: []domain.MCPURLVariableOption{
			{Value: "mcp.pagerduty.com", Label: "United States"},
			{Value: "mcp.eu.pagerduty.com", Label: "Europe"},
		},
	}}
}

func pagerDutyTemplated(t *testing.T, gw ids.GatewayID, name string, config map[string]string) *domain.Registry {
	t.Helper()
	reg, err := domain.NewMCPRegistry(gw, name, "", &domain.MCPTarget{
		Code:         "com.pagerduty/mcp",
		URL:          "https://{host}/mcp",
		URLVariables: pagerDutyHostOptions(),
		Auth: &domain.MCPAuth{
			Mode:                domain.MCPAuthModeForwarded,
			Provider:            "com.pagerduty/mcp",
			Registration:        domain.RegistrationManual,
			ClientID:            "pagerduty-client",
			AuthorizeURL:        "https://app.pagerduty.com/global/oauth/authorize",
			TokenURL:            "https://app.pagerduty.com/global/oauth/token",
			Resource:            "https://{host}/mcp",
			ResourcePerInstance: true,
		},
	})
	require.NoError(t, err)
	reg.MCPTarget.InstanceConfig = config
	return reg
}

// Per-user installs keep the catalog template on the shelf. The vault key
// fills the closed host from instance config, so US and EU in one gateway
// do not overwrite each other's token.
func TestForwardedVaultProvider_PagerDutyTemplatedRegionsDoNotOverwrite(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	us := pagerDutyTemplated(t, gw, "PagerDuty US", map[string]string{"host": "mcp.pagerduty.com"})
	eu := pagerDutyTemplated(t, gw, "PagerDuty EU", map[string]string{"host": "mcp.eu.pagerduty.com"})
	bare := pagerDutyTemplated(t, gw, "PagerDuty", nil)

	usKey := domain.ForwardedVaultProvider(us)
	euKey := domain.ForwardedVaultProvider(eu)
	require.NotEqual(t, usKey, euKey)
	require.NotEqual(t, usKey, domain.ForwardedVaultProvider(bare))
	require.Equal(t, "https://mcp.pagerduty.com/mcp", domain.ForwardedCredentialResource(us))
	require.Equal(t, "https://mcp.eu.pagerduty.com/mcp", domain.ForwardedCredentialResource(eu))
	require.Equal(t, "https://{host}/mcp", domain.ForwardedCredentialResource(bare))
	require.Contains(t, usKey, "|a7055965e374")
	require.Contains(t, euKey, "|b35ba3004532")
	require.Contains(t, domain.ForwardedVaultProvider(bare), "|17636ceb2ec1")

	tokens := map[string]string{usKey: "us-token"}
	tokens[euKey] = "eu-token"
	require.Equal(t, "us-token", tokens[domain.ForwardedVaultProvider(us)])
	require.Equal(t, "eu-token", tokens[domain.ForwardedVaultProvider(eu)])
	require.Equal(t, usKey, domain.ForwardedVaultProvider(us))
}

// Rows whose catalog resource is not a per-instance template keep the
// template fingerprint they were stored under on develop (17636ceb2ec1),
// including a New Relic or Vanta row an admin saved with their own client
// and a custom manual or empty-registration fixed host.
func TestForwardedVaultProvider_ExistingTemplateKeysStayPut(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()

	open, err := domain.NewMCPRegistry(gw, "Aha", "", &domain.MCPTarget{
		URL:          "https://{domain}.aha.io/api/v1/mcp",
		URLVariables: []domain.MCPURLVariable{{Name: "domain", Required: true}},
		Auth: &domain.MCPAuth{
			Mode:         domain.MCPAuthModeForwarded,
			Provider:     "io.aha/mcp",
			Registration: domain.RegistrationManual,
			ClientID:     "aha-client",
			AuthorizeURL: "https://acme.aha.io/oauth/authorize",
			TokenURL:     "https://acme.aha.io/oauth/token",
			Resource:     "https://{domain}.aha.io/api/v1/mcp",
		},
	})
	require.NoError(t, err)
	openKey := domain.ForwardedVaultProvider(open)
	open.MCPTarget.InstanceConfig = map[string]string{"domain": "acme"}
	require.Equal(t, openKey, domain.ForwardedVaultProvider(open))
	require.Contains(t, domain.ForwardedCredentialResource(open), "{domain}")

	newRelic := func(t *testing.T, host string) *domain.Registry {
		t.Helper()
		reg, err := domain.NewMCPRegistry(gw, "New Relic", "", &domain.MCPTarget{
			URL: "https://{host}/mcp/",
			URLVariables: []domain.MCPURLVariable{{
				Name:     "host",
				Required: true,
				Options: []domain.MCPURLVariableOption{
					{Value: "mcp.newrelic.com", Label: "United States"},
					{Value: "mcp.eu.newrelic.com", Label: "Europe"},
				},
			}},
			Auth: &domain.MCPAuth{
				Mode:         domain.MCPAuthModeForwarded,
				Provider:     "com.newrelic/mcp",
				Registration: domain.RegistrationManual,
				ClientID:     "own-client",
				AuthorizeURL: "https://oauth2.service.newrelic.com/oauth2/auth",
				TokenURL:     "https://oauth2.service.newrelic.com/oauth2/token",
				Resource:     "https://{host}/mcp/",
			},
		})
		require.NoError(t, err)
		reg.MCPTarget.InstanceConfig = map[string]string{"host": host}
		return reg
	}
	for _, host := range []string{"mcp.newrelic.com", "mcp.eu.newrelic.com"} {
		key := domain.ForwardedVaultProvider(newRelic(t, host))
		require.Contains(t, key, "|17636ceb2ec1", host)
		require.NotContains(t, key, "|e9cccbc4d5eb")
	}
	vanta := func(t *testing.T, host string) *domain.Registry {
		t.Helper()
		reg, err := domain.NewMCPRegistry(gw, "Vanta", "", &domain.MCPTarget{
			URL: "https://{host}/mcp",
			URLVariables: []domain.MCPURLVariable{{
				Name:     "host",
				Required: true,
				Options: []domain.MCPURLVariableOption{
					{Value: "mcp.vanta.com", Label: "United States"},
					{Value: "mcp.eu.vanta.com", Label: "Europe"},
				},
			}},
			Auth: &domain.MCPAuth{
				Mode:         domain.MCPAuthModeForwarded,
				Provider:     "com.vanta/mcp",
				Registration: domain.RegistrationManual,
				ClientID:     "own-client",
				AuthorizeURL: "https://app.vanta.com/oauth/authorize",
				TokenURL:     "https://api.vanta.com/oauth/token",
				Resource:     "https://{host}/mcp",
			},
		})
		require.NoError(t, err)
		reg.MCPTarget.InstanceConfig = map[string]string{"host": host}
		return reg
	}
	require.Contains(t, domain.ForwardedVaultProvider(vanta(t, "mcp.vanta.com")), "|17636ceb2ec1")
	require.NotContains(t, domain.ForwardedVaultProvider(vanta(t, "mcp.vanta.com")), "|443ad653eb53")
	require.Contains(t, domain.ForwardedVaultProvider(vanta(t, "mcp.eu.vanta.com")), "|17636ceb2ec1")
	require.NotContains(t, domain.ForwardedVaultProvider(vanta(t, "mcp.eu.vanta.com")), "|e613b0a67250")
	for _, registration := range []domain.MCPClientRegistration{domain.RegistrationManual, ""} {
		custom, err := domain.NewMCPRegistry(gw, "Custom", "", &domain.MCPTarget{
			URL: "https://{host}/mcp",
			URLVariables: []domain.MCPURLVariable{{
				Name:     "host",
				Required: true,
				Options:  []domain.MCPURLVariableOption{{Value: "mcp.pagerduty.com"}},
			}},
			Auth: &domain.MCPAuth{
				Mode:         domain.MCPAuthModeForwarded,
				Provider:     "com.example/mcp",
				Registration: registration,
				ClientID:     "own-client",
				AuthorizeURL: "https://example.com/oauth/authorize",
				TokenURL:     "https://example.com/oauth/token",
				Resource:     "https://{host}/mcp",
			},
		})
		require.NoError(t, err)
		custom.MCPTarget.InstanceConfig = map[string]string{"host": "mcp.pagerduty.com"}
		key := domain.ForwardedVaultProvider(custom)
		require.Contains(t, key, "|17636ceb2ec1")
		require.NotContains(t, key, "|a7055965e374")
	}

	shelf, err := domain.NewMCPRegistry(gw, "Vanta", "", &domain.MCPTarget{
		URL: "https://{host}/mcp",
		URLVariables: []domain.MCPURLVariable{{
			Name:     "host",
			Required: true,
			Options: []domain.MCPURLVariableOption{
				{Value: "mcp.vanta.com", Label: "United States"},
				{Value: "mcp.eu.vanta.com", Label: "Europe"},
			},
		}},
		Auth: &domain.MCPAuth{
			Mode:         domain.MCPAuthModeForwarded,
			Provider:     "com.vanta/mcp",
			Registration: domain.RegistrationAuto,
		},
	})
	require.NoError(t, err)
	shelfKey := domain.ForwardedVaultProvider(shelf)
	shelf.MCPTarget.InstanceConfig = map[string]string{"host": "mcp.vanta.com"}
	require.Equal(t, shelfKey, domain.ForwardedVaultProvider(shelf))
	require.Contains(t, domain.ForwardedCredentialResource(shelf), "{host}")
}

// A shared account is one token for the instance. Dial's instance config must
// not move the key off the template the connect flow saved it under.
func TestForwardedVaultProvider_SharedAccountKeepsTheTemplateKey(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	config := map[string]string{"host": "mcp.eu.pagerduty.com"}
	shared := pagerDutyTemplated(t, gw, "PagerDuty", config)
	shared.MCPTarget.Auth.Account = domain.MCPAccountShared
	own := pagerDutyTemplated(t, gw, "PagerDuty EU", config)

	require.Contains(t, domain.ForwardedVaultProvider(shared), "|17636ceb2ec1")
	require.Contains(t, domain.ForwardedVaultProviderFor(shared, config), "|17636ceb2ec1")
	require.Contains(t, domain.ForwardedVaultProvider(own), "|b35ba3004532")
	require.Contains(t, domain.ForwardedVaultProviderFor(pagerDutyTemplated(t, gw, "shelf", nil), config), "|b35ba3004532")
}

func TestForwardedVaultProviderName_LeavesAPlainKeyAlone(t *testing.T) {
	t.Parallel()
	// A URL-variable key carries no fingerprint and must not be truncated into
	// something that could collide with a provider name.
	key := domain.URLVariableVaultProvider("com.snowflake/mcp", "account_url")
	require.Equal(t, key, domain.ForwardedVaultProviderName(key))
}

func registryWithAuth(t *testing.T, gw ids.GatewayID, auth *domain.MCPAuth) *domain.Registry {
	t.Helper()
	reg, err := domain.NewMCPRegistry(gw, "notion", "", &domain.MCPTarget{URL: "https://mcp.notion.com/mcp", Auth: auth})
	require.NoError(t, err)
	return reg
}

func TestCredentialSubject(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	shared := registryWithAuth(t, gw, &domain.MCPAuth{
		Mode: domain.MCPAuthModeForwarded, Provider: "notion", ClientID: "id",
		AuthorizeURL: "https://notion/a", TokenURL: "https://notion/t",
		Account: domain.MCPAccountShared,
	})
	own := registryWithAuth(t, gw, &domain.MCPAuth{
		Mode: domain.MCPAuthModeForwarded, Provider: "notion", ClientID: "id",
		AuthorizeURL: "https://notion/a", TokenURL: "https://notion/t",
	})

	// The instance, not the catalog code: two instances of one server are two
	// accounts, which is what having two instances is for.
	if got, want := domain.CredentialSubject(shared, "alice"), "instance:"+shared.ID.String(); got != want {
		t.Fatalf("shared subject = %q, want %q", got, want)
	}
	if got := domain.CredentialSubject(own, "alice"); got != "alice" {
		t.Fatalf("own subject = %q, want the caller's", got)
	}
	// A subject a person's token could never carry, so the two can never meet.
	if strings.HasPrefix(domain.CredentialSubject(shared, "alice"), "app:") {
		t.Fatal("a shared account must not land in an application's namespace")
	}
}

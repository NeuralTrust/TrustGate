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

package registry

import (
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/require"
)

type stubCatalog struct {
	entries map[string]catalogdomain.MCPServer
	shared  map[string]stubSharedOAuth
}

type stubSharedOAuth struct {
	clientID     string
	clientSecret string
}

func (s stubCatalog) GetByCode(code string) (catalogdomain.MCPServer, bool) {
	e, ok := s.entries[code]
	return e, ok
}

func (s stubCatalog) SharedOAuthCredentials(code string) (string, string, bool) {
	if s.shared == nil {
		return "", "", false
	}
	creds, ok := s.shared[code]
	return creds.clientID, creds.clientSecret, ok
}

func TestCanonicalizeMCPAuthFromCatalog_ClientCredentials(t *testing.T) {
	t.Parallel()
	cat := stubCatalog{entries: map[string]catalogdomain.MCPServer{
		"com.sectigo/mcp": {
			Code: "com.sectigo/mcp",
			URL:  "https://mcp.{instance}.sectigo.com/mcp",
			OAuth: &catalogdomain.MCPOAuth{
				Required:                true,
				ResourceMetadata:        true,
				GrantType:               "client_credentials",
				TokenURL:                "https://auth.sso.sectigo.com/token",
				TokenEndpointAuthMethod: domain.TokenEndpointAuthClientSecretBasic,
			},
		},
	}}
	target := &domain.MCPTarget{
		Code: "com.sectigo/mcp",
		URL:  "https://mcp.enterprise.sectigo.com/mcp",
		Auth: &domain.MCPAuth{
			Mode:         domain.MCPAuthModeClientCredentials,
			ClientID:     "cid",
			ClientSecret: "csecret",
			TokenURL:     "https://evil.example/token",
		},
	}
	require.NoError(t, CanonicalizeMCPAuthFromCatalog(target, cat))
	require.Equal(t, "https://auth.sso.sectigo.com/token", target.Auth.TokenURL)
	require.Equal(t, domain.TokenEndpointAuthClientSecretBasic, target.Auth.TokenEndpointAuthMethod)
	require.Equal(t, "https://mcp.enterprise.sectigo.com/mcp", target.Auth.Resource)
	require.Equal(t, "cid", target.Auth.ClientID)
	require.Equal(t, "csecret", target.Auth.ClientSecret)
}

func TestCanonicalizeMCPAuthFromCatalog_RejectsWrongMode(t *testing.T) {
	t.Parallel()
	cat := stubCatalog{entries: map[string]catalogdomain.MCPServer{
		"com.sectigo/mcp": {
			Code: "com.sectigo/mcp",
			OAuth: &catalogdomain.MCPOAuth{
				Required:  true,
				GrantType: "client_credentials",
				TokenURL:  "https://auth.sso.sectigo.com/token",
			},
		},
	}}
	target := &domain.MCPTarget{
		Code: "com.sectigo/mcp",
		URL:  "https://mcp.enterprise.sectigo.com/mcp",
		Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer x"},
	}
	require.Error(t, CanonicalizeMCPAuthFromCatalog(target, cat))
}

func TestCanonicalizeMCPAuthFromCatalog_DropsClientResourceWithoutCatalogAudience(t *testing.T) {
	t.Parallel()
	cat := stubCatalog{entries: map[string]catalogdomain.MCPServer{
		"com.acme/mcp": {
			Code: "com.acme/mcp",
			OAuth: &catalogdomain.MCPOAuth{
				Required:  true,
				GrantType: "client_credentials",
				TokenURL:  "https://idp.acme/token",
			},
		},
	}}
	target := &domain.MCPTarget{
		Code: "com.acme/mcp",
		URL:  "https://mcp.acme/mcp",
		Auth: &domain.MCPAuth{
			Mode:     domain.MCPAuthModeClientCredentials,
			ClientID: "cid", ClientSecret: "csecret",
			Resource: "https://attacker.example/audience",
		},
	}
	require.NoError(t, CanonicalizeMCPAuthFromCatalog(target, cat))
	require.Empty(t, target.Auth.Resource)
}

func TestCanonicalizeMCPAuthFromCatalog_FailsClosedWithoutCatalog(t *testing.T) {
	t.Parallel()
	target := &domain.MCPTarget{
		Code: "com.sectigo/mcp",
		URL:  "https://mcp.enterprise.sectigo.com/mcp",
		Auth: &domain.MCPAuth{
			Mode:     domain.MCPAuthModeClientCredentials,
			ClientID: "cid", ClientSecret: "csecret",
			TokenURL: "https://evil.example/token",
		},
	}
	require.Error(t, CanonicalizeMCPAuthFromCatalog(target, nil))
}

func TestCanonicalizeMCPAuthFromCatalog_SkipsNonCatalog(t *testing.T) {
	t.Parallel()
	target := &domain.MCPTarget{
		URL:  "https://custom.example/mcp",
		Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeNone},
	}
	require.NoError(t, CanonicalizeMCPAuthFromCatalog(target, stubCatalog{}))
}

func TestCanonicalizeMCPAuthFromCatalog_ManualOAuthFillsEndpoints(t *testing.T) {
	t.Parallel()
	cat := gmailCatalog(nil)
	target := &domain.MCPTarget{
		Code: "com.google.workspace/gmail",
		URL:  "https://gmailmcp.googleapis.com/mcp/v1",
		Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeForwarded, Provider: "com.google.workspace/gmail", Registration: domain.RegistrationManual},
	}
	require.NoError(t, CanonicalizeMCPAuthFromCatalog(target, cat))
	require.Equal(t, "https://accounts.google.com/o/oauth2/v2/auth", target.Auth.AuthorizeURL)
	require.Equal(t, "https://oauth2.googleapis.com/token", target.Auth.TokenURL)
	require.Equal(t, []string{"https://www.googleapis.com/auth/gmail.readonly"}, target.Auth.Scopes)
	require.Equal(t, "https://gmailmcp.googleapis.com/mcp/v1", target.Auth.Resource)
	require.Empty(t, target.Auth.ClientID)
}

func TestCanonicalizeMCPAuthFromCatalog_ManualOAuthAllowsEndpointDiscovery(t *testing.T) {
	t.Parallel()
	cat := stubCatalog{entries: map[string]catalogdomain.MCPServer{
		"com.snowflake/mcp": {
			Code: "com.snowflake/mcp",
			OAuth: &catalogdomain.MCPOAuth{
				Required:         true,
				ResourceMetadata: true,
				Registration:     "manual",
			},
		},
	}}
	target := &domain.MCPTarget{
		Code: "com.snowflake/mcp",
		URL:  "https://account.snowflakecomputing.com/api/v2/databases/db/schemas/public/mcp-servers/agent",
		Auth: &domain.MCPAuth{
			Mode:         domain.MCPAuthModeForwarded,
			Registration: domain.RegistrationManual,
			ClientID:     "client-id",
		},
	}

	require.NoError(t, CanonicalizeMCPAuthFromCatalog(target, cat))
	require.Empty(t, target.Auth.AuthorizeURL)
	require.Empty(t, target.Auth.TokenURL)
	require.Equal(t, target.URL, target.Auth.Resource)
	require.NoError(t, target.Validate())
}

func TestCanonicalizeMCPAuthFromCatalog_BindsSharedOAuthWithoutSecret(t *testing.T) {
	t.Parallel()
	cat := gmailCatalog(map[string]stubSharedOAuth{
		"com.google.workspace/gmail": {clientID: "nt-client", clientSecret: "nt-secret"},
	})
	target := &domain.MCPTarget{
		Code: "com.google.workspace/gmail",
		URL:  "https://gmailmcp.googleapis.com/mcp/v1",
		Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeForwarded, Registration: domain.RegistrationManual},
	}
	require.NoError(t, CanonicalizeMCPAuthFromCatalog(target, cat))
	require.Equal(t, "nt-client", target.Auth.ClientID)
	require.Empty(t, target.Auth.ClientSecret, "the shared client secret is resolved at use time, never stored")
	require.Equal(t, "com.google.workspace/gmail", target.Auth.Provider)
	require.NoError(t, target.Validate())
}

func TestCanonicalizeMCPAuthFromCatalog_PreservesBYOClient(t *testing.T) {
	t.Parallel()
	cat := gmailCatalog(map[string]stubSharedOAuth{
		"com.google.workspace/gmail": {clientID: "nt-client", clientSecret: "nt-secret"},
	})
	target := &domain.MCPTarget{
		Code: "com.google.workspace/gmail",
		URL:  "https://gmailmcp.googleapis.com/mcp/v1",
		Auth: &domain.MCPAuth{
			Mode:         domain.MCPAuthModeForwarded,
			Registration: domain.RegistrationManual,
			ClientID:     "customer-client",
			ClientSecret: "customer-secret",
		},
	}
	require.NoError(t, CanonicalizeMCPAuthFromCatalog(target, cat))
	require.Equal(t, "customer-client", target.Auth.ClientID)
	require.Equal(t, "customer-secret", target.Auth.ClientSecret)
}

func TestCanonicalizeMCPAuthFromCatalog_ClearsStoredPlatformClientSecret(t *testing.T) {
	t.Parallel()
	cat := gmailCatalog(map[string]stubSharedOAuth{
		"com.google.workspace/gmail": {clientID: "nt-client", clientSecret: "rotated-secret"},
	})
	target := &domain.MCPTarget{
		Code: "com.google.workspace/gmail",
		URL:  "https://gmailmcp.googleapis.com/mcp/v1",
		Auth: &domain.MCPAuth{
			Mode:         domain.MCPAuthModeForwarded,
			Registration: domain.RegistrationManual,
			ClientID:     "nt-client",
			ClientSecret: "stale-secret",
		},
	}
	require.NoError(t, CanonicalizeMCPAuthFromCatalog(target, cat))
	require.Equal(t, "nt-client", target.Auth.ClientID)
	require.Empty(t, target.Auth.ClientSecret)
	require.NoError(t, target.Validate())
}

func gmailCatalog(shared map[string]stubSharedOAuth) stubCatalog {
	return stubCatalog{
		entries: map[string]catalogdomain.MCPServer{
			"com.google.workspace/gmail": {
				Code: "com.google.workspace/gmail",
				URL:  "https://gmailmcp.googleapis.com/mcp/v1",
				OAuth: &catalogdomain.MCPOAuth{
					Required:     true,
					Registration: "manual",
					AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
					TokenURL:     "https://oauth2.googleapis.com/token",
					Scopes:       []string{"https://www.googleapis.com/auth/gmail.readonly"},
					Resource:     "https://gmailmcp.googleapis.com/mcp/v1",
				},
			},
		},
		shared: shared,
	}
}

func TestCanonicalizeMCPAuthFromCatalog_StaticAcceptedOnDualAuthEntry(t *testing.T) {
	t.Parallel()
	target := githubTarget()
	target.Auth = &domain.MCPAuth{
		Mode:   domain.MCPAuthModeStatic,
		Header: "Authorization",
		Value:  "Bearer ghp_token",
	}
	require.NoError(t, CanonicalizeMCPAuthFromCatalog(target, githubCatalog(nil)))
	require.Equal(t, domain.MCPAuthModeStatic, target.Auth.Mode)
	require.Equal(t, "Authorization", target.Auth.Header)
	require.Equal(t, "Bearer ghp_token", target.Auth.Value)
	require.NoError(t, target.Validate())
}

func TestCanonicalizeMCPAuthFromCatalog_StaticFillsHeaderFromCatalog(t *testing.T) {
	t.Parallel()
	target := githubTarget()
	target.Auth = &domain.MCPAuth{Mode: domain.MCPAuthModeStatic, Value: "Bearer ghp_token"}
	require.NoError(t, CanonicalizeMCPAuthFromCatalog(target, githubCatalog(nil)))
	require.Equal(t, "Authorization", target.Auth.Header)
	require.NoError(t, target.Validate())
}

func TestCanonicalizeMCPAuthFromCatalog_StaticClearsOAuthFields(t *testing.T) {
	t.Parallel()
	target := githubTarget()
	target.Auth = &domain.MCPAuth{
		Mode:                    domain.MCPAuthModeStatic,
		Header:                  "Authorization",
		Value:                   "Bearer ghp_token",
		Provider:                "com.github/copilot-mcp",
		Registration:            domain.RegistrationManual,
		ClientID:                "gh-client",
		ClientSecret:            "***masked",
		AuthorizeURL:            "https://github.com/login/oauth/authorize",
		TokenURL:                "https://github.com/login/oauth/access_token",
		Scopes:                  []string{"repo"},
		Resource:                "https://api.githubcopilot.com/mcp/",
		TokenEndpointAuthMethod: domain.TokenEndpointAuthClientSecretBasic,
	}
	require.NoError(t, CanonicalizeMCPAuthFromCatalog(target, githubCatalog(nil)))
	require.Empty(t, target.Auth.Provider)
	require.Empty(t, target.Auth.Registration)
	require.Empty(t, target.Auth.ClientID)
	require.Empty(t, target.Auth.ClientSecret)
	require.Empty(t, target.Auth.AuthorizeURL)
	require.Empty(t, target.Auth.TokenURL)
	require.Empty(t, target.Auth.Scopes)
	require.Empty(t, target.Auth.Resource)
	require.Empty(t, target.Auth.TokenEndpointAuthMethod)
	require.NoError(t, target.Validate())
}

func TestCanonicalizeMCPAuthFromCatalog_ForwardedToStaticUpdate(t *testing.T) {
	t.Parallel()
	shared := map[string]stubSharedOAuth{
		"com.github/copilot-mcp": {clientID: "nt-client", clientSecret: "nt-secret"},
	}
	target := githubTarget()
	target.Auth = &domain.MCPAuth{
		Mode:         domain.MCPAuthModeStatic,
		Value:        "Bearer ghp_token",
		Provider:     "com.github/copilot-mcp",
		Registration: domain.RegistrationManual,
		ClientID:     "nt-client",
		ClientSecret: "***masked",
	}
	require.NoError(t, CanonicalizeMCPAuthFromCatalog(target, githubCatalog(shared)))
	require.Equal(t, domain.MCPAuthModeStatic, target.Auth.Mode)
	require.Empty(t, target.Auth.ClientID)
	require.Empty(t, target.Auth.ClientSecret)
	require.NoError(t, target.Validate())
}

func TestCanonicalizeMCPAuthFromCatalog_EmptyModeStillCanonicalizesToForwarded(t *testing.T) {
	t.Parallel()
	target := githubTarget()
	target.Auth = &domain.MCPAuth{}
	require.NoError(t, CanonicalizeMCPAuthFromCatalog(target, githubCatalog(nil)))
	require.Equal(t, domain.MCPAuthModeForwarded, target.Auth.Mode)
	require.Equal(t, "com.github/copilot-mcp", target.Auth.Provider)
	require.Equal(t, domain.RegistrationManual, target.Auth.Registration)
	require.Equal(t, "https://github.com/login/oauth/authorize", target.Auth.AuthorizeURL)
}

func TestCanonicalizeMCPAuthFromCatalog_RejectsStaticOnOAuthOnlyEntry(t *testing.T) {
	t.Parallel()
	target := &domain.MCPTarget{
		Code: "com.google.workspace/gmail",
		URL:  "https://gmailmcp.googleapis.com/mcp/v1",
		Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer x"},
	}
	err := CanonicalizeMCPAuthFromCatalog(target, gmailCatalog(nil))
	require.ErrorIs(t, err, commonerrors.ErrValidation)
	require.ErrorContains(t, err, "accepts auth mode forwarded")
}

func TestCanonicalizeMCPAuthFromCatalog_RejectsStaticWithoutCatalogAuthHeader(t *testing.T) {
	t.Parallel()
	cat := githubCatalog(nil)
	entry := cat.entries["com.github/copilot-mcp"]
	entry.AuthHeaders = nil
	cat.entries["com.github/copilot-mcp"] = entry
	target := githubTarget()
	target.Auth = &domain.MCPAuth{Mode: domain.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer x"}
	err := CanonicalizeMCPAuthFromCatalog(target, cat)
	require.ErrorIs(t, err, commonerrors.ErrValidation)
	require.ErrorContains(t, err, "declares no auth header")
}

func TestCanonicalizeMCPAuthFromCatalog_ClientCredentialsEntryStillRejectsStatic(t *testing.T) {
	t.Parallel()
	cat := stubCatalog{entries: map[string]catalogdomain.MCPServer{
		"com.sectigo/mcp": {
			Code: "com.sectigo/mcp",
			OAuth: &catalogdomain.MCPOAuth{
				Required:  true,
				GrantType: "client_credentials",
				TokenURL:  "https://auth.sso.sectigo.com/token",
			},
		},
	}}
	target := &domain.MCPTarget{
		Code: "com.sectigo/mcp",
		URL:  "https://mcp.enterprise.sectigo.com/mcp",
		Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer x"},
	}
	err := CanonicalizeMCPAuthFromCatalog(target, cat)
	require.ErrorIs(t, err, commonerrors.ErrValidation)
	require.ErrorContains(t, err, "accepts auth mode client_credentials")
}

func githubTarget() *domain.MCPTarget {
	return &domain.MCPTarget{
		Code:      "com.github/copilot-mcp",
		URL:       "https://api.githubcopilot.com/mcp/",
		Transport: domain.MCPTransportStreamableHTTP,
	}
}

func githubCatalog(shared map[string]stubSharedOAuth) stubCatalog {
	return stubCatalog{
		entries: map[string]catalogdomain.MCPServer{
			"com.github/copilot-mcp": {
				Code:        "com.github/copilot-mcp",
				URL:         "https://api.githubcopilot.com/mcp/",
				AuthMethods: []string{"static", "oauth"},
				AuthHeaders: []catalogdomain.MCPAuthHeader{
					{Name: "Authorization", Required: true, Secret: true, Scheme: "Bearer"},
				},
				OAuth: &catalogdomain.MCPOAuth{
					Required:     true,
					Registration: "manual",
					AuthorizeURL: "https://github.com/login/oauth/authorize",
					TokenURL:     "https://github.com/login/oauth/access_token",
					Scopes:       []string{"repo", "read:org"},
					Resource:     "https://api.githubcopilot.com/mcp/",
				},
			},
		},
		shared: shared,
	}
}

func TestCanonicalizeMCPAuthFromCatalog_SharedOAuthBindsTheClientIDOnly(t *testing.T) {
	t.Parallel()
	shared := map[string]stubSharedOAuth{
		"com.google.workspace/gmail": {clientID: "nt-client", clientSecret: "nt-secret"},
	}
	cat := gmailCatalog(shared)
	entry := cat.entries["com.google.workspace/gmail"]
	entry.OAuth.TokenURL = "https://idp.example.com/token"
	cat.entries["com.google.workspace/gmail"] = entry

	target := &domain.MCPTarget{
		Code: "com.google.workspace/gmail",
		URL:  "https://gmailmcp.googleapis.com/mcp/v1",
		Auth: &domain.MCPAuth{
			Mode:         domain.MCPAuthModeForwarded,
			Registration: domain.RegistrationManual,
			ClientID:     "own-client",
			ClientSecret: "own-secret",
		},
	}
	require.NoError(t, CanonicalizeMCPAuthFromCatalog(target, cat))
	require.Equal(t, "own-client", target.Auth.ClientID)
	require.Equal(t, "own-secret", target.Auth.ClientSecret)

	unbound := &domain.MCPTarget{
		Code: "com.google.workspace/gmail",
		URL:  "https://gmailmcp.googleapis.com/mcp/v1",
		Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeForwarded, Registration: domain.RegistrationManual},
	}
	require.NoError(t, CanonicalizeMCPAuthFromCatalog(unbound, cat))
	require.Equal(t, "nt-client", unbound.Auth.ClientID, "the shared client id is bound; its secret is only ever presented to the provider's own endpoints")
	require.Empty(t, unbound.Auth.ClientSecret)
}

// Dropbox and Jotform moved from manual registration to dynamic registration.
// A registry that already stores a client id must stay manual on re-save:
// auto registration rejects client_id, so the edit would fail until somebody
// cleared it. A save with no client id still becomes auto.
func TestCanonicalizeMCPAuthFromCatalog_StoredClientIDStaysManualWhenCatalogIsAuto(t *testing.T) {
	t.Parallel()
	for _, code := range []string{"com.dropbox/mcp", "com.jotform/mcp"} {
		t.Run(code, func(t *testing.T) {
			t.Parallel()
			cat := stubCatalog{entries: map[string]catalogdomain.MCPServer{
				code: {
					Code: code,
					URL:  "https://mcp.example.com/mcp",
					OAuth: &catalogdomain.MCPOAuth{
						Required:     true,
						Registration: "auto",
						AuthorizeURL: "https://auth.example.com/authorize",
						TokenURL:     "https://auth.example.com/token",
						Scopes:       []string{"read"},
						Resource:     "https://mcp.example.com/mcp",
					},
				},
			}}
			target := &domain.MCPTarget{
				Code: code,
				URL:  "https://mcp.example.com/mcp",
				Auth: &domain.MCPAuth{
					Mode:         domain.MCPAuthModeForwarded,
					Registration: domain.RegistrationManual,
					ClientID:     "stored-client",
					ClientSecret: "stored-secret",
					AuthorizeURL: "https://auth.example.com/authorize",
					TokenURL:     "https://auth.example.com/token",
				},
			}
			require.NoError(t, CanonicalizeMCPAuthFromCatalog(target, cat))
			require.Equal(t, domain.RegistrationManual, target.Auth.Registration)
			require.Equal(t, "stored-client", target.Auth.ClientID)
			require.Equal(t, "stored-secret", target.Auth.ClientSecret)
			require.Equal(t, []string{"read"}, target.Auth.Scopes)
			require.NoError(t, target.Validate())

			target.Auth.ClientID = "edited-client"
			require.NoError(t, CanonicalizeMCPAuthFromCatalog(target, cat))
			require.Equal(t, domain.RegistrationManual, target.Auth.Registration)
			require.Equal(t, "edited-client", target.Auth.ClientID)
			require.NoError(t, target.Validate())

			fresh := &domain.MCPTarget{
				Code: code,
				URL:  "https://mcp.example.com/mcp",
				Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeForwarded},
			}
			require.NoError(t, CanonicalizeMCPAuthFromCatalog(fresh, cat))
			require.Equal(t, domain.RegistrationAuto, fresh.Auth.Registration)
			require.Empty(t, fresh.Auth.ClientID)
			require.NoError(t, fresh.Validate())
		})
	}
}

const (
	pagerDutyCode      = "com.pagerduty/mcp"
	pagerDutyUS        = "https://mcp.pagerduty.com/mcp"
	pagerDutyEU        = "https://mcp.eu.pagerduty.com/mcp"
	pagerDutyTemplate  = "https://{host}/mcp"
	pagerDutyAuthorize = "https://app.pagerduty.com/global/oauth/authorize"
	pagerDutyToken     = "https://app.pagerduty.com/global/oauth/token"
)

func pagerDutyCatalog() stubCatalog {
	return stubCatalog{entries: map[string]catalogdomain.MCPServer{
		pagerDutyCode: {
			Code: pagerDutyCode,
			URL:  pagerDutyTemplate,
			URLVariables: []catalogdomain.MCPURLVariable{{
				Name:     "host",
				Required: true,
				Options: []catalogdomain.MCPURLVariableOption{
					{Value: "mcp.pagerduty.com", Label: "United States"},
					{Value: "mcp.eu.pagerduty.com", Label: "Europe"},
				},
			}},
			OAuth: &catalogdomain.MCPOAuth{
				Required:         true,
				ResourceMetadata: true,
				Registration:     "manual",
				AuthorizeURL:     pagerDutyAuthorize,
				TokenURL:         pagerDutyToken,
				Scopes:           []string{"read", "incidents.read", "oncalls.read", "services.read", "users.read", "openid"},
				Resource:         pagerDutyTemplate,
			},
		},
	}}
}

func pagerDutyTarget(url, resource string) *domain.MCPTarget {
	return &domain.MCPTarget{
		Code: pagerDutyCode,
		URL:  url,
		URLVariables: []domain.MCPURLVariable{{
			Name:     "host",
			Required: true,
			Options: []domain.MCPURLVariableOption{
				{Value: "mcp.pagerduty.com", Label: "United States"},
				{Value: "mcp.eu.pagerduty.com", Label: "Europe"},
			},
		}},
		Auth: &domain.MCPAuth{
			Mode:         domain.MCPAuthModeForwarded,
			Provider:     pagerDutyCode,
			Registration: domain.RegistrationManual,
			ClientID:     "pagerduty-client",
			AuthorizeURL: pagerDutyAuthorize,
			TokenURL:     pagerDutyToken,
			Resource:     resource,
			Scopes:       []string{"read"},
		},
	}
}

func forwardedVaultKey(t *testing.T, target *domain.MCPTarget) string {
	t.Helper()
	cp := *target
	auth := *target.Auth
	cp.Auth = &auth
	reg, err := domain.NewMCPRegistry(ids.New[ids.GatewayKind](), "PagerDuty", "", &cp)
	require.NoError(t, err)
	return domain.ForwardedVaultProvider(reg)
}

// An admin update echoes the catalog template into oauth.resource. The stored
// audience has to stay the concrete US resource, or the vault fingerprint
// changes and every existing token is orphaned.
func TestCanonicalizeMCPAuthFromCatalog_PagerDutyFixedURLKeepsVaultKey(t *testing.T) {
	t.Parallel()
	target := pagerDutyTarget(pagerDutyUS, pagerDutyUS)
	keyBefore := forwardedVaultKey(t, target)
	target.Auth.Resource = pagerDutyTemplate

	require.NoError(t, CanonicalizeMCPAuthFromCatalog(target, pagerDutyCatalog()))
	require.Equal(t, pagerDutyUS, target.Auth.Resource)
	require.Equal(t, keyBefore, forwardedVaultKey(t, target))
	require.NotEqual(t, keyBefore, forwardedVaultKey(t, pagerDutyTarget(pagerDutyUS, pagerDutyTemplate)))
	require.Equal(t, pagerDutyAuthorize, target.Auth.AuthorizeURL)
	require.Equal(t, pagerDutyToken, target.Auth.TokenURL)
	require.Equal(t, []string{"read", "incidents.read", "oncalls.read", "services.read", "users.read", "openid"}, target.Auth.Scopes)
}

func TestCanonicalizeMCPAuthFromCatalog_PagerDutyTemplateURLKeepsConcreteResource(t *testing.T) {
	t.Parallel()
	target := pagerDutyTarget(pagerDutyTemplate, pagerDutyUS)
	keyBefore := forwardedVaultKey(t, target)

	require.NoError(t, CanonicalizeMCPAuthFromCatalog(target, pagerDutyCatalog()))
	require.Equal(t, pagerDutyUS, target.Auth.Resource)
	require.Equal(t, keyBefore, forwardedVaultKey(t, target))
	require.Equal(t, pagerDutyAuthorize, target.Auth.AuthorizeURL)
	require.Equal(t, pagerDutyToken, target.Auth.TokenURL)
}

// Fixed-URL US and EU rows in one gateway store different audiences, so one
// connect cannot overwrite the other's vault entry.
func TestCanonicalizeMCPAuthFromCatalog_PagerDutyRegionsDoNotShareAVaultKey(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	us := pagerDutyTarget(pagerDutyUS, pagerDutyTemplate)
	eu := pagerDutyTarget(pagerDutyEU, pagerDutyTemplate)
	cat := pagerDutyCatalog()
	require.NoError(t, CanonicalizeMCPAuthFromCatalog(us, cat))
	require.NoError(t, CanonicalizeMCPAuthFromCatalog(eu, cat))
	require.Equal(t, pagerDutyUS, us.Auth.Resource)
	require.Equal(t, pagerDutyEU, eu.Auth.Resource)

	usReg, err := domain.NewMCPRegistry(gw, "PagerDuty US", "", us)
	require.NoError(t, err)
	euReg, err := domain.NewMCPRegistry(gw, "PagerDuty EU", "", eu)
	require.NoError(t, err)
	usKey := domain.ForwardedVaultProvider(usReg)
	euKey := domain.ForwardedVaultProvider(euReg)
	require.NotEqual(t, usKey, euKey)

	tokens := map[string]string{usKey: "us-token"}
	tokens[euKey] = "eu-token"
	require.Equal(t, "us-token", tokens[domain.ForwardedVaultProvider(usReg)])
	require.Equal(t, "eu-token", tokens[domain.ForwardedVaultProvider(euReg)])
}

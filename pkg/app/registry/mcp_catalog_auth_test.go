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

func TestCanonicalizeMCPAuthFromCatalog_InjectsSharedOAuth(t *testing.T) {
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
	require.Equal(t, "nt-secret", target.Auth.ClientSecret)
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

func TestCanonicalizeMCPAuthFromCatalog_RotatesMatchingPlatformClient(t *testing.T) {
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
	require.Equal(t, "rotated-secret", target.Auth.ClientSecret)
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

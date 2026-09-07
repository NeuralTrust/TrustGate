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

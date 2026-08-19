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
}

func (s stubCatalog) GetByCode(code string) (catalogdomain.MCPServer, bool) {
	e, ok := s.entries[code]
	return e, ok
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

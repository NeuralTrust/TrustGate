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
	"context"
	"testing"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// instanceCatalog is the catalog the creator canonicalises auth against.
type instanceCatalog struct {
	entries map[string]catalogdomain.MCPServer
}

func (c instanceCatalog) GetByCode(code string) (catalogdomain.MCPServer, bool) {
	entry, ok := c.entries[code]
	return entry, ok
}

func (instanceCatalog) SharedOAuthCredentials(string) (string, string, bool) {
	return "", "", false
}

// linearEntry is a server that is one URL behind per-user OAuth: nothing in its
// address or its client differs between two instances.
func linearEntry() catalogdomain.MCPServer {
	return catalogdomain.MCPServer{
		Code:         "app.linear/mcp",
		DisplayName:  "Linear",
		URL:          "https://mcp.linear.app/mcp",
		AuthHint:     "oauth",
		RequiresAuth: true,
		SelfService:  true,
		OAuth:        &catalogdomain.MCPOAuth{Required: true, Registration: "auto"},
	}
}

// snowflakeEntry is a templated URL, so two registries reach two schemas.
func snowflakeEntry() catalogdomain.MCPServer {
	return catalogdomain.MCPServer{
		Code:         "com.snowflake/mcp",
		DisplayName:  "Snowflake",
		URL:          "https://{account_url}/api/v2/databases/{database}/schemas/{schema}/mcp-servers/{server}",
		AuthHint:     "oauth",
		RequiresAuth: true,
		URLVariables: []catalogdomain.MCPURLVariable{{Name: "account_url", Required: true}},
		SelfService:  false,
		OAuth:        &catalogdomain.MCPOAuth{Required: true, Registration: "auto"},
	}
}

func catalogInput(gatewayID ids.GatewayID, name, code, url string) appregistry.CreateInput {
	return appregistry.CreateInput{
		GatewayID: gatewayID,
		Name:      name,
		Type:      domain.TypeMCP,
		// The auth these catalog entries declare: Normalize stamps a mode on every
		// target, so canonicalisation rejects the pair unless it is the one the
		// entry requires.
		MCPTarget: &domain.MCPTarget{
			URL: url, Code: code, Transport: domain.MCPTransportStreamableHTTP,
			Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeForwarded, Provider: code},
		},
	}
}

// A server with one URL and one sign-in used to hold exactly one instance: two
// of them could only differ in what an operator configured, and there was
// nothing to configure. Whose account it uses is now such a thing — one
// instance where each user connects their own, another on the account the team
// shares — so the shelf takes as many as the operator asks for.
func TestCreator_AllowsASecondInstanceOfAFixedOAuthServer(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()
	cat := instanceCatalog{entries: map[string]catalogdomain.MCPServer{"app.linear/mcp": linearEntry()}}
	creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger(), nil, cat)

	// The shelf is never even read: there is no rule left to check it against.
	registry, err := creator.Create(context.Background(),
		catalogInput(gatewayID, "Linear (shared)", "app.linear/mcp", "https://mcp.linear.app/mcp"))

	require.NoError(t, err)
	require.Equal(t, "Linear (shared)", registry.Name)
}

func TestCreator_AllowsASecondInstanceOfAConfigurableServer(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()
	cat := instanceCatalog{entries: map[string]catalogdomain.MCPServer{"com.snowflake/mcp": snowflakeEntry()}}
	creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger(), nil, cat)

	_, err := creator.Create(context.Background(), catalogInput(
		gatewayID, "Snowflake — FINANCE", "com.snowflake/mcp",
		"https://acme.snowflakecomputing.com/api/v2/databases/D/schemas/FINANCE/mcp-servers/S"))

	require.NoError(t, err)
}

// A server an operator wired by hand carries no catalog code at all.
func TestCreator_LeavesAHandWiredServerAlone(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()
	cat := instanceCatalog{entries: map[string]catalogdomain.MCPServer{}}
	creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger(), nil, cat)

	_, err := creator.Create(context.Background(), appregistry.CreateInput{
		GatewayID: gatewayID,
		Name:      "Internal tools",
		Type:      domain.TypeMCP,
		MCPTarget: &domain.MCPTarget{
			URL:       "https://mcp.internal.example.com/mcp",
			Transport: domain.MCPTransportStreamableHTTP,
		},
	})

	require.NoError(t, err)
}

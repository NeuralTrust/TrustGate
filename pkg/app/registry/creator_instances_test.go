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
	"errors"
	"testing"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// instanceCatalog is the catalog the creator reads the instance rule from.
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

// linearEntry is the shape the rule refuses a second copy of: one URL, per-user
// OAuth the gateway registers itself, nothing an operator supplies.
func linearEntry() catalogdomain.MCPServer {
	return catalogdomain.MCPServer{
		Code:         "app.linear/mcp",
		DisplayName:  "Linear",
		URL:          "https://mcp.linear.app/mcp",
		AuthHint:     "oauth",
		RequiresAuth: true,
		OAuth:        &catalogdomain.MCPOAuth{Required: true, Registration: "auto"},
	}
}

// snowflakeEntry is the shape instances exist for: a templated URL, so two
// registries reach two different schemas.
func snowflakeEntry() catalogdomain.MCPServer {
	return catalogdomain.MCPServer{
		Code:         "com.snowflake/mcp",
		DisplayName:  "Snowflake",
		URL:          "https://{account_url}/api/v2/databases/{database}/schemas/{schema}/mcp-servers/{server}",
		AuthHint:     "oauth",
		RequiresAuth: true,
		URLVariables: []catalogdomain.MCPURLVariable{{Name: "account_url", Required: true}},
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

func shelved(gatewayID ids.GatewayID, name, code, url string) *domain.Registry {
	registry, err := domain.NewMCPRegistry(gatewayID, name, "", &domain.MCPTarget{
		URL: url, Code: code, Transport: domain.MCPTransportStreamableHTTP,
		// A shelf entry skips canonicalisation, so it carries the registration
		// the catalog would have stamped on it.
		Auth: &domain.MCPAuth{
			Mode:         domain.MCPAuthModeForwarded,
			Provider:     code,
			Registration: domain.RegistrationAuto,
		},
	})
	if err != nil {
		panic(err)
	}
	return registry
}

func TestCreator_RefusesASecondInstanceOfAFixedOAuthServer(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().
		List(mock.Anything, mock.Anything).
		Return([]*domain.Registry{
			shelved(gatewayID, "Linear", "app.linear/mcp", "https://mcp.linear.app/mcp"),
		}, 1, nil).
		Once()
	cat := instanceCatalog{entries: map[string]catalogdomain.MCPServer{"app.linear/mcp": linearEntry()}}
	creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger(), nil, cat)

	_, err := creator.Create(context.Background(),
		catalogInput(gatewayID, "Linear (second)", "app.linear/mcp", "https://mcp.linear.app/mcp"))

	require.ErrorIs(t, err, appregistry.ErrSingleInstanceServer)
	// A conflict, not a validation error: the request is well formed, the shelf
	// already holds the only instance this server can have.
	require.ErrorIs(t, err, commonerrors.ErrConflict)
	// The operator needs to know which one is in the way.
	require.Contains(t, err.Error(), "Linear")
}

// The first one is what every self-service install depends on.
func TestCreator_AllowsTheFirstInstanceOfAFixedOAuthServer(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().List(mock.Anything, mock.Anything).Return(nil, 0, nil).Once()
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()
	cat := instanceCatalog{entries: map[string]catalogdomain.MCPServer{"app.linear/mcp": linearEntry()}}
	creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger(), nil, cat)

	registry, err := creator.Create(context.Background(),
		catalogInput(gatewayID, "Linear", "app.linear/mcp", "https://mcp.linear.app/mcp"))

	require.NoError(t, err)
	require.Equal(t, "Linear", registry.Name)
}

func TestCreator_AllowsASecondInstanceOfAConfigurableServer(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()
	cat := instanceCatalog{entries: map[string]catalogdomain.MCPServer{"com.snowflake/mcp": snowflakeEntry()}}
	creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger(), nil, cat)

	// The shelf is never even read: the entry says two of these can differ, so
	// there is nothing to compare against.
	_, err := creator.Create(context.Background(), catalogInput(
		gatewayID, "Snowflake — FINANCE", "com.snowflake/mcp",
		"https://acme.snowflakecomputing.com/api/v2/databases/D/schemas/FINANCE/mcp-servers/S"))

	require.NoError(t, err)
}

// A server an operator wired by hand has no catalog entry to read a rule from.
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

// A read failure must not be mistaken for "nothing on the shelf", which would
// let the duplicate through.
func TestCreator_DoesNotCreateWhenTheShelfCannotBeRead(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().List(mock.Anything, mock.Anything).Return(nil, 0, errors.New("db down")).Once()
	cat := instanceCatalog{entries: map[string]catalogdomain.MCPServer{"app.linear/mcp": linearEntry()}}
	creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger(), nil, cat)

	_, err := creator.Create(context.Background(),
		catalogInput(gatewayID, "Linear", "app.linear/mcp", "https://mcp.linear.app/mcp"))

	require.Error(t, err)
	require.Contains(t, err.Error(), "db down")
}

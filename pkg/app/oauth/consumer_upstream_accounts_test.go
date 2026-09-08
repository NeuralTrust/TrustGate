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

package oauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
	"github.com/stretchr/testify/require"
)

type upstreamFixture struct {
	accounts   oauth.ConsumerUpstreamAccounts
	connect    oauth.ConnectService
	vault      *memVaultRepo
	gatewayID  ids.GatewayID
	consumerID ids.ConsumerID
	authID     ids.AuthID
}

func mcpRegistry(t *testing.T, gw ids.GatewayID, name string, auth *registrydomain.MCPAuth) *registrydomain.Registry {
	t.Helper()
	reg, err := registrydomain.NewMCPRegistry(gw, name, "", &registrydomain.MCPTarget{
		URL:  "https://" + name + ".example.com/mcp",
		Auth: auth,
	})
	require.NoError(t, err)
	return reg
}

func forwardedAuthCfg(provider string) *registrydomain.MCPAuth {
	return &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeForwarded, Provider: provider,
		ClientID: "cid", AuthorizeURL: "https://idp.example.com/a", TokenURL: "https://idp.example.com/t",
	}
}

func newUpstreamFixture(
	t *testing.T,
	gw ids.GatewayID,
	identity consumerdomain.Identity,
	auths []*authdomain.Auth,
	registries []*registrydomain.Registry,
) upstreamFixture {
	t.Helper()
	consumerID := ids.New[ids.ConsumerKind]()
	authIDs := make([]ids.AuthID, 0, len(auths))
	for _, a := range auths {
		a.GatewayID = gw
		authIDs = append(authIDs, a.ID)
	}
	data := appconsumer.NewData(gw, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{
			ID: consumerID, GatewayID: gw, Type: consumerdomain.TypeMCP,
			Slug: "assistant", Active: true, Identity: identity, AuthIDs: authIDs,
		},
		Auths:      auths,
		Registries: registries,
	}})
	vault := &memVaultRepo{}
	store := newMemConnectStore()
	connect := oauth.NewConnectService(
		store, vault, &stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil), infraoauth.NewUpstreamRegistrar(store, nil),
		discardConnectAuditor(), nil, nil, nil, nil,
	)
	accounts, err := oauth.NewConsumerUpstreamAccounts(&stubDataFinder{data: data}, connect)
	require.NoError(t, err)
	fixture := upstreamFixture{
		accounts: accounts, connect: connect, vault: vault,
		gatewayID: gw, consumerID: consumerID,
	}
	if len(auths) > 0 {
		fixture.authID = auths[0].ID
	}
	return fixture
}

func apiKeyAuth(name string) *authdomain.Auth {
	return &authdomain.Auth{
		ID: ids.New[ids.AuthKind](), Name: name,
		Type: authdomain.TypeAPIKey, Enabled: true,
	}
}

var machineIdentity = consumerdomain.Identity{}

func TestConsumerUpstreamAccounts_ReportsWhatEachServerNeeds(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	f := newUpstreamFixture(t, gw, machineIdentity,
		[]*authdomain.Auth{apiKeyAuth("prod")},
		[]*registrydomain.Registry{
			mcpRegistry(t, gw, "notion", forwardedAuthCfg("com.notion/mcp")),
			mcpRegistry(t, gw, "internal", &registrydomain.MCPAuth{
				Mode: registrydomain.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer shared",
			}),
		})
	ctx := context.Background()

	state, err := f.accounts.State(ctx, f.gatewayID, f.consumerID, ids.AuthID{})
	require.NoError(t, err)
	require.Equal(t, "prod", state.PrincipalSub, "the account hangs off the api key's name today")
	require.Len(t, state.Accounts, 2)
	require.True(t, state.NeedsLinking(), "the forwarded server has no account linked yet")

	byRegistry := map[string]oauth.UpstreamAccount{}
	for _, a := range state.Accounts {
		byRegistry[a.Registry] = a
	}
	notion := byRegistry["notion"]
	require.True(t, notion.NeedsLinkedAccount)
	require.Equal(t, "com.notion/mcp", notion.Provider)
	require.False(t, notion.Linked)
	internal := byRegistry["internal"]
	require.False(t, internal.NeedsLinkedAccount, "a server with its own credential asks the application for nothing")
	require.Equal(t, registrydomain.MCPAuthModeStatic, internal.Mode)
}

func TestConsumerUpstreamAccounts_ReportsALinkedAccount(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	f := newUpstreamFixture(t, gw, machineIdentity,
		[]*authdomain.Auth{apiKeyAuth("prod")},
		[]*registrydomain.Registry{mcpRegistry(t, gw, "notion", forwardedAuthCfg("com.notion/mcp"))})
	ctx := context.Background()
	cred, err := vaultdomain.NewCredential(
		f.gatewayID, "prod", "com.notion/mcp", "victor@corp.com",
		"access", "refresh", []string{"read"}, time.Now().Add(time.Hour),
	)
	require.NoError(t, err)
	require.NoError(t, f.vault.Upsert(ctx, cred))

	state, err := f.accounts.State(ctx, f.gatewayID, f.consumerID, ids.AuthID{})
	require.NoError(t, err)
	require.Len(t, state.Accounts, 1)
	require.True(t, state.Accounts[0].Linked)
	require.Equal(t, "victor@corp.com", state.Accounts[0].AccountRef)
	require.False(t, state.NeedsLinking(), "nothing left for an admin to link")
}

func TestConsumerUpstreamAccounts_LinkMintsATicketForTheApplication(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	f := newUpstreamFixture(t, gw, machineIdentity,
		[]*authdomain.Auth{apiKeyAuth("prod")},
		[]*registrydomain.Registry{mcpRegistry(t, gw, "notion", forwardedAuthCfg("com.notion/mcp"))})
	ctx := context.Background()

	link, err := f.accounts.Link(ctx, f.gatewayID, f.consumerID, ids.AuthID{})
	require.NoError(t, err)
	require.NotEmpty(t, link.Ticket)
	require.Equal(t, "/assistant/mcp", link.ConsumerPath)
	require.Equal(t, []string{"com.notion/mcp"}, link.Providers)

	// The ticket an admin gets is the same one the self-service page mints: it
	// opens the consumer's connect page with the provider listed.
	page, err := f.connect.Page(ctx, link.Ticket)
	require.NoError(t, err)
	require.Len(t, page.Providers, 1)
	require.Equal(t, "com.notion/mcp", page.Providers[0].Provider)
}

func TestConsumerUpstreamAccounts_RefusesConsumersWithoutAccountsOfTheirOwn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("users sign in", func(t *testing.T) {
		t.Parallel()
		f := newUpstreamFixture(t, ids.New[ids.GatewayKind](),
			consumerdomain.Identity{ActsForUsers: true, Source: consumerdomain.IdentitySourcePlatform},
			[]*authdomain.Auth{apiKeyAuth("prod")}, nil)
		_, err := f.accounts.State(ctx, f.gatewayID, f.consumerID, ids.AuthID{})
		require.ErrorIs(t, err, oauth.ErrUpstreamAccountsNotMachine)
	})

	t.Run("the application names its own users", func(t *testing.T) {
		t.Parallel()
		f := newUpstreamFixture(t, ids.New[ids.GatewayKind](),
			consumerdomain.Identity{ActsForUsers: true, Source: consumerdomain.IdentitySourceApp},
			[]*authdomain.Auth{apiKeyAuth("prod")}, nil)
		_, err := f.accounts.Link(ctx, f.gatewayID, f.consumerID, ids.AuthID{})
		require.ErrorIs(t, err, oauth.ErrUpstreamAccountsNotMachine)
	})

	t.Run("no api key at all", func(t *testing.T) {
		t.Parallel()
		f := newUpstreamFixture(t, ids.New[ids.GatewayKind](), machineIdentity, nil, nil)
		_, err := f.accounts.State(ctx, f.gatewayID, f.consumerID, ids.AuthID{})
		require.ErrorIs(t, err, oauth.ErrUpstreamAccountsNotMachine)
	})
}

// Keys that differ in name do not share upstream accounts, because the name is
// the principal. Rather than pick one silently, say which one is meant.
func TestConsumerUpstreamAccounts_KeysWithDifferentNamesAreAmbiguous(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	prod, staging := apiKeyAuth("prod"), apiKeyAuth("staging")
	f := newUpstreamFixture(t, gw, machineIdentity,
		[]*authdomain.Auth{prod, staging},
		[]*registrydomain.Registry{mcpRegistry(t, gw, "notion", forwardedAuthCfg("com.notion/mcp"))})
	ctx := context.Background()

	_, err := f.accounts.State(ctx, f.gatewayID, f.consumerID, ids.AuthID{})
	require.ErrorIs(t, err, oauth.ErrUpstreamAccountsAmbiguousKey)

	// Named explicitly, each key reads its own principal.
	state, err := f.accounts.State(ctx, f.gatewayID, f.consumerID, staging.ID)
	require.NoError(t, err)
	require.Equal(t, "staging", state.PrincipalSub)

	// Two keys sharing a name share the principal, so no id is needed.
	gw2 := ids.New[ids.GatewayKind]()
	rotated := apiKeyAuth("prod")
	f2 := newUpstreamFixture(t, gw2, machineIdentity,
		[]*authdomain.Auth{apiKeyAuth("prod"), rotated},
		[]*registrydomain.Registry{mcpRegistry(t, gw2, "notion", forwardedAuthCfg("com.notion/mcp"))})
	state, err = f2.accounts.State(ctx, f2.gatewayID, f2.consumerID, ids.AuthID{})
	require.NoError(t, err)
	require.Equal(t, "prod", state.PrincipalSub)
}

func TestConsumerUpstreamAccounts_UnknownConsumerAndKey(t *testing.T) {
	t.Parallel()
	f := newUpstreamFixture(t, ids.New[ids.GatewayKind](), machineIdentity, []*authdomain.Auth{apiKeyAuth("prod")}, nil)
	ctx := context.Background()

	_, err := f.accounts.State(ctx, f.gatewayID, ids.New[ids.ConsumerKind](), ids.AuthID{})
	require.True(t, errors.Is(err, commonerrors.ErrNotFound))

	_, err = f.accounts.State(ctx, f.gatewayID, f.consumerID, ids.New[ids.AuthKind]())
	require.True(t, errors.Is(err, commonerrors.ErrNotFound))
}

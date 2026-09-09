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

// catalogMCPRegistry is a registry materialized from the catalog: it carries the
// server's code, which is what focuses a connect page on one card.
func catalogMCPRegistry(t *testing.T, gw ids.GatewayID, name, code string, auth *registrydomain.MCPAuth) *registrydomain.Registry {
	t.Helper()
	reg, err := registrydomain.NewMCPRegistry(gw, name, "", &registrydomain.MCPTarget{
		URL:  "https://" + name + ".example.com/mcp",
		Code: code,
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
	return upstreamFixture{
		accounts: accounts, connect: connect, vault: vault,
		gatewayID: gw, consumerID: consumerID,
	}
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

	state, err := f.accounts.State(ctx, f.gatewayID, f.consumerID)
	require.NoError(t, err)
	require.Equal(t, consumerdomain.AppSubject(f.consumerID), state.PrincipalSub,
		"the account hangs off the application, not off any of its credentials")
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
		f.gatewayID, consumerdomain.AppSubject(f.consumerID), "com.notion/mcp", "victor@corp.com",
		"access", "refresh", []string{"read"}, time.Now().Add(time.Hour),
	)
	require.NoError(t, err)
	require.NoError(t, f.vault.Upsert(ctx, cred))

	state, err := f.accounts.State(ctx, f.gatewayID, f.consumerID)
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

	link, err := f.accounts.Link(ctx, f.gatewayID, f.consumerID, ids.RegistryID{})
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

// Authorizing from one server's row must authorize that server and no other:
// the ticket carries only its provider, and the connect page it opens offers
// only that one, so an admin who meant to link Notion cannot be walked through
// Linear as well.
func TestConsumerUpstreamAccounts_LinkNarrowsToOneServer(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	notion := mcpRegistry(t, gw, "notion", forwardedAuthCfg("com.notion/mcp"))
	linear := mcpRegistry(t, gw, "linear", forwardedAuthCfg("app.linear/mcp"))
	internal := mcpRegistry(t, gw, "internal", &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer shared",
	})
	f := newUpstreamFixture(t, gw, machineIdentity,
		[]*authdomain.Auth{apiKeyAuth("prod")},
		[]*registrydomain.Registry{notion, linear, internal})
	ctx := context.Background()

	link, err := f.accounts.Link(ctx, f.gatewayID, f.consumerID, notion.ID)
	require.NoError(t, err)
	require.Equal(t, []string{"com.notion/mcp"}, link.Providers)

	page, err := f.connect.Page(ctx, link.Ticket)
	require.NoError(t, err)
	require.Len(t, page.Providers, 1, "the page must offer only the server the row asked for")
	require.Equal(t, "com.notion/mcp", page.Providers[0].Provider)

	// Unnarrowed, the same call still covers every server that forwards one.
	all, err := f.accounts.Link(ctx, f.gatewayID, f.consumerID, ids.RegistryID{})
	require.NoError(t, err)
	require.Equal(t, []string{"app.linear/mcp", "com.notion/mcp"}, all.Providers)
}

func TestConsumerUpstreamAccounts_LinkRefusesServersItCannotAuthorize(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	internal := mcpRegistry(t, gw, "internal", &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer shared",
	})
	f := newUpstreamFixture(t, gw, machineIdentity,
		[]*authdomain.Auth{apiKeyAuth("prod")},
		[]*registrydomain.Registry{mcpRegistry(t, gw, "notion", forwardedAuthCfg("com.notion/mcp")), internal})
	ctx := context.Background()

	// A server that carries its own credential has no account to link, and an
	// empty ticket would open a page offering nothing.
	_, err := f.accounts.Link(ctx, f.gatewayID, f.consumerID, internal.ID)
	require.ErrorIs(t, err, oauth.ErrUpstreamAccountNotForwarded)

	// A registry the consumer is not bound to is not this application's to
	// authorize, even when it exists on the gateway.
	_, err = f.accounts.Link(ctx, f.gatewayID, f.consumerID, ids.New[ids.RegistryKind]())
	require.ErrorIs(t, err, commonerrors.ErrNotFound)
}

func TestConsumerUpstreamAccounts_RefusesConsumersWithoutAccountsOfTheirOwn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("users sign in", func(t *testing.T) {
		t.Parallel()
		f := newUpstreamFixture(t, ids.New[ids.GatewayKind](),
			consumerdomain.Identity{ActsForUsers: true, Source: consumerdomain.IdentitySourcePlatform},
			[]*authdomain.Auth{apiKeyAuth("prod")}, nil)
		_, err := f.accounts.State(ctx, f.gatewayID, f.consumerID)
		require.ErrorIs(t, err, oauth.ErrUpstreamAccountsNotMachine)
	})

	t.Run("the application names its own users", func(t *testing.T) {
		t.Parallel()
		f := newUpstreamFixture(t, ids.New[ids.GatewayKind](),
			consumerdomain.Identity{ActsForUsers: true, Source: consumerdomain.IdentitySourceApp},
			[]*authdomain.Auth{apiKeyAuth("prod")}, nil)
		_, err := f.accounts.Link(ctx, f.gatewayID, f.consumerID, ids.RegistryID{})
		require.ErrorIs(t, err, oauth.ErrUpstreamAccountsNotMachine)
	})
}

// An application that holds no api key at all — one that authenticates with a
// client certificate, or one whose only key was just revoked — still has
// upstream accounts, because they hang off the consumer.
func TestConsumerUpstreamAccounts_NeedNoAPIKey(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	f := newUpstreamFixture(t, gw, machineIdentity, nil,
		[]*registrydomain.Registry{mcpRegistry(t, gw, "notion", forwardedAuthCfg("com.notion/mcp"))})
	ctx := context.Background()

	state, err := f.accounts.State(ctx, f.gatewayID, f.consumerID)
	require.NoError(t, err)
	require.Equal(t, consumerdomain.AppSubject(f.consumerID), state.PrincipalSub)
	require.True(t, state.NeedsLinking())

	link, err := f.accounts.Link(ctx, f.gatewayID, f.consumerID, ids.RegistryID{})
	require.NoError(t, err)
	require.NotEmpty(t, link.Ticket)
}

// Credentials are not identities: whatever an application's keys are called,
// and however many it holds, they all reach the one account set that belongs to
// the consumer. Renaming or rotating a key cannot strand a linked account.
func TestConsumerUpstreamAccounts_EveryCredentialReachesTheSameAccounts(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	f := newUpstreamFixture(t, gw, machineIdentity,
		[]*authdomain.Auth{apiKeyAuth("prod"), apiKeyAuth("staging")},
		[]*registrydomain.Registry{mcpRegistry(t, gw, "notion", forwardedAuthCfg("com.notion/mcp"))})
	ctx := context.Background()
	cred, err := vaultdomain.NewCredential(
		f.gatewayID, consumerdomain.AppSubject(f.consumerID), "com.notion/mcp", "ops@corp.com",
		"access", "refresh", []string{"read"}, time.Now().Add(time.Hour),
	)
	require.NoError(t, err)
	require.NoError(t, f.vault.Upsert(ctx, cred))

	state, err := f.accounts.State(ctx, f.gatewayID, f.consumerID)
	require.NoError(t, err)
	require.Equal(t, consumerdomain.AppSubject(f.consumerID), state.PrincipalSub)
	require.True(t, state.Accounts[0].Linked, "the linked account is the application's, not one key's")
	require.Equal(t, "ops@corp.com", state.Accounts[0].AccountRef)
	require.False(t, state.NeedsLinking())
}

func TestConsumerUpstreamAccounts_UnknownConsumer(t *testing.T) {
	t.Parallel()
	f := newUpstreamFixture(t, ids.New[ids.GatewayKind](), machineIdentity, []*authdomain.Auth{apiKeyAuth("prod")}, nil)
	ctx := context.Background()

	_, err := f.accounts.State(ctx, f.gatewayID, ids.New[ids.ConsumerKind]())
	require.True(t, errors.Is(err, commonerrors.ErrNotFound))

	_, err = f.accounts.Link(ctx, f.gatewayID, ids.New[ids.ConsumerKind](), ids.RegistryID{})
	require.True(t, errors.Is(err, commonerrors.ErrNotFound))
}

// The page an admin lands on must be the one a user lands on from their client:
// one server's own consent card, not the picker. The picker with a single card
// and a search box reads as the wrong screen — and it is, for a row that named
// its server.
func TestConsumerUpstreamAccounts_LinkOpensOnTheServersOwnCard(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	airtable := catalogMCPRegistry(t, gw, "airtable", "com.airtable/mcp", forwardedAuthCfg("com.airtable/mcp"))
	notion := catalogMCPRegistry(t, gw, "notion", "com.notion/mcp", forwardedAuthCfg("com.notion/mcp"))
	f := newUpstreamFixture(t, gw, machineIdentity,
		[]*authdomain.Auth{apiKeyAuth("prod")},
		[]*registrydomain.Registry{airtable, notion})
	ctx := context.Background()

	link, err := f.accounts.Link(ctx, f.gatewayID, f.consumerID, airtable.ID)
	require.NoError(t, err)
	page, err := f.connect.Page(ctx, link.Ticket)
	require.NoError(t, err)
	require.Equal(t, "com.airtable/mcp", page.Code, "the page must be focused on the server the row named")
	require.Len(t, page.Providers, 1)
	require.Equal(t, "com.airtable/mcp", page.Providers[0].Code, "the focused code must match a provider, or the card renders empty")

	// Every server at once is the one case the picker is for.
	all, err := f.accounts.Link(ctx, f.gatewayID, f.consumerID, ids.RegistryID{})
	require.NoError(t, err)
	allPage, err := f.connect.Page(ctx, all.Ticket)
	require.NoError(t, err)
	require.Empty(t, allPage.Code)
	require.Len(t, allPage.Providers, 2)
}

// A server an admin added by hand carries no catalog code, so there is nothing
// to focus the page on: it falls back to the picker rather than rendering a
// card that matches no provider.
func TestConsumerUpstreamAccounts_LinkFallsBackWithoutACatalogCode(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	custom := mcpRegistry(t, gw, "internal-tools", forwardedAuthCfg("internal-tools"))
	f := newUpstreamFixture(t, gw, machineIdentity,
		[]*authdomain.Auth{apiKeyAuth("prod")},
		[]*registrydomain.Registry{custom})
	ctx := context.Background()

	link, err := f.accounts.Link(ctx, f.gatewayID, f.consumerID, custom.ID)
	require.NoError(t, err)
	page, err := f.connect.Page(ctx, link.Ticket)
	require.NoError(t, err)
	require.Empty(t, page.Code)
	require.Len(t, page.Providers, 1)
}

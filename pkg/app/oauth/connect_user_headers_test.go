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

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
	"github.com/stretchr/testify/require"
)

type userHeaderFixture struct {
	service   oauth.ConnectService
	enroll    oauth.UserHeaderEnrollment
	store     *memConnectStore
	vault     *memVaultRepo
	gatewayID ids.GatewayID
	keyed     *registrydomain.Registry
	other     *registrydomain.Registry
}

func newUserHeaderFixture(t *testing.T) userHeaderFixture {
	t.Helper()
	gatewayID := ids.New[ids.GatewayKind]()
	keyed, err := registrydomain.NewMCPRegistry(gatewayID, "Keyed API", "", &registrydomain.MCPTarget{
		URL:  "https://keyed.example/mcp",
		Auth: &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeNone},
		UserHeaders: []registrydomain.MCPUserHeader{
			{Name: "X-API-Key", Required: true, Secret: true, Description: "Your personal key"},
			{Name: "X-Account", Description: "Account id"},
		},
	})
	require.NoError(t, err)
	other, err := registrydomain.NewMCPRegistry(gatewayID, "Plain", "", &registrydomain.MCPTarget{
		URL:  "https://plain.example/mcp",
		Auth: &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeNone},
	})
	require.NoError(t, err)
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gatewayID,
			Type: consumerdomain.TypeMCP, Slug: "dev", Active: true,
		},
		Registries: []*registrydomain.Registry{keyed, other},
	}})
	store := newMemConnectStore()
	vault := &memVaultRepo{}
	service := oauth.NewConnectService(store, vault, &stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil), infraoauth.NewUpstreamRegistrar(store, nil),
		oauth.NewConnectAuditor(nil), nil, nil, nil, nil)
	enroll, ok := service.(oauth.UserHeaderEnrollment)
	require.True(t, ok, "the connect service serves per-user header enrollment")
	return userHeaderFixture{service: service, enroll: enroll, store: store, vault: vault,
		gatewayID: gatewayID, keyed: keyed, other: other}
}

func (f userHeaderFixture) ticketFor(t *testing.T, sub string) string {
	t.Helper()
	ticket, err := f.service.CreateTicket(context.Background(), f.gatewayID, sub, "/dev/mcp")
	require.NoError(t, err)
	return ticket
}

func TestUserHeaders_PageListsOnlyServersWithHeaders(t *testing.T) {
	f := newUserHeaderFixture(t)
	page, err := f.service.Page(context.Background(), f.ticketFor(t, "ana"))
	require.NoError(t, err)
	require.Len(t, page.UserHeaders, 1)
	server := page.UserHeaders[0]
	require.Equal(t, f.keyed.ID.String(), server.Instance)
	require.True(t, server.Missing())
	require.Len(t, server.Fields, 2)
	require.False(t, server.Fields[0].Set)
}

func TestUserHeaders_SaveStoresPerPrincipalAndNeverShowsSecrets(t *testing.T) {
	f := newUserHeaderFixture(t)
	ctx := context.Background()
	ana := f.ticketFor(t, "ana")
	require.NoError(t, f.enroll.SaveUserHeaders(ctx, ana, f.keyed.ID.String(),
		map[string]string{"x-api-key": "ana-secret", "X-Account": "acct-1"}))

	cred, err := f.vault.Find(ctx, f.gatewayID, "ana", registrydomain.UserHeaderVaultProvider(f.keyed.ID, "X-API-Key"))
	require.NoError(t, err)
	require.Equal(t, "ana-secret", cred.AccessToken)
	_, err = f.vault.Find(ctx, f.gatewayID, "bruno", registrydomain.UserHeaderVaultProvider(f.keyed.ID, "X-API-Key"))
	require.ErrorIs(t, err, vaultdomain.ErrNotFound)

	page, err := f.service.Page(ctx, ana)
	require.NoError(t, err)
	fields := page.UserHeaders[0].Fields
	require.True(t, fields[0].Set)
	require.Empty(t, fields[0].Value, "a secret is never written back into the page")
	require.Equal(t, "acct-1", fields[1].Value)
	require.False(t, page.UserHeaders[0].Missing())

	// An empty secret keeps the stored value: the page never sends it back.
	require.NoError(t, f.enroll.SaveUserHeaders(ctx, ana, f.keyed.ID.String(),
		map[string]string{"X-API-Key": "", "X-Account": "acct-2"}))
	cred, err = f.vault.Find(ctx, f.gatewayID, "ana", registrydomain.UserHeaderVaultProvider(f.keyed.ID, "X-API-Key"))
	require.NoError(t, err)
	require.Equal(t, "ana-secret", cred.AccessToken)
}

func TestUserHeaders_SaveRefusesBadInputBeforeWriting(t *testing.T) {
	f := newUserHeaderFixture(t)
	ctx := context.Background()
	ana := f.ticketFor(t, "ana")
	cases := map[string]map[string]string{
		"required missing": {"X-Account": "acct"},
		"crlf":             {"X-API-Key": "k\r\nX-Evil: 1", "X-Account": "acct"},
		"unknown header":   {"X-API-Key": "k", "X-Other": "v"},
	}
	for name, values := range cases {
		t.Run(name, func(t *testing.T) {
			err := f.enroll.SaveUserHeaders(ctx, ana, f.keyed.ID.String(), values)
			require.ErrorIs(t, err, oauth.ErrUserHeaderInvalid)
			require.NotContains(t, err.Error(), "X-Evil")
			_, err = f.vault.Find(ctx, f.gatewayID, "ana", registrydomain.UserHeaderVaultProvider(f.keyed.ID, "X-Account"))
			require.ErrorIs(t, err, vaultdomain.ErrNotFound, "nothing is written when one field is refused")
		})
	}
}

func TestUserHeaders_ScopeOfTheTicket(t *testing.T) {
	f := newUserHeaderFixture(t)
	ctx := context.Background()
	ana := f.ticketFor(t, "ana")

	err := f.enroll.SaveUserHeaders(ctx, ana, f.other.ID.String(), map[string]string{"X-API-Key": "k"})
	require.ErrorIs(t, err, oauth.ErrUserHeaderServerNotFound)
	err = f.enroll.SaveUserHeaders(ctx, "no-such-ticket", f.keyed.ID.String(), map[string]string{"X-API-Key": "k"})
	require.True(t, errors.Is(err, oauth.ErrTicketNotFound))

	pinned, err := f.service.CreateServerTicket(ctx, f.gatewayID, "ana", "/dev/mcp", "", f.other.ID.String())
	require.NoError(t, err)
	err = f.enroll.SaveUserHeaders(ctx, pinned, f.keyed.ID.String(), map[string]string{"X-API-Key": "k"})
	require.ErrorIs(t, err, oauth.ErrUserHeaderServerNotFound, "a ticket pinned to another instance cannot write here")
}

func TestUserHeaders_RemoveDeletesOnlyThisPersonsValues(t *testing.T) {
	f := newUserHeaderFixture(t)
	ctx := context.Background()
	ana, bruno := f.ticketFor(t, "ana"), f.ticketFor(t, "bruno")
	require.NoError(t, f.enroll.SaveUserHeaders(ctx, ana, f.keyed.ID.String(), map[string]string{"X-API-Key": "a"}))
	require.NoError(t, f.enroll.SaveUserHeaders(ctx, bruno, f.keyed.ID.String(), map[string]string{"X-API-Key": "b"}))

	require.NoError(t, f.enroll.RemoveUserHeaders(ctx, ana, f.keyed.ID.String()))

	_, err := f.vault.Find(ctx, f.gatewayID, "ana", registrydomain.UserHeaderVaultProvider(f.keyed.ID, "X-API-Key"))
	require.ErrorIs(t, err, vaultdomain.ErrNotFound)
	cred, err := f.vault.Find(ctx, f.gatewayID, "bruno", registrydomain.UserHeaderVaultProvider(f.keyed.ID, "X-API-Key"))
	require.NoError(t, err)
	require.Equal(t, "b", cred.AccessToken)
}

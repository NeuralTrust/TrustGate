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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	oauthmocks "github.com/NeuralTrust/TrustGate/pkg/app/oauth/mocks"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
	"github.com/stretchr/testify/require"
)

const connectAuditProviderID = "provider-canonical"

type connectAuditFixtureData struct {
	service    oauth.ConnectService
	store      *memConnectStore
	vault      *memVaultRepo
	data       *appconsumer.Data
	gatewayID  ids.GatewayID
	consumerID ids.ConsumerID
	authID     ids.AuthID
}

func newConnectAuditFixture(
	t *testing.T,
	auditor oauth.ConnectAuditor,
	tokenURL string,
) connectAuditFixtureData {
	t.Helper()

	gatewayID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	authID := ids.New[ids.AuthKind]()
	reg, err := registrydomain.NewMCPRegistry(gatewayID, "registry-name", "", &registrydomain.MCPTarget{
		URL: "https://upstream.example/mcp",
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     connectAuditProviderID,
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			AuthorizeURL: "https://provider.example/authorize",
			TokenURL:     tokenURL,
		},
	})
	require.NoError(t, err)
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{
			ID:        consumerID,
			GatewayID: gatewayID,
			Type:      consumerdomain.TypeMCP,
			Slug:      "runtime",
			Active:    true,
		},
		Registries: []*registrydomain.Registry{reg},
	}})
	store := newMemConnectStore()
	vault := &memVaultRepo{}
	service := oauth.NewConnectService(
		store,
		vault,
		&stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil),
		infraoauth.NewUpstreamRegistrar(store, nil),
		auditor,
	)
	return connectAuditFixtureData{
		service:    service,
		store:      store,
		vault:      vault,
		data:       data,
		gatewayID:  gatewayID,
		consumerID: consumerID,
		authID:     authID,
	}
}

func newConnectAuditTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-token-sentinel",
			"refresh_token": "refresh-token-sentinel",
			"expires_in":    3600,
			"scope":         "scope-sentinel",
		}))
	}))
	t.Cleanup(server.Close)
	return server
}

func completeConnectTicket(fixture connectAuditFixtureData) oauth.ConnectTicket {
	return oauth.ConnectTicket{
		GatewayID:    fixture.gatewayID.String(),
		PrincipalSub: "subject-sentinel",
		ConsumerPath: "/runtime/mcp",
		ConsumerID:   fixture.consumerID.String(),
		AuthID:       fixture.authID.String(),
	}
}

func TestConnectServiceAPIKeyLifecycleAudit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tokenServer := newConnectAuditTokenServer(t)
	auditor := oauthmocks.NewConnectAuditor(t)
	fixture := newConnectAuditFixture(t, auditor, tokenServer.URL)
	identity := oauth.ConnectAuditIdentity{
		GatewayID:  fixture.gatewayID.String(),
		ConsumerID: fixture.consumerID.String(),
		AuthID:     fixture.authID.String(),
	}
	ticketAudit := auditor.EXPECT().TicketCreated(ctx, identity).Once()
	linkAudit := auditor.EXPECT().
		ProviderLinked(ctx, identity, connectAuditProviderID).
		Once()
	linkAudit.NotBefore(ticketAudit)
	unlinkAudit := auditor.EXPECT().
		ProviderUnlinked(ctx, identity, connectAuditProviderID).
		Once()
	unlinkAudit.NotBefore(linkAudit)

	ticketID, err := fixture.service.CreateAPIKeyTicket(
		ctx,
		fixture.gatewayID,
		"subject-sentinel",
		"/runtime/mcp",
		fixture.consumerID,
		fixture.authID,
	)
	require.NoError(t, err)
	require.Equal(t, completeConnectTicket(fixture), fixture.store.tickets[ticketID])

	location, err := fixture.service.Start(
		ctx,
		"https://gateway.example",
		ticketID,
		connectAuditProviderID,
	)
	require.NoError(t, err)
	parsed, err := url.Parse(location)
	require.NoError(t, err)
	_, err = fixture.service.Callback(
		ctx,
		"https://gateway.example",
		connectAuditProviderID,
		parsed.Query().Get("state"),
		"code-sentinel",
		"",
		"",
	)
	require.NoError(t, err)
	require.NoError(t, fixture.service.Disconnect(ctx, ticketID, connectAuditProviderID))
}

func TestConnectServiceDisconnectSurvivesProviderConfigRemoval(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	auditor := oauthmocks.NewConnectAuditor(t)
	fixture := newConnectAuditFixture(t, auditor, "https://unused.example/token")
	identity := oauth.ConnectAuditIdentity{
		GatewayID:  fixture.gatewayID.String(),
		ConsumerID: fixture.consumerID.String(),
		AuthID:     fixture.authID.String(),
	}
	auditor.EXPECT().TicketCreated(ctx, identity).Once()
	auditor.EXPECT().
		ProviderUnlinked(ctx, identity, connectAuditProviderID).
		Once()

	ticketID, err := fixture.service.CreateAPIKeyTicket(
		ctx,
		fixture.gatewayID,
		"subject-sentinel",
		"/runtime/mcp",
		fixture.consumerID,
		fixture.authID,
	)
	require.NoError(t, err)
	credential, err := vaultdomain.NewCredential(
		fixture.gatewayID,
		"subject-sentinel",
		connectAuditProviderID,
		"",
		"access-token-sentinel",
		"",
		nil,
		time.Now().Add(time.Hour),
	)
	require.NoError(t, err)
	fixture.vault.creds = map[string]*vaultdomain.Credential{
		fixture.vault.k(fixture.gatewayID, "subject-sentinel", connectAuditProviderID): credential,
	}
	target, ok := fixture.data.MatchSlug("runtime")
	require.True(t, ok)
	target.Registries = nil

	require.NoError(t, fixture.service.Disconnect(ctx, ticketID, connectAuditProviderID))
	require.Empty(t, fixture.vault.creds)
}

func TestConnectServiceLifecycleAuditDoesNotLeakSecrets(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tokenServer := newConnectAuditTokenServer(t)
	var output bytes.Buffer
	auditor := oauth.NewConnectAuditor(slog.New(slog.NewJSONHandler(&output, nil)))
	fixture := newConnectAuditFixture(t, auditor, tokenServer.URL)

	ticketID, err := fixture.service.CreateAPIKeyTicket(
		ctx,
		fixture.gatewayID,
		"subject-sentinel",
		"/runtime/mcp",
		fixture.consumerID,
		fixture.authID,
	)
	require.NoError(t, err)
	location, err := fixture.service.Start(
		ctx,
		"https://gateway.example",
		ticketID,
		connectAuditProviderID,
	)
	require.NoError(t, err)
	parsed, err := url.Parse(location)
	require.NoError(t, err)
	_, err = fixture.service.Callback(
		ctx,
		"https://gateway.example",
		connectAuditProviderID,
		parsed.Query().Get("state"),
		"code-sentinel",
		"",
		"",
	)
	require.NoError(t, err)
	require.NoError(t, fixture.service.Disconnect(ctx, ticketID, connectAuditProviderID))

	records := strings.Split(strings.TrimSpace(output.String()), "\n")
	require.Len(t, records, 3)
	require.NotContains(t, output.String(), "subject-sentinel")
	require.NotContains(t, output.String(), "access-token-sentinel")
	require.NotContains(t, output.String(), "refresh-token-sentinel")
	require.NotContains(t, output.String(), "scope-sentinel")
	require.NotContains(t, output.String(), "code-sentinel")
	require.NotContains(t, output.String(), ticketID)
	require.NotContains(t, output.String(), "client-secret")
}

func TestConnectServiceSkipsAuditForNonAPIKeyTicket(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tokenServer := newConnectAuditTokenServer(t)
	auditor := oauthmocks.NewConnectAuditor(t)
	fixture := newConnectAuditFixture(t, auditor, tokenServer.URL)

	ticketID, err := fixture.service.CreateTicket(
		ctx,
		fixture.gatewayID,
		"subject-sentinel",
		"/runtime/mcp",
	)
	require.NoError(t, err)
	location, err := fixture.service.Start(
		ctx,
		"https://gateway.example",
		ticketID,
		connectAuditProviderID,
	)
	require.NoError(t, err)
	parsed, err := url.Parse(location)
	require.NoError(t, err)
	_, err = fixture.service.Callback(
		ctx,
		"https://gateway.example",
		connectAuditProviderID,
		parsed.Query().Get("state"),
		"code-sentinel",
		"",
		"",
	)
	require.NoError(t, err)
	require.NoError(t, fixture.service.Disconnect(ctx, ticketID, connectAuditProviderID))

	ticket := fixture.store.tickets[ticketID]
	require.Empty(t, ticket.ConsumerID)
	require.Empty(t, ticket.AuthID)
}

func TestConnectServiceSkipsAuditForIncompleteTickets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		consumerID string
		authID     string
	}{
		{name: "missing consumer", authID: "auth-sentinel"},
		{name: "missing auth", consumerID: "consumer-sentinel"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			auditor := oauthmocks.NewConnectAuditor(t)
			fixture := newConnectAuditFixture(t, auditor, "https://unused.example/token")
			ticket := completeConnectTicket(fixture)
			ticket.ConsumerID = tt.consumerID
			ticket.AuthID = tt.authID
			fixture.store.tickets["ticket-sentinel"] = ticket
			credential, err := vaultdomain.NewCredential(
				fixture.gatewayID,
				ticket.PrincipalSub,
				connectAuditProviderID,
				"",
				"access-token-sentinel",
				"",
				nil,
				time.Now().Add(time.Hour),
			)
			require.NoError(t, err)
			fixture.vault.creds = map[string]*vaultdomain.Credential{
				fixture.vault.k(fixture.gatewayID, ticket.PrincipalSub, connectAuditProviderID): credential,
			}

			require.NoError(
				t,
				fixture.service.Disconnect(ctx, "ticket-sentinel", connectAuditProviderID),
			)
		})
	}
}

func TestConnectServiceSkipsAuditWhenPersistenceFails(t *testing.T) {
	t.Parallel()

	dependencyErr := errors.New("persistence failed with secret-detail")
	tests := []struct {
		name string
		run  func(*testing.T, connectAuditFixtureData) error
	}{
		{
			name: "ticket save",
			run: func(t *testing.T, fixture connectAuditFixtureData) error {
				fixture.store.saveTicketErr = dependencyErr
				_, err := fixture.service.CreateAPIKeyTicket(
					context.Background(),
					fixture.gatewayID,
					"subject-sentinel",
					"/runtime/mcp",
					fixture.consumerID,
					fixture.authID,
				)
				return err
			},
		},
		{
			name: "provider upsert",
			run: func(t *testing.T, fixture connectAuditFixtureData) error {
				fixture.store.tickets["ticket-sentinel"] = completeConnectTicket(fixture)
				fixture.vault.upsertErr = dependencyErr
				location, err := fixture.service.Start(
					context.Background(),
					"https://gateway.example",
					"ticket-sentinel",
					connectAuditProviderID,
				)
				require.NoError(t, err)
				parsed, err := url.Parse(location)
				require.NoError(t, err)
				_, err = fixture.service.Callback(
					context.Background(),
					"https://gateway.example",
					connectAuditProviderID,
					parsed.Query().Get("state"),
					"code-sentinel",
					"",
					"",
				)
				return err
			},
		},
		{
			name: "provider delete",
			run: func(t *testing.T, fixture connectAuditFixtureData) error {
				ticket := completeConnectTicket(fixture)
				fixture.store.tickets["ticket-sentinel"] = ticket
				credential, err := vaultdomain.NewCredential(
					fixture.gatewayID,
					ticket.PrincipalSub,
					connectAuditProviderID,
					"",
					"access-token-sentinel",
					"",
					nil,
					time.Now().Add(time.Hour),
				)
				require.NoError(t, err)
				fixture.vault.creds = map[string]*vaultdomain.Credential{
					fixture.vault.k(fixture.gatewayID, ticket.PrincipalSub, connectAuditProviderID): credential,
				}
				fixture.vault.deleteErr = dependencyErr
				return fixture.service.Disconnect(
					context.Background(),
					"ticket-sentinel",
					connectAuditProviderID,
				)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tokenServer := newConnectAuditTokenServer(t)
			fixture := newConnectAuditFixture(t, oauthmocks.NewConnectAuditor(t), tokenServer.URL)
			require.ErrorIs(t, tt.run(t, fixture), dependencyErr)
		})
	}
}

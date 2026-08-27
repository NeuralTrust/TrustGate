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
	"sync"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	oauthmocks "github.com/NeuralTrust/TrustGate/pkg/app/oauth/mocks"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
	vaultrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/vault"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
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
			AuthIDs:   []ids.AuthID{authID},
		},
		Registries: []*registrydomain.Registry{reg},
		Auths: []*authdomain.Auth{{
			ID:        authID,
			GatewayID: gatewayID,
			Type:      authdomain.TypeAPIKey,
			Enabled:   true,
		}},
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
		nil,
		nil,
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
	providers := []string{connectAuditProviderID}
	return oauth.ConnectTicket{
		GatewayID:    fixture.gatewayID.String(),
		PrincipalSub: "subject-sentinel",
		ConsumerPath: "/runtime/mcp",
		ConsumerID:   fixture.consumerID.String(),
		AuthID:       fixture.authID.String(),
		Providers:    &providers,
	}
}

func addConnectAuditProvider(
	t *testing.T,
	fixture connectAuditFixtureData,
	name,
	provider string,
) {
	t.Helper()

	registry, err := registrydomain.NewMCPRegistry(
		fixture.gatewayID,
		name,
		"",
		&registrydomain.MCPTarget{
			URL: "https://added.example/mcp",
			Auth: &registrydomain.MCPAuth{
				Mode:         registrydomain.MCPAuthModeForwarded,
				Provider:     provider,
				Registration: registrydomain.RegistrationAuto,
			},
		},
	)
	require.NoError(t, err)
	target, ok := fixture.data.MatchSlug("runtime")
	require.True(t, ok)
	target.Registries = append(target.Registries, registry)
}

func TestConnectTicketProviderSnapshotJSONCompatibility(t *testing.T) {
	t.Parallel()

	var legacy oauth.ConnectTicket
	require.NoError(
		t,
		json.Unmarshal(
			[]byte(`{"gateway_id":"gateway","principal_sub":"subject","consumer_path":"/runtime/mcp"}`),
			&legacy,
		),
	)
	require.Nil(t, legacy.Providers)

	providers := []string{}
	payload, err := json.Marshal(oauth.ConnectTicket{
		GatewayID:    "gateway",
		PrincipalSub: "subject",
		ConsumerPath: "/runtime/mcp",
		Providers:    &providers,
	})
	require.NoError(t, err)
	require.Contains(t, string(payload), `"providers":[]`)

	var current oauth.ConnectTicket
	require.NoError(t, json.Unmarshal(payload, &current))
	require.NotNil(t, current.Providers)
	require.Empty(t, *current.Providers)
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
		[]string{connectAuditProviderID},
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

func TestConnectServiceProviderSnapshotProtectsStartAndCallback(t *testing.T) {
	t.Parallel()

	t.Run("provider added after mint is rejected before state", func(t *testing.T) {
		t.Parallel()

		fixture := newConnectAuditFixture(
			t,
			oauthmocks.NewConnectAuditor(t),
			"https://unused.example/token",
		)
		fixture.store.tickets["ticket-sentinel"] = completeConnectTicket(fixture)
		addConnectAuditProvider(t, fixture, "added-registry", "added-provider")

		location, err := fixture.service.Start(
			context.Background(),
			"https://gateway.example",
			"ticket-sentinel",
			"added-provider",
		)

		require.Empty(t, location)
		require.ErrorIs(t, err, oauth.ErrProviderNotFound)
		require.Empty(t, fixture.store.connects)
	})

	t.Run("tampered state provider is rejected before exchange", func(t *testing.T) {
		t.Parallel()

		fixture := newConnectAuditFixture(
			t,
			oauthmocks.NewConnectAuditor(t),
			"https://unused.example/token",
		)
		addConnectAuditProvider(t, fixture, "added-registry", "added-provider")
		fixture.store.connects["state-sentinel"] = oauth.ConnectState{
			Ticket:   completeConnectTicket(fixture),
			TicketID: "ticket-sentinel",
			Provider: "added-provider",
			Verifier: "verifier-sentinel",
		}

		ticketID, err := fixture.service.Callback(
			context.Background(),
			"https://gateway.example",
			"added-provider",
			"state-sentinel",
			"code-sentinel",
			"",
			"",
		)

		require.Equal(t, "ticket-sentinel", ticketID)
		require.ErrorIs(t, err, oauth.ErrProviderNotFound)
		require.Empty(t, fixture.vault.creds)
	})

	t.Run("tampered ticket metadata fails closed", func(t *testing.T) {
		t.Parallel()

		fixture := newConnectAuditFixture(
			t,
			oauthmocks.NewConnectAuditor(t),
			"https://unused.example/token",
		)
		ticket := completeConnectTicket(fixture)
		ticket.Providers = nil
		fixture.store.connects["state-sentinel"] = oauth.ConnectState{
			Ticket:   ticket,
			TicketID: "ticket-sentinel",
			Provider: connectAuditProviderID,
			Verifier: "verifier-sentinel",
		}

		ticketID, err := fixture.service.Callback(
			context.Background(),
			"https://gateway.example",
			connectAuditProviderID,
			"state-sentinel",
			"code-sentinel",
			"",
			"",
		)

		require.Equal(t, "ticket-sentinel", ticketID)
		require.ErrorIs(t, err, oauth.ErrTicketNotFound)
		require.Empty(t, fixture.vault.creds)
	})

	t.Run("valid snapshot permits start and callback", func(t *testing.T) {
		t.Parallel()

		tokenServer := newConnectAuditTokenServer(t)
		fixture := newConnectAuditFixture(t, discardConnectAuditor(), tokenServer.URL)
		fixture.store.tickets["ticket-sentinel"] = completeConnectTicket(fixture)

		location, err := fixture.service.Start(
			context.Background(),
			"https://gateway.example",
			"ticket-sentinel",
			connectAuditProviderID,
		)
		require.NoError(t, err)
		parsed, err := url.Parse(location)
		require.NoError(t, err)

		ticketID, err := fixture.service.Callback(
			context.Background(),
			"https://gateway.example",
			connectAuditProviderID,
			parsed.Query().Get("state"),
			"code-sentinel",
			"",
			"",
		)

		require.NoError(t, err)
		require.Equal(t, "ticket-sentinel", ticketID)
		require.Len(t, fixture.vault.creds, 1)
	})
}

func TestConnectServicePageUsesProviderSnapshot(t *testing.T) {
	t.Parallel()

	t.Run("provider added after mint is not listed or queried", func(t *testing.T) {
		t.Parallel()

		fixture := newConnectAuditFixture(
			t,
			oauthmocks.NewConnectAuditor(t),
			"https://unused.example/token",
		)
		fixture.store.tickets["ticket-sentinel"] = completeConnectTicket(fixture)
		addConnectAuditProvider(t, fixture, "added-registry", "added-provider")

		page, err := fixture.service.Page(context.Background(), "ticket-sentinel")

		require.NoError(t, err)
		require.Len(t, page.Providers, 1)
		require.Equal(t, connectAuditProviderID, page.Providers[0].Provider)
		require.Equal(t, "registry-name", page.Providers[0].Registry)
		require.Equal(t, []string{connectAuditProviderID}, fixture.vault.findProviders)
	})

	t.Run("valid snapshot provider is listed and queried", func(t *testing.T) {
		t.Parallel()

		fixture := newConnectAuditFixture(
			t,
			oauthmocks.NewConnectAuditor(t),
			"https://unused.example/token",
		)
		fixture.store.tickets["ticket-sentinel"] = completeConnectTicket(fixture)

		page, err := fixture.service.Page(context.Background(), "ticket-sentinel")

		require.NoError(t, err)
		require.Len(t, page.Providers, 1)
		require.Equal(t, connectAuditProviderID, page.Providers[0].Provider)
		require.Equal(t, "registry-name", page.Providers[0].Registry)
		require.Equal(t, []string{connectAuditProviderID}, fixture.vault.findProviders)
	})

	t.Run("legacy ticket lists and queries current providers", func(t *testing.T) {
		t.Parallel()

		fixture := newConnectAuditFixture(
			t,
			oauthmocks.NewConnectAuditor(t),
			"https://unused.example/token",
		)
		ticket := completeConnectTicket(fixture)
		ticket.ConsumerID = ""
		ticket.AuthID = ""
		ticket.Providers = nil
		fixture.store.tickets["ticket-sentinel"] = ticket
		addConnectAuditProvider(t, fixture, "added-registry", "added-provider")

		page, err := fixture.service.Page(context.Background(), "ticket-sentinel")

		require.NoError(t, err)
		require.Len(t, page.Providers, 2)
		require.Equal(
			t,
			[]string{connectAuditProviderID, "added-provider"},
			fixture.vault.findProviders,
		)
		require.ElementsMatch(
			t,
			[]oauth.ProviderStatus{
				{Provider: connectAuditProviderID, Registry: "registry-name"},
				{Provider: "added-provider", Registry: "added-registry"},
			},
			page.Providers,
		)
	})
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
		[]string{connectAuditProviderID},
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

func TestConnectServiceDisconnectRejectsProviderOutsideSnapshot(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	fixture := newConnectAuditFixture(
		t,
		oauthmocks.NewConnectAuditor(t),
		"https://unused.example/token",
	)
	ticket := completeConnectTicket(fixture)
	fixture.store.tickets["ticket-sentinel"] = ticket
	otherRegistry, err := registrydomain.NewMCPRegistry(
		fixture.gatewayID,
		"other-registry",
		"",
		&registrydomain.MCPTarget{
			URL: "https://other.example/mcp",
			Auth: &registrydomain.MCPAuth{
				Mode:         registrydomain.MCPAuthModeForwarded,
				Provider:     "other-provider",
				Registration: registrydomain.RegistrationAuto,
			},
		},
	)
	require.NoError(t, err)
	fixture.data.Consumers = append(fixture.data.Consumers, appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: fixture.gatewayID,
			Type:      consumerdomain.TypeMCP,
			Slug:      "other",
			Active:    true,
		},
		Registries: []*registrydomain.Registry{otherRegistry},
	})
	credential, err := vaultdomain.NewCredential(
		fixture.gatewayID,
		ticket.PrincipalSub,
		"other-provider",
		"",
		"access-token-sentinel",
		"",
		nil,
		time.Now().Add(time.Hour),
	)
	require.NoError(t, err)
	fixture.vault.creds = map[string]*vaultdomain.Credential{
		fixture.vault.k(fixture.gatewayID, ticket.PrincipalSub, "other-provider"): credential,
	}

	err = fixture.service.Disconnect(ctx, "ticket-sentinel", "other-provider")

	require.ErrorIs(t, err, oauth.ErrProviderNotFound)
	require.Len(t, fixture.vault.creds, 1)
}

func TestConnectServiceDisconnectLegacyTicketUsesCurrentProviders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		provider   string
		wantErr    error
		wantStored int
	}{
		{
			name:     "configured provider",
			provider: connectAuditProviderID,
		},
		{
			name:       "unconfigured provider",
			provider:   "other-provider",
			wantErr:    oauth.ErrProviderNotFound,
			wantStored: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fixture := newConnectAuditFixture(
				t,
				oauthmocks.NewConnectAuditor(t),
				"https://unused.example/token",
			)
			ticket := completeConnectTicket(fixture)
			ticket.ConsumerID = ""
			ticket.AuthID = ""
			ticket.Providers = nil
			fixture.store.tickets["ticket-sentinel"] = ticket
			credential, err := vaultdomain.NewCredential(
				fixture.gatewayID,
				ticket.PrincipalSub,
				tt.provider,
				"",
				"access-token-sentinel",
				"",
				nil,
				time.Now().Add(time.Hour),
			)
			require.NoError(t, err)
			fixture.vault.creds = map[string]*vaultdomain.Credential{
				fixture.vault.k(fixture.gatewayID, ticket.PrincipalSub, tt.provider): credential,
			}

			err = fixture.service.Disconnect(
				context.Background(),
				"ticket-sentinel",
				tt.provider,
			)

			if tt.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tt.wantErr)
			}
			require.Len(t, fixture.vault.creds, tt.wantStored)
		})
	}
}

func TestConnectServiceRejectsStaleAPIKeyTicketIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*appconsumer.RoutableConsumer)
	}{
		{
			name: "consumer recreated",
			mutate: func(target *appconsumer.RoutableConsumer) {
				target.Consumer.ID = ids.New[ids.ConsumerKind]()
			},
		},
		{
			name: "auth detached",
			mutate: func(target *appconsumer.RoutableConsumer) {
				target.Consumer.AuthIDs = nil
				target.Auths = nil
			},
		},
		{
			name: "auth disabled",
			mutate: func(target *appconsumer.RoutableConsumer) {
				target.Auths[0].Enabled = false
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fixture := newConnectAuditFixture(
				t,
				oauthmocks.NewConnectAuditor(t),
				"https://unused.example/token",
			)
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
				fixture.vault.k(
					fixture.gatewayID,
					ticket.PrincipalSub,
					connectAuditProviderID,
				): credential,
			}
			target, ok := fixture.data.MatchSlug("runtime")
			require.True(t, ok)
			tt.mutate(target)

			err = fixture.service.Disconnect(
				context.Background(),
				"ticket-sentinel",
				connectAuditProviderID,
			)

			require.ErrorIs(t, err, oauth.ErrTicketNotFound)
			require.Len(t, fixture.vault.creds, 1)
		})
	}
}

func TestConnectServiceConcurrentDisconnectAuditsExactlyOnce(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	auditor := oauthmocks.NewConnectAuditor(t)
	fixture := newConnectAuditFixture(t, auditor, "https://unused.example/token")
	ticket := completeConnectTicket(fixture)
	fixture.store.tickets["ticket-sentinel"] = ticket
	identity := oauth.ConnectAuditIdentity{
		GatewayID:  fixture.gatewayID.String(),
		ConsumerID: fixture.consumerID.String(),
		AuthID:     fixture.authID.String(),
	}
	auditor.EXPECT().
		ProviderUnlinked(ctx, identity, connectAuditProviderID).
		Once()

	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		require.NoError(t, client.Close())
	})
	cipher, err := crypto.NewCipher("test-secret-key-that-is-long-enough-1234567890")
	require.NoError(t, err)
	vault := vaultrepo.NewRedisRepository(client, cipher)
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
	require.NoError(t, vault.Upsert(ctx, credential))
	service := oauth.NewConnectService(
		fixture.store,
		vault,
		&stubDataFinder{data: fixture.data},
		infraoauth.NewProviderClient(nil),
		infraoauth.NewUpstreamRegistrar(fixture.store, nil),
		auditor,
		nil,
		nil,
	)

	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			results <- service.Disconnect(ctx, "ticket-sentinel", connectAuditProviderID)
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	var deleted, notFound int
	for result := range results {
		switch {
		case result == nil:
			deleted++
		case errors.Is(result, vaultdomain.ErrNotFound):
			notFound++
		default:
			t.Fatalf("unexpected disconnect error: %v", result)
		}
	}
	require.Equal(t, 1, deleted)
	require.Equal(t, 1, notFound)
}

func TestConnectServiceCorruptCredentialDoesNotAudit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	auditor := oauthmocks.NewConnectAuditor(t)
	fixture := newConnectAuditFixture(t, auditor, "https://unused.example/token")
	ticket := completeConnectTicket(fixture)
	fixture.store.tickets["ticket-sentinel"] = ticket
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		require.NoError(t, client.Close())
	})
	cipher, err := crypto.NewCipher("test-secret-key-that-is-long-enough-1234567890")
	require.NoError(t, err)
	key := "vault:" + fixture.gatewayID.String() + ":" +
		ticket.PrincipalSub + ":" + connectAuditProviderID
	require.NoError(t, server.Set(key, "{corrupt"))
	service := oauth.NewConnectService(
		fixture.store,
		vaultrepo.NewRedisRepository(client, cipher),
		&stubDataFinder{data: fixture.data},
		infraoauth.NewProviderClient(nil),
		infraoauth.NewUpstreamRegistrar(fixture.store, nil),
		auditor,
		nil,
		nil,
	)

	err = service.Disconnect(ctx, "ticket-sentinel", connectAuditProviderID)

	require.ErrorIs(t, err, vaultdomain.ErrNotFound)
	raw, err := server.Get(key)
	require.NoError(t, err)
	require.Equal(t, "{corrupt", raw)
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
		[]string{connectAuditProviderID},
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

func TestConnectServiceRejectsPartialAPIKeyTicketIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*oauth.ConnectTicket)
	}{
		{
			name: "missing consumer",
			mutate: func(ticket *oauth.ConnectTicket) {
				ticket.ConsumerID = ""
			},
		},
		{
			name: "missing auth",
			mutate: func(ticket *oauth.ConnectTicket) {
				ticket.AuthID = ""
			},
		},
		{
			name: "identity without provider snapshot",
			mutate: func(ticket *oauth.ConnectTicket) {
				ticket.Providers = nil
			},
		},
		{
			name: "provider snapshot without identity",
			mutate: func(ticket *oauth.ConnectTicket) {
				ticket.ConsumerID = ""
				ticket.AuthID = ""
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			auditor := oauthmocks.NewConnectAuditor(t)
			fixture := newConnectAuditFixture(t, auditor, "https://unused.example/token")
			ticket := completeConnectTicket(fixture)
			tt.mutate(&ticket)
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

			err = fixture.service.Disconnect(
				ctx,
				"ticket-sentinel",
				connectAuditProviderID,
			)

			require.ErrorIs(t, err, oauth.ErrTicketNotFound)
			require.Len(t, fixture.vault.creds, 1)
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
					[]string{connectAuditProviderID},
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

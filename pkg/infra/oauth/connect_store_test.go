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
	"testing"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func newConnectStore(t *testing.T) (*infraoauth.ConnectStore, *miniredis.Miniredis) {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		require.NoError(t, client.Close())
	})
	return infraoauth.NewConnectStore(client), server
}

func TestConnectStoreTicketRemainsReusableForFifteenMinutes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, server := newConnectStore(t)
	ticket := appoauth.ConnectTicket{
		GatewayID:    "gateway-sentinel",
		PrincipalSub: "subject-sentinel",
		ConsumerPath: "/runtime/mcp",
		ResumeURL:    "resume-sentinel",
		ConsumerID:   "consumer-sentinel",
		AuthID:       "auth-sentinel",
	}

	require.NoError(t, store.SaveTicket(ctx, "ticket-sentinel", ticket))
	require.Equal(t, 15*time.Minute, server.TTL("oauth:connect:ticket:ticket-sentinel"))

	first, err := store.GetTicket(ctx, "ticket-sentinel")
	require.NoError(t, err)
	second, err := store.GetTicket(ctx, "ticket-sentinel")
	require.NoError(t, err)
	require.Equal(t, &ticket, first)
	require.Equal(t, &ticket, second)
}

func TestConnectStoreStateRemainsAtomicSingleUseForTenMinutes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, server := newConnectStore(t)
	state := appoauth.ConnectState{
		Ticket: appoauth.ConnectTicket{
			GatewayID:    "gateway-sentinel",
			PrincipalSub: "subject-sentinel",
			ConsumerPath: "/runtime/mcp",
			ConsumerID:   "consumer-sentinel",
			AuthID:       "auth-sentinel",
		},
		TicketID: "ticket-sentinel",
		Provider: "provider-sentinel",
		Verifier: "verifier-sentinel",
	}

	require.NoError(t, store.SaveConnect(ctx, "state-sentinel", state))
	require.Equal(t, 10*time.Minute, server.TTL("oauth:connect:state:state-sentinel"))

	first, err := store.TakeConnect(ctx, "state-sentinel")
	require.NoError(t, err)
	second, err := store.TakeConnect(ctx, "state-sentinel")
	require.NoError(t, err)
	require.Equal(t, &state, first)
	require.Nil(t, second)
}

func TestConnectStoreReadsLegacyTicketWithoutAuditIdentity(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, server := newConnectStore(t)
	require.NoError(t, server.Set(
		"oauth:connect:ticket:legacy-ticket",
		`{"gateway_id":"gateway-sentinel","principal_sub":"subject-sentinel","consumer_path":"/runtime/mcp"}`,
	))

	ticket, err := store.GetTicket(ctx, "legacy-ticket")
	require.NoError(t, err)
	require.Equal(t, "gateway-sentinel", ticket.GatewayID)
	require.Equal(t, "subject-sentinel", ticket.PrincipalSub)
	require.Equal(t, "/runtime/mcp", ticket.ConsumerPath)
	require.Empty(t, ticket.ConsumerID)
	require.Empty(t, ticket.AuthID)
}

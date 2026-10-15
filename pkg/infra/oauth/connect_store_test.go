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

func TestConnectStorePeekLeavesTheStateInPlace(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, _ := newConnectStore(t)
	state := appoauth.ConnectState{
		TicketID:    "ticket-sentinel",
		Provider:    "provider-sentinel",
		StartOrigin: "https://start.example",
	}
	require.NoError(t, store.SaveConnect(ctx, "state-sentinel", state))

	peeked, err := store.PeekConnect(ctx, "state-sentinel")
	require.NoError(t, err)
	require.Equal(t, &state, peeked)
	taken, err := store.TakeConnect(ctx, "state-sentinel")
	require.NoError(t, err)
	require.Equal(t, &state, taken)
	gone, err := store.PeekConnect(ctx, "state-sentinel")
	require.NoError(t, err)
	require.Nil(t, gone)
}

func TestConnectStoreFinishIsShortLivedAndSingleUse(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, server := newConnectStore(t)
	finish := appoauth.ConnectFinish{Provider: "provider-sentinel", State: "state-sentinel", Code: "code-sentinel"}

	require.NoError(t, store.SaveFinish(ctx, "finish-sentinel", finish))
	require.Equal(t, 2*time.Minute, server.TTL("oauth:connect:finish:finish-sentinel"))

	first, err := store.TakeFinish(ctx, "finish-sentinel")
	require.NoError(t, err)
	second, err := store.TakeFinish(ctx, "finish-sentinel")
	require.NoError(t, err)
	require.Equal(t, &finish, first)
	require.Nil(t, second)
}

func TestConnectStoreKeepsOnePendingFinishPerFlow(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, server := newConnectStore(t)
	first := appoauth.ConnectFinish{Provider: "provider-sentinel", State: "state-sentinel", Code: "code-1"}
	second := appoauth.ConnectFinish{Provider: "provider-sentinel", State: "state-sentinel", Code: "code-2"}
	other := appoauth.ConnectFinish{Provider: "provider-sentinel", State: "other-state", Code: "code-3"}

	require.NoError(t, store.SaveFinish(ctx, "finish-1", first))
	require.NoError(t, store.SaveFinish(ctx, "finish-2", second))
	require.NoError(t, store.SaveFinish(ctx, "finish-3", other))

	replaced, err := store.TakeFinish(ctx, "finish-1")
	require.NoError(t, err)
	require.Nil(t, replaced, "a second callback for one flow must replace the first")
	latest, err := store.TakeFinish(ctx, "finish-2")
	require.NoError(t, err)
	require.Equal(t, &second, latest)
	untouched, err := store.TakeFinish(ctx, "finish-3")
	require.NoError(t, err)
	require.Equal(t, &other, untouched)

	for _, key := range server.Keys() {
		require.NotContains(t, key, "state-sentinel", "the state must not appear in key names")
	}
}

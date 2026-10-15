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

package oauth

import (
	"context"
	"testing"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// A link and the browser that signed in for it live as long as the link does,
// and go when the page spends them.
func TestPersonalKeyPageStore_KeepsTicketsAndSessionsForTheLinksLife(t *testing.T) {
	server := miniredis.RunT(t)
	store := NewPersonalKeyPageStore(redis.NewClient(&redis.Options{Addr: server.Addr()}))
	ctx := context.Background()

	missing, err := store.GetTicket(ctx, "nope")
	require.NoError(t, err)
	require.Nil(t, missing)

	ticket := appoauth.PersonalKeyTicket{GatewayID: "gw", PrincipalSub: "alice", MCPURL: "https://gw.example/store/mcp"}
	require.NoError(t, store.SaveTicket(ctx, "tk", ticket))
	got, err := store.GetTicket(ctx, "tk")
	require.NoError(t, err)
	require.Equal(t, ticket, *got)
	require.Equal(t, appoauth.PersonalKeyTicketTTL, server.TTL(personalKeyTicketPrefix+"tk"))

	session := appoauth.PersonalKeySession{Ticket: "tk", Subject: "alice", Groups: []string{"eng"}, CSRF: "c"}
	require.NoError(t, store.SaveSession(ctx, "s", session))
	gotSession, err := store.GetSession(ctx, "s")
	require.NoError(t, err)
	require.Equal(t, session, *gotSession)

	require.NoError(t, store.DeleteTicket(ctx, "tk"))
	require.NoError(t, store.DeleteSession(ctx, "s"))
	got, _ = store.GetTicket(ctx, "tk")
	gotSession, _ = store.GetSession(ctx, "s")
	require.Nil(t, got)
	require.Nil(t, gotSession)
}

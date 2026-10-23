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

package console

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	keygroupdomain "github.com/NeuralTrust/TrustGate/pkg/domain/keygroup"
	"github.com/stretchr/testify/require"
)

type gatewaysByID map[ids.GatewayID]*gatewaydomain.Gateway

func (g gatewaysByID) FindByID(_ context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error) {
	if gw, ok := g[id]; ok {
		return gw, nil
	}
	return nil, errors.New("gateway not found")
}

func teamGateway(team string) (ids.GatewayID, gatewaysByID) {
	id := ids.New[ids.GatewayKind]()
	return id, gatewaysByID{id: {ID: id, Metadata: gatewaydomain.WithTenantID(nil, team)}}
}

// The console checks the signature as it does a personal key event's, and
// reads which limit was reached, under the gateway's team.
func TestKeyGroupBudgetEvents_PostsASignedEventUnderTheGatewaysTeam(t *testing.T) {
	var got struct {
		body      []byte
		timestamp string
		signature string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.body, _ = io.ReadAll(r.Body)
		got.timestamp = r.Header.Get(TimestampHeader)
		got.signature = r.Header.Get(SignatureHeader)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	gw, gateways := teamGateway("team-a")
	events, err := NewKeyGroupBudgetEvents(srv.URL+"/api/internal/trustgate/personal-key-events", "shared-secret", gateways, srv.Client())
	require.NoError(t, err)
	events.now = func() time.Time { return time.Unix(1_760_000_000, 0) }

	require.NoError(t, events.Notify(context.Background(), keygroupdomain.Reached{
		GatewayID: gw, GroupID: "g-eng", Scope: keygroupdomain.ScopeMember, UserID: "user-1",
		LimitUSD: 20, SpentUSD: 20.25, Period: "2026-10", Action: keygroupdomain.ActionBlock,
	}))

	require.Equal(t, "v1="+Sign([]byte("shared-secret"), got.timestamp, got.body), got.signature)
	var body map[string]any
	require.NoError(t, json.Unmarshal(got.body, &body))
	require.Equal(t, map[string]any{
		"event": "key_group_budget_reached", "source": "budget", "team_id": "team-a", "gateway_id": gw.String(),
		"group_id": "g-eng", "scope": "member", "user_id": "user-1", "limit_usd": 20.0, "spent_usd": 20.25,
		"period": "2026-10", "action": "block",
	}, body)
}

func TestKeyGroupBudgetEvents_TheGroupsTotalNamesNoUser(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	gw, gateways := teamGateway("team-a")
	events, err := NewKeyGroupBudgetEvents(srv.URL, "s", gateways, srv.Client())
	require.NoError(t, err)

	require.NoError(t, events.Notify(context.Background(), keygroupdomain.Reached{
		GatewayID: gw, GroupID: "g-eng", Scope: keygroupdomain.ScopeGroup, LimitUSD: 100, SpentUSD: 100, Period: "2026-10", Action: keygroupdomain.ActionAlert,
	}))
	require.Equal(t, "group", body["scope"])
	require.NotContains(t, body, "user_id")
}

func TestKeyGroupBudgetEvents_ReportsWhatCouldNotBeSent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	gw, gateways := teamGateway("team-a")
	noTeam := ids.New[ids.GatewayKind]()
	gateways[noTeam] = &gatewaydomain.Gateway{ID: noTeam}
	events, err := NewKeyGroupBudgetEvents(srv.URL, "s", gateways, srv.Client())
	require.NoError(t, err)

	require.ErrorContains(t, events.Notify(context.Background(), keygroupdomain.Reached{GatewayID: gw}), "401")
	require.ErrorContains(t, events.Notify(context.Background(), keygroupdomain.Reached{GatewayID: noTeam}), "no team")
	require.Error(t, events.Notify(context.Background(), keygroupdomain.Reached{GatewayID: ids.New[ids.GatewayKind]()}))
}

func TestNewKeyGroupBudgetEvents_RefusesAnIncompleteSetup(t *testing.T) {
	_, gateways := teamGateway("team-a")
	_, err := NewKeyGroupBudgetEvents("app.neuraltrust.ai/events", "s", gateways, nil)
	require.Error(t, err)
	_, err = NewKeyGroupBudgetEvents("https://app.neuraltrust.ai/events", "", gateways, nil)
	require.Error(t, err)
	_, err = NewKeyGroupBudgetEvents("https://app.neuraltrust.ai/events", "s", nil, nil)
	require.Error(t, err)
}

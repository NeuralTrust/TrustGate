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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/require"
)

// The console checks the signature with the secret it already shares, over the
// timestamp and the exact body, and reads the event in its own words.
func TestPersonalKeyEvents_PostsASignedEventTheConsoleCanCheck(t *testing.T) {
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
	events, err := NewPersonalKeyEvents(srv.URL+"/api/internal/trustgate/personal-key-events", "shared-secret", srv.Client())
	require.NoError(t, err)
	events.now = func() time.Time { return time.Unix(1_760_000_000, 0) }
	gw, auth := ids.New[ids.GatewayKind](), ids.New[ids.AuthKind]()

	require.NoError(t, events.Notify(context.Background(), appauth.PersonalKeyEvent{
		Kind: appauth.PersonalKeyCreated, GatewayID: gw, TenantID: "team-a", OwnerID: "user-1", AuthID: auth,
	}))

	require.Equal(t, "1760000000", got.timestamp)
	require.Equal(t, "v1="+Sign([]byte("shared-secret"), got.timestamp, got.body), got.signature)
	var body map[string]any
	require.NoError(t, json.Unmarshal(got.body, &body))
	require.Equal(t, map[string]any{
		"event": "created", "source": "mcp_store", "team_id": "team-a",
		"gateway_id": gw.String(), "user_id": "user-1", "auth_id": auth.String(),
	}, body)
}

func TestPersonalKeyEvents_ReportsAConsoleThatRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	events, err := NewPersonalKeyEvents(srv.URL, "s", srv.Client())
	require.NoError(t, err)

	err = events.Notify(context.Background(), appauth.PersonalKeyEvent{Kind: appauth.PersonalKeyRevoked, TenantID: "team-a"})
	require.ErrorContains(t, err, "401")
	require.Error(t, events.Notify(context.Background(), appauth.PersonalKeyEvent{Kind: appauth.PersonalKeyRevoked}), "an event for no team has nowhere to go")
}

func TestNewPersonalKeyEvents_RefusesABadEndpointOrNoSecret(t *testing.T) {
	_, err := NewPersonalKeyEvents("app.neuraltrust.ai/events", "s", nil)
	require.Error(t, err)
	_, err = NewPersonalKeyEvents("https://app.neuraltrust.ai/events", "", nil)
	require.Error(t, err)
}

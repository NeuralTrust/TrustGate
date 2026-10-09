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

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/stretchr/testify/require"
)

// consoleStub answers as the console's llm-access-requests route does, after
// checking the signature the way it does.
func consoleStub(t *testing.T, status int, answer string, got *map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		timestamp := r.Header.Get(TimestampHeader)
		require.Equal(t, "v1="+Sign([]byte("shared-secret"), timestamp, body), r.Header.Get(SignatureHeader))
		require.NoError(t, json.Unmarshal(body, got))
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
}

func TestModelAccessRequests_ChecksInTheConsolesWords(t *testing.T) {
	var got map[string]any
	srv := consoleStub(t, http.StatusOK, `{"status":"choose_registry","name":"Mistral","provider":"mistral","registries":[{"registry_id":"reg-a","name":"Mistral"},{"registry_id":"reg-b","name":"Mistral EU"}]}`, &got)
	defer srv.Close()
	client, err := NewModelAccessRequests(srv.URL, "shared-secret", srv.Client())
	require.NoError(t, err)
	client.now = func() time.Time { return time.Unix(1_760_000_000, 0) }

	answer, err := client.Check(context.Background(), appoauth.ModelAccessQuery{TeamID: "team-1", GatewayID: "gw-1", UserID: "alice", Provider: " Mistral "})

	require.NoError(t, err)
	require.Equal(t, map[string]any{"action": "check", "team_id": "team-1", "gateway_id": "gw-1", "user_id": "alice", "provider": "Mistral"}, got)
	require.Equal(t, &appoauth.ModelAccessAnswer{
		Status:     appoauth.ModelAccessChooseRegistry,
		Name:       "Mistral",
		Provider:   "mistral",
		Registries: []appoauth.ModelAccessChoice{{RegistryID: "reg-a", Name: "Mistral"}, {RegistryID: "reg-b", Name: "Mistral EU"}},
	}, answer)
}

func TestModelAccessRequests_FilesWithTheReason(t *testing.T) {
	var got map[string]any
	srv := consoleStub(t, http.StatusOK, `{"status":"requested","name":"Mistral","requested_at":"2026-10-09T09:00:00.000Z"}`, &got)
	defer srv.Close()
	client, err := NewModelAccessRequests(srv.URL, "shared-secret", srv.Client())
	require.NoError(t, err)

	answer, err := client.File(context.Background(), appoauth.ModelAccessFiling{
		ModelAccessQuery: appoauth.ModelAccessQuery{TeamID: "team-1", GatewayID: "gw-1", UserID: "alice", Provider: "mistral", RegistryID: "reg-mistral"},
		Reason:           "French support tickets",
	})

	require.NoError(t, err)
	require.Equal(t, "file", got["action"])
	require.Equal(t, "reg-mistral", got["registry_id"])
	require.Equal(t, "French support tickets", got["reason"])
	require.Equal(t, appoauth.ModelAccessRequested, answer.Status)
}

func TestModelAccessRequests_FailsOnAnythingButAnAnswer(t *testing.T) {
	var got map[string]any
	for _, tc := range []struct {
		status int
		body   string
	}{
		{http.StatusNotFound, `{"error":"unknown_user"}`},
		{http.StatusOK, `not json`},
		{http.StatusOK, `{}`},
	} {
		srv := consoleStub(t, tc.status, tc.body, &got)
		client, err := NewModelAccessRequests(srv.URL, "shared-secret", srv.Client())
		require.NoError(t, err)
		_, err = client.Check(context.Background(), appoauth.ModelAccessQuery{TeamID: "team-1", GatewayID: "gw-1", UserID: "alice", Provider: "x"})
		require.Error(t, err, "%d %s", tc.status, tc.body)
		srv.Close()
	}

	client, err := NewModelAccessRequests("https://console.example/route", "shared-secret", nil)
	require.NoError(t, err)
	_, err = client.Check(context.Background(), appoauth.ModelAccessQuery{GatewayID: "gw-1", UserID: "alice", Provider: "x"})
	require.ErrorContains(t, err, "no team")
}

func TestNewModelAccessRequests_NeedsAnURLAndASecret(t *testing.T) {
	_, err := NewModelAccessRequests("not a url", "s", nil)
	require.Error(t, err)
	_, err = NewModelAccessRequests("https://console.example/route", "", nil)
	require.Error(t, err)
}

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
	"log/slog"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/stretchr/testify/require"
)

func TestConnectAuditorExactFields(t *testing.T) {
	t.Parallel()

	identity := oauth.ConnectAuditIdentity{
		GatewayID:  "gateway-sentinel",
		ConsumerID: "consumer-sentinel",
		AuthID:     "auth-sentinel",
	}
	tests := []struct {
		name     string
		event    string
		provider string
		emit     func(oauth.ConnectAuditor)
	}{
		{
			name:  "ticket created",
			event: "mcp_connect_ticket_created",
			emit: func(auditor oauth.ConnectAuditor) {
				auditor.TicketCreated(context.Background(), identity)
			},
		},
		{
			name:     "provider linked",
			event:    "mcp_provider_linked",
			provider: "provider-sentinel",
			emit: func(auditor oauth.ConnectAuditor) {
				auditor.ProviderLinked(context.Background(), identity, "provider-sentinel")
			},
		},
		{
			name:     "provider unlinked",
			event:    "mcp_provider_unlinked",
			provider: "provider-sentinel",
			emit: func(auditor oauth.ConnectAuditor) {
				auditor.ProviderUnlinked(context.Background(), identity, "provider-sentinel")
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			auditor := oauth.NewConnectAuditor(slog.New(slog.NewJSONHandler(&output, nil)))
			tt.emit(auditor)

			var record map[string]any
			require.NoError(t, json.Unmarshal(output.Bytes(), &record))
			require.Equal(t, "INFO", record["level"])
			require.Equal(t, "security audit", record["msg"])
			delete(record, "time")
			delete(record, "level")
			delete(record, "msg")

			want := map[string]any{
				"event":       tt.event,
				"gateway_id":  identity.GatewayID,
				"consumer_id": identity.ConsumerID,
				"auth_id":     identity.AuthID,
			}
			if tt.provider != "" {
				want["provider_id"] = tt.provider
			}
			require.Equal(t, want, record)
			require.NotContains(t, output.String(), "subject-sentinel")
			require.NotContains(t, output.String(), "key-sentinel")
			require.NotContains(t, output.String(), "token-sentinel")
			require.NotContains(t, output.String(), "scope-sentinel")
			require.NotContains(t, output.String(), "ticket-sentinel")
		})
	}
}

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

package vertex

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

func TestVertexClientImplementsConnectionTester(t *testing.T) {
	_, ok := NewVertexClient().(providers.ConnectionTester)
	assert.True(t, ok, "vertex must expose a connection tester so the UI can validate a registry")
}

func TestTestConnection(t *testing.T) {
	validOptions := map[string]any{"project": "careplus-poc", "location": "europe-west1"}
	serviceAccount := providers.Credentials{GCP: &providers.GCP{ServiceAccountJSON: `{"type":"service_account"}`}}

	tests := []struct {
		name      string
		config    *providers.Config
		token     tokenSource
		wantOK    bool
		wantStage providers.ProbeStage
		wantMsg   string
	}{
		{
			name:      "valid service account",
			config:    &providers.Config{Options: validOptions, Credentials: serviceAccount},
			token:     func(context.Context, *providers.GCP) (string, error) { return "ya29.minted", nil },
			wantOK:    true,
			wantStage: providers.StageAuthentication,
		},
		{
			name:      "google rejects the service account",
			config:    &providers.Config{Options: validOptions, Credentials: serviceAccount},
			token:     func(context.Context, *providers.GCP) (string, error) { return "", fmt.Errorf("invalid_grant") },
			wantOK:    false,
			wantStage: providers.StageAuthentication,
			wantMsg:   "invalid_grant",
		},
		{
			name:      "missing location",
			config:    &providers.Config{Options: map[string]any{"project": "careplus-poc"}, Credentials: serviceAccount},
			wantOK:    false,
			wantStage: providers.StageConnectivity,
			wantMsg:   "location",
		},
		{
			name:      "no credentials configured",
			config:    &providers.Config{Options: validOptions},
			wantOK:    false,
			wantStage: providers.StageAuthentication,
			wantMsg:   "gcp service account credentials or a bearer token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := (&client{tokenSource: tt.token}).TestConnection(context.Background(), tt.config)

			assert.Equal(t, tt.wantOK, result.OK)
			assert.Equal(t, tt.wantStage, result.Stage)
			if tt.wantMsg != "" {
				assert.Contains(t, result.Message, tt.wantMsg)
			}
		})
	}
}

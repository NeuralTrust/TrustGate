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

package modules

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/firewall"
)

func TestFirewallTokenProviderSelection(t *testing.T) {
	const secret = "oauth-secret-that-must-never-leak" // #nosec G101 -- test fixture
	for _, tc := range []struct {
		name     string
		cfg      config.FirewallComplexityConfig
		wantType any
		wantLogs []string
	}{
		{
			name:     "legacy secret",
			cfg:      config.FirewallComplexityConfig{SecretKey: "legacy"},
			wantType: &firewall.TokenProvider{},
		},
		{
			name:     "nothing configured",
			cfg:      config.FirewallComplexityConfig{},
			wantType: &firewall.TokenProvider{},
		},
		{
			name: "oauth client",
			cfg: config.FirewallComplexityConfig{
				JWTSet: true, BaseURL: "https://fw.example", BaseURLSource: "FIREWALL_JWT",
				ClientID: "client-7f3a", ClientSecret: secret,
			},
			wantType: &firewall.OAuthTokenSource{},
			wantLogs: []string{"firewall client loaded from FIREWALL_JWT", "client-7f3a"},
		},
		{
			name: "oauth client wins over secret key",
			cfg: config.FirewallComplexityConfig{
				JWTSet: true, BaseURL: "https://fw.example", SecretKey: "legacy",
				ClientID: "client-7f3a", ClientSecret: secret,
			},
			wantType: &firewall.OAuthTokenSource{},
			wantLogs: []string{"FIREWALL_SECRET_KEY is ignored"},
		},
		{
			name:     "invalid token",
			cfg:      config.FirewallComplexityConfig{JWTSet: true, SecretKey: "legacy", JWTError: errors.New("FIREWALL_JWT has expired")},
			wantType: &firewall.UnusableSource{},
			wantLogs: []string{"FIREWALL_SECRET_KEY is ignored", "FIREWALL_JWT has expired"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			got := firewallTokenProvider(tc.cfg, slog.New(slog.NewTextHandler(&logs, nil)))
			assert.IsType(t, tc.wantType, got)
			for _, want := range tc.wantLogs {
				assert.Contains(t, logs.String(), want)
			}
			assert.NotContains(t, logs.String(), secret)
		})
	}
}

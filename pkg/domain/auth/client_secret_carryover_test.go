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

package auth

import (
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
)

const (
	storedLoginSecret    = "stored-login-secret"
	storedExchangeSecret = "stored-exchange-secret"
)

func TestConfig_ResolveSecretsFrom_CarriesSecretWithItsClient(t *testing.T) {
	t.Parallel()
	loginOnly := OAuth2Config{ClientID: "app-1", ClientSecret: storedLoginSecret}
	exchangeOnly := OAuth2Config{ExchangeClientID: "app-1", ExchangeClientSecret: storedExchangeSecret}
	bothShared := OAuth2Config{
		ClientID: "app-1", ClientSecret: storedLoginSecret,
		ExchangeClientID: "app-1", ExchangeClientSecret: storedExchangeSecret,
	}
	maskedLogin := secret.Mask(storedLoginSecret)

	tests := []struct {
		name               string
		prev               OAuth2Config
		next               OAuth2Config
		wantSecret         string
		wantExchangeSecret string
	}{
		{
			name:       "typed secret wins over the stored one",
			prev:       exchangeOnly,
			next:       OAuth2Config{ClientID: "app-1", ClientSecret: "typed"},
			wantSecret: "typed",
		},
		{
			name: "clearing the login client with a blank secret clears it",
			prev: loginOnly,
			next: OAuth2Config{},
		},
		{
			name: "clearing the login client while echoing the mask clears it",
			prev: loginOnly,
			next: OAuth2Config{ClientSecret: maskedLogin},
		},
		{
			name:       "same login id with a masked secret keeps it",
			prev:       loginOnly,
			next:       OAuth2Config{ClientID: "app-1", ClientSecret: maskedLogin},
			wantSecret: storedLoginSecret,
		},
		{
			name:       "same login id with a blank secret keeps it",
			prev:       loginOnly,
			next:       OAuth2Config{ClientID: "app-1"},
			wantSecret: storedLoginSecret,
		},
		{
			name:               "same exchange id with a masked secret keeps it",
			prev:               exchangeOnly,
			next:               OAuth2Config{ExchangeClientID: "app-1", ExchangeClientSecret: secret.Mask(storedExchangeSecret)},
			wantExchangeSecret: storedExchangeSecret,
		},
		{
			name:       "exchange client moved to the login pair keeps its secret",
			prev:       exchangeOnly,
			next:       OAuth2Config{ClientID: "app-1"},
			wantSecret: storedExchangeSecret,
		},
		{
			name:               "login client moved to the exchange pair keeps its secret",
			prev:               loginOnly,
			next:               OAuth2Config{ExchangeClientID: "app-1", ExchangeClientSecret: maskedLogin},
			wantExchangeSecret: storedLoginSecret,
		},
		{
			name: "changed login id with a blank secret becomes a public client",
			prev: loginOnly,
			next: OAuth2Config{ClientID: "app-2"},
		},
		{
			name:       "changed login id with a masked secret stays masked",
			prev:       loginOnly,
			next:       OAuth2Config{ClientID: "app-2", ClientSecret: maskedLogin},
			wantSecret: maskedLogin,
		},
		{
			name: "new login id never takes another client's exchange secret",
			prev: exchangeOnly,
			next: OAuth2Config{ClientID: "app-2"},
		},
		{
			name: "new exchange id never takes another client's login secret",
			prev: loginOnly,
			next: OAuth2Config{ExchangeClientID: "app-2"},
		},
		{
			name:               "shared id keeps each pair's own secret",
			prev:               bothShared,
			next:               OAuth2Config{ClientID: "app-1", ExchangeClientID: "app-1"},
			wantSecret:         storedLoginSecret,
			wantExchangeSecret: storedExchangeSecret,
		},
		{
			name: "public login client sharing the exchange id stays public",
			prev: OAuth2Config{
				ClientID:         "app-1",
				ExchangeClientID: "app-1", ExchangeClientSecret: storedExchangeSecret,
			},
			next: OAuth2Config{
				ClientID:         "app-1",
				ExchangeClientID: "app-1", ExchangeClientSecret: secret.Mask(storedExchangeSecret),
			},
			wantExchangeSecret: storedExchangeSecret,
		},
		{
			name: "public exchange client sharing the login id stays public",
			prev: OAuth2Config{
				ClientID: "app-1", ClientSecret: storedLoginSecret,
				ExchangeClientID: "app-1",
			},
			next: OAuth2Config{
				ClientID: "app-1", ClientSecret: maskedLogin,
				ExchangeClientID: "app-1",
			},
			wantSecret: storedLoginSecret,
		},
		{
			name:       "ids are compared after trimming",
			prev:       exchangeOnly,
			next:       OAuth2Config{ClientID: " app-1 "},
			wantSecret: storedExchangeSecret,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			prev, next := tc.prev, tc.next
			cfg := Config{OAuth2: &next}
			cfg.ResolveSecretsFrom(Config{OAuth2: &prev})
			if cfg.OAuth2.ClientSecret != tc.wantSecret {
				t.Fatalf("ClientSecret = %q, want %q", cfg.OAuth2.ClientSecret, tc.wantSecret)
			}
			if cfg.OAuth2.ExchangeClientSecret != tc.wantExchangeSecret {
				t.Fatalf("ExchangeClientSecret = %q, want %q", cfg.OAuth2.ExchangeClientSecret, tc.wantExchangeSecret)
			}
		})
	}
}

func TestConfig_ResolveSecretsFrom_ClearedLoginClientStopsExchangeFallback(t *testing.T) {
	t.Parallel()
	prev := Config{OAuth2: &OAuth2Config{ClientID: "app-1", ClientSecret: storedLoginSecret}}
	next := Config{OAuth2: entraValidateOnly()}
	next.ResolveSecretsFrom(prev)
	if _, _, ok := next.OAuth2.ExchangeCredentials(); ok {
		t.Fatal("ExchangeCredentials() ok = true, want no fallback to a cleared login client")
	}
}

func TestConfig_ResolveSecretsFrom_ChangedLoginIDWithMaskIsRefused(t *testing.T) {
	t.Parallel()
	prev := Config{OAuth2: &OAuth2Config{ClientID: "app-1", ClientSecret: storedLoginSecret}}
	next := Config{OAuth2: entraValidateOnly()}
	next.OAuth2.ClientID = "app-2"
	next.OAuth2.ClientSecret = secret.Mask(storedLoginSecret)
	next.ResolveSecretsFrom(prev)
	if err := next.Validate(TypeOAuth2); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Validate() = %v, want a masked secret for a new client refused", err)
	}
}

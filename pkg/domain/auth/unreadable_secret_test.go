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
)

func TestOAuth2Config_UnreadableExchangeSecret(t *testing.T) {
	t.Parallel()
	stored := Config{OAuth2: &OAuth2Config{
		Issuer: "https://issuer.example.com", Audiences: []string{"gateway"},
		JWKSURL:          "https://issuer.example.com/.well-known/jwks.json",
		ExchangeClientID: "exchange", ExchangeSecretUnreadable: true,
	}}
	if err := stored.Validate(TypeOAuth2); err != nil {
		t.Fatalf("an unreadable stored secret must not block validation: %v", err)
	}

	echoed := Config{OAuth2: &OAuth2Config{
		Issuer: "https://issuer.example.com", Audiences: []string{"gateway"},
		JWKSURL:          "https://issuer.example.com/.well-known/jwks.json",
		ExchangeClientID: "exchange", ExchangeClientSecret: "***",
	}}
	echoed.ResolveSecretsFrom(stored)
	if echoed.OAuth2.ExchangeClientSecret != "" || !echoed.OAuth2.ExchangeSecretUnreadable {
		t.Fatalf("marker not carried: %+v", echoed.OAuth2)
	}
	if err := echoed.Validate(TypeOAuth2); err != nil {
		t.Fatalf("masked echo: %v", err)
	}

	moved := Config{OAuth2: &OAuth2Config{
		Issuer: "https://issuer.example.com", Audiences: []string{"gateway"},
		JWKSURL:          "https://issuer.example.com/.well-known/jwks.json",
		ExchangeClientID: "another-exchange",
	}}
	moved.ResolveSecretsFrom(stored)
	if moved.OAuth2.ExchangeSecretUnreadable {
		t.Fatal("a new client id does not inherit the marker")
	}
	if err := moved.Validate(TypeOAuth2); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("a new client id without a secret must be refused: %v", err)
	}
}

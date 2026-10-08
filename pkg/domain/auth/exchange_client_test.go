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

func entraValidateOnly() *OAuth2Config {
	return &OAuth2Config{
		Issuer:    "https://login.microsoftonline.com/tid/v2.0",
		Audiences: []string{"api://gateway"},
	}
}

func TestOAuth2Config_ExchangeClientDoesNotEnableBrokeredLogin(t *testing.T) {
	t.Parallel()
	cfg := entraValidateOnly()
	cfg.ExchangeClientID = "gw-app"
	cfg.ExchangeClientSecret = "s3cret"

	if err := cfg.validate(); err != nil {
		t.Fatalf("validate() = %v", err)
	}
	if cfg.Interactive() {
		t.Fatal("an exchange client must not make the provider interactive")
	}
	if id, secret, ok := cfg.ExchangeCredentials(); !ok || id != "gw-app" || secret != "s3cret" {
		t.Fatalf("ExchangeCredentials() = %q, %q, %v", id, secret, ok)
	}
}

func TestOAuth2Config_ExchangeCredentials(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name               string
		cfg                *OAuth2Config
		wantID, wantSecret string
		wantOK             bool
	}{
		{"none", entraValidateOnly(), "", "", false},
		{"nil", nil, "", "", false},
		{"legacy login client", &OAuth2Config{ClientID: "login", ClientSecret: "ls"}, "login", "ls", true},
		{
			"exchange client wins over the login client",
			&OAuth2Config{ClientID: "login", ClientSecret: "ls", ExchangeClientID: "obo", ExchangeClientSecret: "os"},
			"obo", "os", true,
		},
		{"login client without a secret", &OAuth2Config{ClientID: "login"}, "", "", false},
		{
			"exchange client without a secret does not fall back to the login client",
			&OAuth2Config{ClientID: "login", ClientSecret: "ls", ExchangeClientID: "obo"},
			"", "", false,
		},
		{
			"unreadable exchange secret does not fall back to the login client",
			&OAuth2Config{ClientID: "login", ClientSecret: "ls", ExchangeClientID: "obo", ExchangeSecretUnreadable: true},
			"", "", false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			id, secret, ok := tc.cfg.ExchangeCredentials()
			if id != tc.wantID || secret != tc.wantSecret || ok != tc.wantOK {
				t.Fatalf("ExchangeCredentials() = %q, %q, %v; want %q, %q, %v", id, secret, ok, tc.wantID, tc.wantSecret, tc.wantOK)
			}
		})
	}
}

func TestOAuth2Config_Validate_ExchangeClient(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		id, secret     string
		wantInvalidCfg bool
	}{
		{"both set", "gw-app", "s3cret", false},
		{"neither set", "", "", false},
		{"id without secret", "gw-app", "", true},
		{"secret without id", "", "s3cret", true},
		{"masked secret", "gw-app", "********cret", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := entraValidateOnly()
			cfg.ExchangeClientID = tc.id
			cfg.ExchangeClientSecret = tc.secret
			err := cfg.validate()
			if tc.wantInvalidCfg != errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("validate() = %v, wantInvalidConfig %v", err, tc.wantInvalidCfg)
			}
		})
	}
}

func TestConfig_ResolveSecretsFrom_ExchangeClient(t *testing.T) {
	t.Parallel()
	prev := Config{OAuth2: &OAuth2Config{ExchangeClientID: "gw-app", ExchangeClientSecret: "stored"}}

	kept := Config{OAuth2: &OAuth2Config{ExchangeClientID: "gw-app"}}
	kept.ResolveSecretsFrom(prev)
	if kept.OAuth2.ExchangeClientSecret != "stored" {
		t.Fatalf("omitted secret = %q, want the stored one", kept.OAuth2.ExchangeClientSecret)
	}

	cleared := Config{OAuth2: &OAuth2Config{}}
	cleared.ResolveSecretsFrom(prev)
	if cleared.OAuth2.ExchangeClientSecret != "" {
		t.Fatal("clearing the exchange client must not keep its stored secret")
	}

	clearedEchoingMask := Config{OAuth2: &OAuth2Config{ExchangeClientSecret: "********ored"}}
	clearedEchoingMask.ResolveSecretsFrom(prev)
	if clearedEchoingMask.OAuth2.ExchangeClientSecret != "" {
		t.Fatal("clearing the client while echoing the masked secret must clear the secret")
	}

	changed := Config{OAuth2: &OAuth2Config{ExchangeClientID: "other-app"}}
	changed.ResolveSecretsFrom(prev)
	if changed.OAuth2.ExchangeClientSecret != "" {
		t.Fatal("a new exchange client must not inherit the old client's secret")
	}
	full := entraValidateOnly()
	full.ExchangeClientID = "other-app"
	if err := full.validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("validate() = %v, want a new client without a secret refused", err)
	}
}

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
	"context"
	"encoding/json"
	"strings"
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
)

func sealingRepo(t *testing.T, secret string, encryptWrites bool) *Repository {
	t.Helper()
	s, err := crypto.NewFieldSealer(secret, crypto.RegistrySecretsPurpose)
	if err != nil {
		t.Fatalf("NewFieldSealer: %v", err)
	}
	r := &Repository{}
	WithFieldSealer(s, encryptWrites)(r)
	return r
}

const unitTestSecret = "unit-test-secret-0123456789abcdef"

func oauth2Config() domain.Config {
	return domain.Config{OAuth2: &domain.OAuth2Config{
		Issuer:               "https://idp.example.com",
		ClientID:             "login",
		ClientSecret:         "login-secret-value",
		ExchangeClientID:     "exchange",
		ExchangeClientSecret: "exchange-secret-value",
	}}
}

func decode(t *testing.T, raw []byte) domain.Config {
	t.Helper()
	var c domain.Config
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return c
}

func TestMarshalConfig_EncryptsClientSecretsWhenEnabled(t *testing.T) {
	t.Parallel()
	r := sealingRepo(t, unitTestSecret, true)
	id := ids.New[ids.AuthKind]()
	in := oauth2Config()

	raw, err := r.marshalConfig(id, in)
	if err != nil {
		t.Fatalf("marshalConfig: %v", err)
	}
	if strings.Contains(string(raw), "login-secret-value") || strings.Contains(string(raw), "exchange-secret-value") {
		t.Fatalf("stored config holds a readable secret: %s", raw)
	}
	if in.OAuth2.ClientSecret != "login-secret-value" {
		t.Fatal("marshal must not modify the domain config")
	}
	stored := decode(t, raw)
	if !crypto.IsSealed(stored.OAuth2.ClientSecret) || !crypto.IsSealed(stored.OAuth2.ExchangeClientSecret) {
		t.Fatalf("secrets not in the enc:v1 form: %+v", stored.OAuth2)
	}
	if hasUnsealedSecrets(stored) || !hasUnsealedSecrets(in) {
		t.Fatal("hasUnsealedSecrets misreports")
	}
	sealingRepo(t, unitTestSecret, false).openConfigForRead(context.Background(), id, &stored)
	if stored.OAuth2.ClientSecret != "login-secret-value" || stored.OAuth2.ExchangeClientSecret != "exchange-secret-value" {
		t.Fatalf("round trip lost values: %+v", stored.OAuth2)
	}
}

func TestMarshalConfig_WritesPlainWhenEncryptionIsOff(t *testing.T) {
	t.Parallel()
	raw, err := sealingRepo(t, unitTestSecret, false).marshalConfig(ids.New[ids.AuthKind](), oauth2Config())
	if err != nil {
		t.Fatalf("marshalConfig: %v", err)
	}
	if strings.Contains(string(raw), crypto.SealedPrefix) || !strings.Contains(string(raw), "login-secret-value") {
		t.Fatalf("expected the payload unencrypted: %s", raw)
	}
}

func TestOpenConfigForRead_LegacyAndUnreadableValues(t *testing.T) {
	t.Parallel()
	legacy := oauth2Config()
	sealingRepo(t, unitTestSecret, true).openConfigForRead(context.Background(), ids.New[ids.AuthKind](), &legacy)
	if legacy.OAuth2.ClientSecret != "login-secret-value" {
		t.Fatalf("legacy read = %+v", legacy.OAuth2)
	}

	id := ids.New[ids.AuthKind]()
	raw, _ := sealingRepo(t, unitTestSecret, true).marshalConfig(id, oauth2Config())
	for name, read := range map[string]func(*domain.Config){
		"other row": func(c *domain.Config) {
			sealingRepo(t, unitTestSecret, true).openConfigForRead(context.Background(), ids.New[ids.AuthKind](), c)
		},
		"other key": func(c *domain.Config) {
			sealingRepo(t, "another-unit-test-secret-0123456789", true).openConfigForRead(context.Background(), id, c)
		},
		"no sealer": func(c *domain.Config) { (&Repository{}).openConfigForRead(context.Background(), id, c) },
	} {
		stored := decode(t, raw)
		read(&stored)
		if stored.OAuth2.ClientSecret != "" || stored.OAuth2.ExchangeClientSecret != "" {
			t.Fatalf("%s: unreadable secrets must come back empty: %+v", name, stored.OAuth2)
		}
		if stored.OAuth2.ClientID != "login" || stored.OAuth2.Issuer == "" {
			t.Fatalf("%s: the rest of the config must survive: %+v", name, stored.OAuth2)
		}
	}
}

func TestOpenConfigForRead_MarksWhatDidNotOpen(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.AuthKind]()
	raw, err := sealingRepo(t, unitTestSecret, true).marshalConfig(id, oauth2Config())
	if err != nil {
		t.Fatalf("marshalConfig: %v", err)
	}
	stored := decode(t, raw)
	(&Repository{}).openConfigForRead(context.Background(), id, &stored)
	if !stored.OAuth2.ClientSecretUnreadable || !stored.OAuth2.ExchangeSecretUnreadable {
		t.Fatalf("unreadable secrets not marked: %+v", stored.OAuth2)
	}
}

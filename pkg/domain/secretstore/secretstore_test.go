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

package secretstore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

func vaultStore() *secretstore.Store {
	return &secretstore.Store{
		Name:         "corp-vault",
		Type:         secretstore.TypeHashiCorpVault,
		AllowedPaths: []string{"ai-gateway/"},
		Config: &secretstore.HashiCorpVaultConfig{
			Address: "https://vault.internal:8200",
			Auth:    secretstore.VaultAuth{Method: secretstore.VaultAuthKubernetes, Role: "trustgate"},
		},
	}
}

func TestStoreValidate(t *testing.T) {
	t.Parallel()
	if err := vaultStore().Validate(); err != nil {
		t.Fatalf("valid store refused: %v", err)
	}
	tests := map[string]func(s *secretstore.Store){
		"bad name":              func(s *secretstore.Store) { s.Name = "Corp Vault" },
		"no allowed paths":      func(s *secretstore.Store) { s.AllowedPaths = nil },
		"empty prefix":          func(s *secretstore.Store) { s.AllowedPaths = []string{" "} },
		"absolute prefix":       func(s *secretstore.Store) { s.AllowedPaths = []string{"/ai-gateway/"} },
		"nil gateway":           func(s *secretstore.Store) { s.Gateways = []ids.GatewayID{{}} },
		"ttl too short":         func(s *secretstore.Store) { s.Cache.TTL = time.Second },
		"negative max stale":    func(s *secretstore.Store) { s.Cache.MaxStale = -time.Second },
		"missing config":        func(s *secretstore.Store) { s.Config = nil },
		"type mismatch":         func(s *secretstore.Store) { s.Type = secretstore.TypeEnv },
		"phase 2 type":          func(s *secretstore.Store) { s.Type = secretstore.TypeAzureKeyVault },
		"vault without address": func(s *secretstore.Store) { s.Config.(*secretstore.HashiCorpVaultConfig).Address = "" },
		"vault address with credentials": func(s *secretstore.Store) {
			s.Config.(*secretstore.HashiCorpVaultConfig).Address = "https://u:p@vault"
		},
		"vault kv 3":          func(s *secretstore.Store) { s.Config.(*secretstore.HashiCorpVaultConfig).KVVersion = 3 },
		"vault relative CA":   func(s *secretstore.Store) { s.Config.(*secretstore.HashiCorpVaultConfig).CACertFile = "ca.crt" },
		"kubernetes no role":  func(s *secretstore.Store) { s.Config.(*secretstore.HashiCorpVaultConfig).Auth.Role = "" },
		"unknown auth method": func(s *secretstore.Store) { s.Config.(*secretstore.HashiCorpVaultConfig).Auth.Method = "userpass" },
		"approle without secret file": func(s *secretstore.Store) {
			s.Config.(*secretstore.HashiCorpVaultConfig).Auth = secretstore.VaultAuth{Method: secretstore.VaultAuthAppRole, RoleID: "r"}
		},
		"token without file": func(s *secretstore.Store) {
			s.Config.(*secretstore.HashiCorpVaultConfig).Auth = secretstore.VaultAuth{Method: secretstore.VaultAuthToken}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := vaultStore()
			mutate(s)
			err := s.Validate()
			if !errors.Is(err, secretstore.ErrInvalidStore) || !errors.Is(err, commonerrors.ErrInvalidConfig) {
				t.Fatalf("Validate() = %v, want ErrInvalidStore", err)
			}
		})
	}
}

func TestTypedConfigs(t *testing.T) {
	t.Parallel()
	valid := []secretstore.TypedConfig{
		&secretstore.AWSSecretsManagerConfig{Region: "eu-west-1"},
		&secretstore.AWSSecretsManagerConfig{Region: "eu-west-1", Endpoint: "https://vpce.example", AssumeRoleARN: "arn:aws:iam::1:role/r"},
		&secretstore.GCPSecretManagerConfig{ProjectID: "acme-ai"},
		&secretstore.FileConfig{Root: "/var/run/trustgate/secrets"},
		&secretstore.EnvConfig{Prefix: "TG_SECRET_"},
		&secretstore.HashiCorpVaultConfig{Address: "http://vault:8200", KVVersion: 1, Auth: secretstore.VaultAuth{Method: secretstore.VaultAuthJWT, Role: "r", JWTFile: "/var/run/jwt"}},
		&secretstore.HashiCorpVaultConfig{Address: "https://vault", Auth: secretstore.VaultAuth{Method: secretstore.VaultAuthAppRole, RoleID: "r", SecretIDFile: "/etc/s"}},
		&secretstore.HashiCorpVaultConfig{Address: "https://vault", Auth: secretstore.VaultAuth{Method: secretstore.VaultAuthToken, TokenFile: "/etc/t"}},
	}
	for _, c := range valid {
		if err := c.Validate(); err != nil {
			t.Errorf("%T refused: %v", c, err)
		}
	}
	invalid := []secretstore.TypedConfig{
		&secretstore.AWSSecretsManagerConfig{},
		&secretstore.AWSSecretsManagerConfig{Region: "eu-west-1", Endpoint: "vpce.example"},
		&secretstore.AWSSecretsManagerConfig{Region: "eu-west-1", AssumeRoleARN: "role/r"},
		&secretstore.GCPSecretManagerConfig{},
		&secretstore.FileConfig{Root: "secrets"},
		&secretstore.FileConfig{Root: "/"},
		&secretstore.EnvConfig{},
		&secretstore.HashiCorpVaultConfig{Address: "https://vault", Auth: secretstore.VaultAuth{Method: secretstore.VaultAuthAppRole, RoleID: "r", SecretIDFile: "secret_id"}},
	}
	for _, c := range invalid {
		if err := c.Validate(); !errors.Is(err, secretstore.ErrInvalidStore) {
			t.Errorf("%T %+v accepted (err %v)", c, c, err)
		}
	}
}

func TestVaultDefaults(t *testing.T) {
	t.Parallel()
	c := &secretstore.HashiCorpVaultConfig{Auth: secretstore.VaultAuth{Method: secretstore.VaultAuthKubernetes}}
	if c.EffectiveMount() != "secret" || c.EffectiveKVVersion() != 2 {
		t.Fatalf("defaults: mount %q, kv %d", c.EffectiveMount(), c.EffectiveKVVersion())
	}
	if c.Auth.EffectiveMount() != "kubernetes" || c.Auth.EffectiveJWTFile() != secretstore.DefaultServiceAccountTokenFile {
		t.Fatalf("auth defaults: mount %q, jwt %q", c.Auth.EffectiveMount(), c.Auth.EffectiveJWTFile())
	}
}

func TestCachePolicyDefaults(t *testing.T) {
	t.Parallel()
	got := secretstore.CachePolicy{}.WithDefaults()
	want := secretstore.CachePolicy{TTL: 5 * time.Minute, MaxStale: 24 * time.Hour, NegativeTTL: 30 * time.Second}
	if got != want {
		t.Fatalf("WithDefaults() = %+v, want %+v", got, want)
	}
	if kept := (secretstore.CachePolicy{TTL: time.Minute}).WithDefaults(); kept.TTL != time.Minute {
		t.Fatalf("WithDefaults() overwrote ttl: %v", kept.TTL)
	}
}

func TestStoreAllows(t *testing.T) {
	t.Parallel()
	teamA := ids.New[ids.GatewayKind]()
	teamB := ids.New[ids.GatewayKind]()

	s := vaultStore()
	if err := s.Allows(teamB, "ai-gateway/openai"); err != nil {
		t.Fatalf("empty allowlist must admit every gateway: %v", err)
	}
	if err := s.Allows(teamA, "payments/db"); !errors.Is(err, secretstore.ErrPathNotAllowed) {
		t.Fatalf("path outside the prefixes: %v", err)
	}

	s.Gateways = []ids.GatewayID{teamA}
	if err := s.Allows(teamA, "ai-gateway/openai"); err != nil {
		t.Fatalf("allowlisted gateway refused: %v", err)
	}
	if err := s.Allows(teamB, "ai-gateway/openai"); !errors.Is(err, secretstore.ErrNotAllowed) {
		t.Fatalf("gateway outside the allowlist: %v", err)
	}

	s.AllowedPaths = []string{"*"}
	if !s.AllowsPath("anything/at/all") {
		t.Fatal("explicit * must allow every path")
	}
	s.AllowedPaths = []string{"*secret"}
	if s.AllowsPath("my-secret") {
		t.Fatal("* only matches when it is the whole prefix")
	}
}

func TestClassOf(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err  error
		want secretstore.Class
	}{
		{nil, ""},
		{fmt.Errorf("vault: %w", secretstore.ErrNotFound), secretstore.ClassNotFound},
		{fmt.Errorf("vault: %w", secretstore.ErrAccessDenied), secretstore.ClassAccessDenied},
		{secretstore.ErrFieldNotFound, secretstore.ClassFieldNotFound},
		{secretstore.ErrInvalidPayload, secretstore.ClassInvalidPayload},
		{secretstore.ErrAuthFailed, secretstore.ClassAuthFailed},
		{secretstore.ErrStoreMissing, secretstore.ClassStoreMissing},
		{secretstore.ErrNotAllowed, secretstore.ClassNotAllowed},
		{secretstore.ErrPathNotAllowed, secretstore.ClassPathNotAllowed},
		{secretstore.ErrUnavailable, secretstore.ClassUnavailable},
		{errors.New("connection reset"), secretstore.ClassUnavailable},
		{context.DeadlineExceeded, secretstore.ClassUnavailable},
		{context.Canceled, secretstore.ClassUnavailable},
	}
	for _, tt := range tests {
		if got := secretstore.ClassOf(tt.err); got != tt.want {
			t.Errorf("ClassOf(%v) = %q, want %q", tt.err, got, tt.want)
		}
	}
}

func TestServesStale(t *testing.T) {
	t.Parallel()
	stale := map[secretstore.Class]bool{
		secretstore.ClassUnavailable:    true,
		secretstore.ClassAuthFailed:     true,
		secretstore.ClassNotFound:       false,
		secretstore.ClassAccessDenied:   false,
		secretstore.ClassFieldNotFound:  false,
		secretstore.ClassInvalidPayload: false,
		secretstore.ClassStoreMissing:   false,
		secretstore.ClassNotAllowed:     false,
		secretstore.ClassPathNotAllowed: false,
	}
	for class, want := range stale {
		if got := secretstore.ServesStale(class); got != want {
			t.Errorf("ServesStale(%q) = %v, want %v", class, got, want)
		}
	}
}

func TestSecretSelect(t *testing.T) {
	t.Parallel()
	kv := secretstore.NewFieldsSecret(map[string]string{"api_key": "sk-1", "org": "o"}, "7")
	if v, err := kv.Select("api_key"); err != nil || v != "sk-1" {
		t.Fatalf("Select(api_key) = %q, %v", v, err)
	}
	if _, err := kv.Select("missing"); !errors.Is(err, secretstore.ErrFieldNotFound) {
		t.Fatalf("missing field: %v", err)
	}
	if _, err := kv.Select(""); !errors.Is(err, secretstore.ErrInvalidPayload) {
		t.Fatalf("two keys and no field: %v", err)
	}
	single := secretstore.NewFieldsSecret(map[string]string{"value": "sk-2"}, "")
	if v, err := single.Select(""); err != nil || v != "sk-2" {
		t.Fatalf("single key, no field = %q, %v", v, err)
	}

	plain := secretstore.NewStringSecret("sk-3", "AWSCURRENT")
	if v, err := plain.Select(""); err != nil || v != "sk-3" || plain.Version() != "AWSCURRENT" {
		t.Fatalf("whole string = %q, %v, version %q", v, err, plain.Version())
	}
	if _, err := plain.Select("key"); !errors.Is(err, secretstore.ErrInvalidPayload) {
		t.Fatalf("field of a non-JSON payload: %v", err)
	}

	object := secretstore.NewStringSecret(`{"key":"sk-4","n":1,"nested":{"a":"b"}}`, "")
	if v, err := object.Select("key"); err != nil || v != "sk-4" {
		t.Fatalf("JSON field = %q, %v", v, err)
	}
	for _, field := range []string{"n", "nested"} {
		if _, err := object.Select(field); !errors.Is(err, secretstore.ErrInvalidPayload) {
			t.Errorf("non-string JSON field %q: %v", field, err)
		}
	}
	if _, err := object.Select("absent"); !errors.Is(err, secretstore.ErrFieldNotFound) {
		t.Fatalf("absent JSON field: %v", err)
	}
	if _, err := secretstore.NewStringSecret("null", "").Select("key"); !errors.Is(err, secretstore.ErrInvalidPayload) {
		t.Fatalf("null payload: %v", err)
	}
}

func TestSecretEqual(t *testing.T) {
	t.Parallel()
	a := secretstore.NewFieldsSecret(map[string]string{"k": "v"}, "1")
	if !a.Equal(secretstore.NewFieldsSecret(map[string]string{"k": "v"}, "2")) {
		t.Error("the version must not count")
	}
	for _, other := range []secretstore.Secret{
		secretstore.NewFieldsSecret(map[string]string{"k": "w"}, "1"),
		secretstore.NewFieldsSecret(map[string]string{"k": "v", "x": "y"}, "1"),
		secretstore.NewFieldsSecret(map[string]string{"j": "v"}, "1"),
		secretstore.NewStringSecret("v", "1"),
	} {
		if a.Equal(other) || other.Equal(a) {
			t.Errorf("%v equal to a different payload", other)
		}
	}
	if !secretstore.NewStringSecret("v", "").Equal(secretstore.NewStringSecret("v", "x")) {
		t.Error("same string payload must be equal")
	}
	if secretstore.NewStringSecret("", "").Equal(secretstore.NewFieldsSecret(nil, "")) {
		t.Error("an empty string and an empty key/value payload differ")
	}
}

func TestKVSecret(t *testing.T) {
	t.Parallel()
	s := secretstore.NewKVSecret(map[string]any{"key": "sk", "n": 1.0, "obj": map[string]any{}}, "4")
	if v, err := s.Select("key"); err != nil || v != "sk" || s.Version() != "4" {
		t.Fatalf("Select(key) = %q, %v", v, err)
	}
	for _, f := range []string{"n", "obj", ""} {
		if _, err := s.Select(f); !errors.Is(err, secretstore.ErrInvalidPayload) {
			t.Errorf("Select(%q) = %v, want invalid_payload", f, err)
		}
	}
	if _, err := s.Select("absent"); !errors.Is(err, secretstore.ErrFieldNotFound) {
		t.Errorf("absent: %v", err)
	}
	if _, err := secretstore.NewKVSecret(map[string]any{"n": true}, "").Select(""); !errors.Is(err, secretstore.ErrInvalidPayload) {
		t.Errorf("single non-string key: %v", err)
	}
	if v, err := secretstore.NewKVSecret(map[string]any{"only": "x"}, "").Select(""); err != nil || v != "x" {
		t.Errorf("single string key = %q, %v", v, err)
	}
	if s.Equal(secretstore.NewKVSecret(map[string]any{"key": "sk"}, "4")) {
		t.Error("dropping a non-string key must count as a change")
	}
}

func TestNewFieldsSecretCopies(t *testing.T) {
	t.Parallel()
	fields := map[string]string{"k": "before"}
	s := secretstore.NewFieldsSecret(fields, "")
	fields["k"] = "after"
	if v, _ := s.Select("k"); v != "before" {
		t.Fatalf("secret shares the caller's map: %q", v)
	}
}

func TestSecretNeverPrintsItsValue(t *testing.T) {
	t.Parallel()
	const value = "sk-live-do-not-leak"
	secrets := []secretstore.Secret{
		secretstore.NewStringSecret(value, "1"),
		secretstore.NewFieldsSecret(map[string]string{"k": value}, "1"),
	}
	for _, s := range secrets {
		var logged bytes.Buffer
		slog.New(slog.NewJSONHandler(&logged, nil)).Info("fetched", slog.Any("secret", s))
		marshalled, err := json.Marshal(map[string]any{"secret": s})
		if err != nil {
			t.Fatal(err)
		}
		outputs := []string{
			fmt.Sprint(s), fmt.Sprintf("%v %+v %#v %s %q", s, s, s, s, s),
			logged.String(), string(marshalled),
		}
		for _, out := range outputs {
			if strings.Contains(out, value) {
				t.Fatalf("value leaked in %q", out)
			}
		}
	}
}

func TestEligibility(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"", " Hybrid "} {
		if e, err := secretstore.ParseEligibility(in); err != nil || e != secretstore.EligibilityHybrid {
			t.Errorf("ParseEligibility(%q) = %q, %v", in, e, err)
		}
	}
	if e, err := secretstore.ParseEligibility("ALL"); err != nil || e != secretstore.EligibilityAll {
		t.Errorf("ParseEligibility(ALL) = %q, %v", e, err)
	}
	if _, err := secretstore.ParseEligibility("hosted"); err == nil {
		t.Error("unknown eligibility accepted")
	}

	gw := func(dataPlane string) *gateway.Gateway {
		return &gateway.Gateway{Entitlements: gateway.Entitlements{DataPlane: dataPlane}}
	}
	tests := []struct {
		e    secretstore.Eligibility
		gw   *gateway.Gateway
		want bool
	}{
		{secretstore.EligibilityHybrid, gw(gateway.DataPlaneHybrid), true},
		{secretstore.EligibilityHybrid, gw(""), false},
		{secretstore.EligibilityHybrid, gw(gateway.DataPlaneHosted), false},
		{secretstore.EligibilityHybrid, gw(gateway.DataPlaneDedicated), false},
		{secretstore.EligibilityAll, gw(""), true},
		{secretstore.EligibilityAll, gw(gateway.DataPlaneDedicated), true},
		{"", gw(""), false},
		{secretstore.EligibilityAll, nil, false},
	}
	for _, tt := range tests {
		if got := secretstore.Eligible(tt.e, tt.gw); got != tt.want {
			t.Errorf("Eligible(%q, %+v) = %v, want %v", tt.e, tt.gw, got, tt.want)
		}
	}
}

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

package registry

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
)

const unitTestSecret = "unit-test-secret-0123456789abcdef"

func newSealer(t *testing.T, secret string) *crypto.FieldSealer {
	t.Helper()
	s, err := crypto.NewFieldSealer(secret, crypto.RegistrySecretsPurpose)
	if err != nil {
		t.Fatalf("NewFieldSealer: %v", err)
	}
	return s
}

func sealingRepo(t *testing.T, encryptWrites bool) *Repository {
	t.Helper()
	r := &Repository{}
	WithFieldSealer(newSealer(t, unitTestSecret), encryptWrites)(r)
	return r
}

func credentialTarget() *domain.MCPTarget {
	return &domain.MCPTarget{
		URL:     "https://mcp.example.com/mcp",
		Headers: map[string]string{"X-Api-Key": "header-value"},
		Auth: &domain.MCPAuth{
			Mode:         domain.MCPAuthModeClientCredentials,
			ClientID:     "cid",
			ClientSecret: "client-secret-value",
			Value:        "static-value",
			TokenURL:     "https://idp.example.com/token",
		},
	}
}

func storedTarget(t *testing.T, raw []byte) *domain.MCPTarget {
	t.Helper()
	var stored domain.MCPTarget
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return &stored
}

func TestMarshalMCPTarget_EncryptsCredentialsWhenEnabled(t *testing.T) {
	t.Parallel()
	r := sealingRepo(t, true)
	id := ids.New[ids.RegistryKind]()
	in := credentialTarget()

	raw, err := r.marshalMCPTarget(id, in)
	if err != nil {
		t.Fatalf("marshalMCPTarget: %v", err)
	}
	for _, plain := range []string{"header-value", "client-secret-value", "static-value"} {
		if strings.Contains(string(raw), plain) {
			t.Fatalf("stored mcp_target contains %q: %s", plain, raw)
		}
	}
	stored := storedTarget(t, raw)
	for _, v := range []string{stored.Headers["X-Api-Key"], stored.Auth.ClientSecret, stored.Auth.Value} {
		if !strings.HasPrefix(v, crypto.SealedPrefix+r.sealer.KeyID()+":") {
			t.Fatalf("stored value %q is not in the enc:v1 form", v)
		}
	}
	if stored.Auth.ClientID != "cid" || stored.URL != in.URL {
		t.Fatalf("non-secret fields changed: %+v", stored)
	}
	if in.Headers["X-Api-Key"] != "header-value" || in.Auth.ClientSecret != "client-secret-value" {
		t.Fatal("marshal must not modify the domain object")
	}
	if !hasUnsealedSecrets(in) || hasUnsealedSecrets(stored) {
		t.Fatal("hasUnsealedSecrets misreports")
	}

	r.openMCPTargetForRead(context.Background(), id, stored)
	if stored.Headers["X-Api-Key"] != "header-value" || stored.Auth.ClientSecret != "client-secret-value" || stored.Auth.Value != "static-value" {
		t.Fatalf("round trip lost values: %+v %+v", stored.Headers, stored.Auth)
	}
}

func TestMarshalMCPTarget_WritesPlainWhenEncryptionIsOff(t *testing.T) {
	t.Parallel()
	for _, r := range []*Repository{sealingRepo(t, false), {}} {
		raw, err := r.marshalMCPTarget(ids.New[ids.RegistryKind](), credentialTarget())
		if err != nil {
			t.Fatalf("marshalMCPTarget: %v", err)
		}
		if strings.Contains(string(raw), crypto.SealedPrefix) || !strings.Contains(string(raw), "client-secret-value") {
			t.Fatalf("expected the payload unencrypted: %s", raw)
		}
	}
}

func TestOpenMCPTargetForRead_ReadsEncryptedValuesWhenWritesAreOff(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.RegistryKind]()
	raw, err := sealingRepo(t, true).marshalMCPTarget(id, credentialTarget())
	if err != nil {
		t.Fatalf("marshalMCPTarget: %v", err)
	}
	stored := storedTarget(t, raw)
	sealingRepo(t, false).openMCPTargetForRead(context.Background(), id, stored)
	if stored.Auth.Value != "static-value" || stored.Headers["X-Api-Key"] != "header-value" {
		t.Fatalf("encrypted values not read: %+v", stored)
	}
}

func TestOpenMCPTargetForRead_LegacyPlainValues(t *testing.T) {
	t.Parallel()
	for _, r := range []*Repository{sealingRepo(t, true), {}} {
		target := credentialTarget()
		r.openMCPTargetForRead(context.Background(), ids.New[ids.RegistryKind](), target)
		if target.Auth.ClientSecret != "client-secret-value" || target.Headers["X-Api-Key"] != "header-value" {
			t.Fatalf("legacy values changed: %+v", target)
		}
	}
}

func TestOpenMCPTargetForRead_BlanksValuesThatDoNotOpen(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.RegistryKind]()
	raw, err := sealingRepo(t, true).marshalMCPTarget(id, credentialTarget())
	if err != nil {
		t.Fatalf("marshalMCPTarget: %v", err)
	}
	otherKey := &Repository{}
	WithFieldSealer(newSealer(t, "another-unit-test-secret-0123456789"), true)(otherKey)
	readers := map[string]struct {
		repo *Repository
		id   ids.RegistryID
	}{
		"other row":  {sealingRepo(t, true), ids.New[ids.RegistryKind]()},
		"other key":  {otherKey, id},
		"no sealer":  {&Repository{}, id},
		"right read": {sealingRepo(t, true), id},
	}
	for name, reader := range readers {
		stored := storedTarget(t, raw)
		reader.repo.openMCPTargetForRead(context.Background(), reader.id, stored)
		if name == "right read" {
			if stored.Auth.Value != "static-value" {
				t.Fatalf("%s: value not read", name)
			}
			continue
		}
		if stored.Auth.Value != "" || stored.Auth.ClientSecret != "" || stored.Headers["X-Api-Key"] != "" {
			t.Fatalf("%s: unreadable values must come back empty: %+v %+v", name, stored.Auth, stored.Headers)
		}
		if _, ok := stored.Headers["X-Api-Key"]; !ok || stored.Auth.ClientID != "cid" {
			t.Fatalf("%s: the rest of the target must survive: %+v", name, stored)
		}
	}
}

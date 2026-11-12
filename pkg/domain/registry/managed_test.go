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

package registry_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// The managed keys are process-wide, so these tests do not run in parallel.

func TestNewManagedLLMRegistry_TakesNoCredentials(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()

	reg, err := domain.NewManagedLLMRegistry(gw, "OpenAI (NeuralTrust)", "", &domain.LLMTarget{Provider: "openai"})
	if err != nil {
		t.Fatalf("NewManagedLLMRegistry: %v", err)
	}
	if !reg.Managed || !reg.Enabled || reg.Auth() != nil {
		t.Fatalf("got managed=%v enabled=%v auth=%v, want a managed, enabled registry with no stored auth", reg.Managed, reg.Enabled, reg.Auth())
	}

	cases := map[string]*domain.LLMTarget{
		"stored credentials": {Provider: "openai", Auth: domain.NewAPIKeyAuth("sk-tenant")},
		"own host":           {Provider: "openai", ProviderOptions: map[string]any{"base_url": "https://evil.example"}},
		"unmanaged provider": {Provider: "anthropic"},
	}
	for name, target := range cases {
		if _, err := domain.NewManagedLLMRegistry(gw, "x", "", target); !errors.Is(err, commonerrors.ErrValidation) {
			t.Errorf("%s: err = %v, want a validation error", name, err)
		}
	}
}

func TestEffectiveAuth_ManagedUsesNeuralTrustKey(t *testing.T) {
	t.Cleanup(func() { domain.SetManagedAPIKeys(nil) })
	gw := ids.New[ids.GatewayKind]()
	managed, err := domain.NewManagedLLMRegistry(gw, "OpenAI (NeuralTrust)", "", &domain.LLMTarget{Provider: "openai"})
	if err != nil {
		t.Fatal(err)
	}
	own, err := domain.NewLLMRegistry(gw, "mine", "", &domain.LLMTarget{Provider: "openai", Auth: domain.NewAPIKeyAuth("sk-tenant")})
	if err != nil {
		t.Fatal(err)
	}

	domain.SetManagedAPIKeys(map[string]string{"openai": "  "})
	if auth := managed.EffectiveAuth(); auth != nil {
		t.Fatalf("blank key: EffectiveAuth = %+v, want nil", auth)
	}

	domain.SetManagedAPIKeys(map[string]string{"openai": "sk-neuraltrust"})
	auth := managed.EffectiveAuth()
	if auth == nil || auth.Type != domain.AuthTypeAPIKey || auth.APIKey == nil || auth.APIKey.APIKey != "sk-neuraltrust" {
		t.Fatalf("managed EffectiveAuth = %+v, want NeuralTrust's api key", auth)
	}
	if managed.Auth() != nil {
		t.Fatal("the managed key must never become the stored auth")
	}
	if got := own.EffectiveAuth(); got == nil || got.APIKey.APIKey != "sk-tenant" {
		t.Fatalf("unmanaged EffectiveAuth = %+v, want the stored key", got)
	}

	raw, err := json.Marshal(managed)
	if err != nil {
		t.Fatal(err)
	}
	if containsKey(raw, "sk-neuraltrust") {
		t.Fatalf("the snapshot form of a managed registry carries the key: %s", raw)
	}
}

func containsKey(raw []byte, key string) bool {
	return strings.Contains(string(raw), key)
}

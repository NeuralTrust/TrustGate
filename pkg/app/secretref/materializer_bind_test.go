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

package secretref

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

type switchingResolver struct {
	markerResolver
	value   string
	changed bool
}

func (r *switchingResolver) Resolve(context.Context, domain.Ref) (string, error) { return r.value, nil }

func (r *switchingResolver) ForceRefresh(context.Context, []domain.Ref) (bool, error) {
	return r.changed, nil
}

func TestCopiesAreBoundToTheirSourceAndFingerprinted(t *testing.T) {
	t.Parallel()
	r := &switchingResolver{value: "k1"}
	m := newMat(t, MaterializerConfig{Enabled: true, Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: r})
	gw := ids.New[ids.GatewayKind]()
	src := &registry.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gw, LLMTarget: &registry.LLMTarget{Auth: registry.NewAPIKeyAuth(refStr("k"))}}
	first := m.Registries(context.Background(), gw, map[ids.RegistryID]*registry.Registry{src.ID: src})[src.ID]
	if first.SecretSource() != src || first.SecretDigest() == "" {
		t.Fatalf("source %p digest %q", first.SecretSource(), first.SecretDigest())
	}
	if again := m.Registries(context.Background(), gw, map[ids.RegistryID]*registry.Registry{src.ID: src})[src.ID]; again.SecretDigest() != first.SecretDigest() {
		t.Fatal("the same values must give the same fingerprint")
	}
	if len(first.SecretDigest()) > 32 || first.SecretDigest() == "k1" {
		t.Fatalf("fingerprint %q", first.SecretDigest())
	}

	if _, ok := m.Refresh(context.Background(), first); ok {
		t.Fatal("no change, no retry")
	}
	r.value, r.changed = "k2", true
	fresh, ok := m.Refresh(context.Background(), first)
	if !ok || fresh.LLMTarget.Auth.APIKey.APIKey != "k2" || fresh.SecretDigest() == first.SecretDigest() {
		t.Fatalf("refresh = %v, %+v", ok, fresh)
	}
	plain := &registry.Registry{ID: ids.New[ids.RegistryKind]()}
	if _, ok := m.Refresh(context.Background(), plain); ok {
		t.Fatal("a registry without references is never retried")
	}
}

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

package store

import (
	"context"
	"fmt"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// RegistryEnsurer materialises the shared registry for a catalog code — the
// "created on first install" self-service path from the design memo. It is the
// write the DB-less data plane cannot make itself: on the control plane it
// persists the registry directly; on the data plane it is a thin gRPC forwarder
// to the control plane. Ensure is idempotent — a second call for a code that is
// already on the shelf is a no-op.
type RegistryEnsurer interface {
	Ensure(ctx context.Context, gatewayID ids.GatewayID, code string) error
}

// registryEnsurer is the control-plane implementation. It builds the shared
// registry from the catalog entry and persists it through the same registry
// Creator the admin's connect-from-catalog path uses, so a self-serviced
// registry is byte-for-byte the shape an admin would have shelved by hand
// (auth canonicalised from the catalog, config-sync signalled so it propagates
// to the data plane).
type registryEnsurer struct {
	catalog    CatalogReader
	registries RegistryLister
	creator    appregistry.Creator
}

// NewRegistryEnsurer wires the control-plane registry materialiser.
func NewRegistryEnsurer(
	catalog CatalogReader,
	registries RegistryLister,
	creator appregistry.Creator,
) (RegistryEnsurer, error) {
	if catalog == nil || registries == nil || creator == nil {
		return nil, ErrUnavailable
	}
	return &registryEnsurer{catalog: catalog, registries: registries, creator: creator}, nil
}

func (e *registryEnsurer) Ensure(ctx context.Context, gatewayID ids.GatewayID, code string) error {
	entry, ok := e.catalog.GetByCode(code)
	if !ok {
		return fmt.Errorf("%w: %q", ErrCatalogEntryNotFound, code)
	}
	// Already on the shelf (admin-connected or a prior install): nothing to do.
	// The check runs against whatever lister is local — the control plane's DB
	// here — so it reflects the authoritative registry set, not a lagging
	// snapshot.
	existing, err := findRegistryByCode(ctx, e.registries, gatewayID, code)
	if err != nil {
		return err
	}
	if existing != nil {
		return nil
	}
	enabled := true
	if _, err := e.creator.Create(ctx, appregistry.CreateInput{
		GatewayID: gatewayID,
		Name:      displayName(entry, code),
		Type:      registrydomain.TypeMCP,
		Enabled:   &enabled,
		MCPTarget: catalogMCPTarget(entry),
	}); err != nil {
		return fmt.Errorf("store: materialise registry for %q: %w", code, err)
	}
	return nil
}

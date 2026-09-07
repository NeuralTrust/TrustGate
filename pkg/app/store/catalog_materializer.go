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
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// ErrNeedsAdminSetup is returned when a catalog server cannot be materialised
// without an admin: its shared registry would carry a credential the catalog
// does not have (an API key header, a client_credentials secret, a manual
// OAuth client). The admin must connect it from the registry panel instead.
var ErrNeedsAdminSetup = fmt.Errorf("store: server needs admin setup before it can be used: %w", commonerrors.ErrConflict)

// CatalogMaterializer puts a self-service catalog server on the shelf on an
// admin's request — the consumer-binding counterpart of the user's first
// install. It exists so an admin can route a consumer to Notion (or any
// built-in) without first "installing" it by hand: the registry is created
// with the same shared shape a self-service install would produce, and the
// call is idempotent (an existing registry for the code is returned as is).
type CatalogMaterializer interface {
	Materialize(ctx context.Context, gatewayID ids.GatewayID, code string) (*registrydomain.Registry, error)
}

type catalogMaterializer struct {
	catalog    CatalogReader
	registries RegistryLister
	ensurer    RegistryEnsurer
}

// NewCatalogMaterializer wires the admin-facing materialiser over the same
// ensurer the installer and approver use.
func NewCatalogMaterializer(
	catalog CatalogReader,
	registries RegistryLister,
	ensurer RegistryEnsurer,
) (CatalogMaterializer, error) {
	if catalog == nil || registries == nil || ensurer == nil {
		return nil, ErrUnavailable
	}
	return &catalogMaterializer{catalog: catalog, registries: registries, ensurer: ensurer}, nil
}

func (m *catalogMaterializer) Materialize(
	ctx context.Context,
	gatewayID ids.GatewayID,
	code string,
) (*registrydomain.Registry, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, fmt.Errorf("store: catalog code is required: %w", commonerrors.ErrValidation)
	}
	entry, ok := m.catalog.GetByCode(code)
	if !ok {
		return nil, fmt.Errorf("%w: %q: %w", ErrCatalogEntryNotFound, code, commonerrors.ErrNotFound)
	}
	// An existing shelf entry (admin-connected or a prior install) wins, even
	// for servers that need admin setup: the admin already did it.
	existing, err := findRegistryByCode(ctx, m.registries, gatewayID, code)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return existing, nil
	}
	if catalogNeedsAdminCredential(entry) {
		return nil, fmt.Errorf("%w: %q", ErrNeedsAdminSetup, code)
	}
	if err := m.ensurer.Ensure(ctx, gatewayID, code); err != nil {
		return nil, err
	}
	created, err := findRegistryByCode(ctx, m.registries, gatewayID, code)
	if err != nil {
		return nil, err
	}
	if created == nil {
		return nil, fmt.Errorf("store: materialised registry for %q not found", code)
	}
	return created, nil
}

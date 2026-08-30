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

// Package store holds the MCP Store's application services: installing a
// catalog entry for a principal and scoping the per-principal surface.
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// registryListPageSize bounds the per-gateway registry scan used to find an
// already-provisioned shared registry for a catalog code. Registries per gateway
// are few (tens), so a single large page covers them.
const registryListPageSize = 500

var (
	ErrUnavailable          = errors.New("store: installer unavailable")
	ErrCatalogEntryNotFound = errors.New("store: catalog entry not found")
)

// CatalogReader is the catalog lookup the installer needs.
type CatalogReader interface {
	GetByCode(code string) (catalogdomain.MCPServer, bool)
}

// RegistryLister lists a gateway's registries so the installer can find an
// already-provisioned shared registry by catalog code.
type RegistryLister interface {
	List(ctx context.Context, filter registrydomain.ListFilter) ([]*registrydomain.Registry, int, error)
}

// InstallResult reports the outcome of an install to the caller (the meta-tool).
type InstallResult struct {
	Code             string
	Name             string
	RegistryID       string
	RequiresAuth     bool
	AlreadyInstalled bool
}

//go:generate mockery --name=Installer --dir=. --output=./mocks --filename=store_installer_mock.go --case=underscore --with-expecter
type Installer interface {
	Install(ctx context.Context, gatewayID ids.GatewayID, principalSub, code, installedBy string) (*InstallResult, error)
	Uninstall(ctx context.Context, gatewayID ids.GatewayID, principalSub, code string) error
}

type installer struct {
	catalog       CatalogReader
	registries    RegistryLister
	registryMaker appregistry.Creator
	installs      installationdomain.Repository
}

// NewInstaller wires the Store installer. The shared registry per catalog code
// is created on first install and reused by every subsequent installer of that
// code (auth stays per-principal in the vault), so a gateway holds ~one registry
// per MCP rather than one per user.
func NewInstaller(
	catalog CatalogReader,
	registries RegistryLister,
	registryMaker appregistry.Creator,
	installs installationdomain.Repository,
) (Installer, error) {
	if catalog == nil || registries == nil || registryMaker == nil || installs == nil {
		return nil, ErrUnavailable
	}
	return &installer{
		catalog:       catalog,
		registries:    registries,
		registryMaker: registryMaker,
		installs:      installs,
	}, nil
}

func (i *installer) Install(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, code, installedBy string,
) (*InstallResult, error) {
	code = strings.TrimSpace(code)
	entry, ok := i.catalog.GetByCode(code)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrCatalogEntryNotFound, code)
	}

	reg, err := i.ensureSharedRegistry(ctx, gatewayID, entry)
	if err != nil {
		return nil, err
	}

	existing, err := i.installs.Find(ctx, gatewayID, principalSub, code)
	alreadyInstalled := err == nil && existing.IsActive()
	if err != nil && !errors.Is(err, installationdomain.ErrNotFound) {
		return nil, err
	}

	record, err := installationdomain.New(gatewayID, principalSub, code, installedBy, nil)
	if err != nil {
		return nil, err
	}
	if err := i.installs.Upsert(ctx, record); err != nil {
		return nil, err
	}

	return &InstallResult{
		Code:             code,
		Name:             displayName(entry, code),
		RegistryID:       reg.ID.String(),
		RequiresAuth:     entry.RequiresAuth,
		AlreadyInstalled: alreadyInstalled,
	}, nil
}

func (i *installer) Uninstall(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, code string,
) error {
	// Remove only the per-principal installation; the shared registry stays for
	// other installers and is an admin-managed resource.
	return i.installs.Delete(ctx, gatewayID, principalSub, strings.TrimSpace(code))
}

// ensureSharedRegistry returns the gateway's registry for the catalog code,
// creating it on first install. Best-effort idempotent: it scans existing
// registries first; a concurrent first-install of the same code could create a
// second registry, which is harmless (both point at the same upstream).
func (i *installer) ensureSharedRegistry(
	ctx context.Context,
	gatewayID ids.GatewayID,
	entry catalogdomain.MCPServer,
) (*registrydomain.Registry, error) {
	if found, err := i.findRegistryByCode(ctx, gatewayID, entry.Code); err != nil {
		return nil, err
	} else if found != nil {
		return found, nil
	}

	created, err := i.registryMaker.Create(ctx, appregistry.CreateInput{
		GatewayID: gatewayID,
		Name:      displayName(entry, entry.Code),
		Type:      registrydomain.TypeMCP,
		MCPTarget: &registrydomain.MCPTarget{
			Code:      entry.Code,
			URL:       entry.URL,
			Transport: registrydomain.MCPTransport(strings.TrimSpace(entry.Transport)),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("store: provision shared registry for %q: %w", entry.Code, err)
	}
	return created, nil
}

func (i *installer) findRegistryByCode(
	ctx context.Context,
	gatewayID ids.GatewayID,
	code string,
) (*registrydomain.Registry, error) {
	items, _, err := i.registries.List(ctx, registrydomain.ListFilter{
		GatewayID: gatewayID,
		Page:      1,
		Size:      registryListPageSize,
	})
	if err != nil {
		return nil, fmt.Errorf("store: list registries: %w", err)
	}
	for _, reg := range items {
		if reg != nil && reg.MCPTarget != nil && reg.MCPTarget.Code == code {
			return reg, nil
		}
	}
	return nil, nil
}

func displayName(entry catalogdomain.MCPServer, code string) string {
	if name := strings.TrimSpace(entry.DisplayName); name != "" {
		return name
	}
	return code
}

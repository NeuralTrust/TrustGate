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
	"slices"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

const registryPageSize = 100

type gatewayRegistryLister interface {
	ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*registrydomain.Registry, error)
}

type catalogRegistryLister interface {
	ListByGatewayAndCatalogCode(ctx context.Context, gatewayID ids.GatewayID, code string) ([]*registrydomain.Registry, error)
}

type registryIDLister interface {
	ListByGatewayAndIDs(ctx context.Context, gatewayID ids.GatewayID, registryIDs []ids.RegistryID) ([]*registrydomain.Registry, error)
}

func listRegistriesByGateway(ctx context.Context, lister RegistryLister, gatewayID ids.GatewayID) ([]*registrydomain.Registry, error) {
	if indexed, ok := lister.(gatewayRegistryLister); ok {
		items, err := indexed.ListByGateway(ctx, gatewayID)
		if err != nil {
			return nil, fmt.Errorf("store: list registries: %w", err)
		}
		return items, nil
	}

	items := make([]*registrydomain.Registry, 0)
	seen := make(map[ids.RegistryID]struct{})
	for page := 1; ; page++ {
		batch, total, err := lister.List(ctx, registrydomain.ListFilter{GatewayID: gatewayID, Page: page, Size: registryPageSize})
		if err != nil {
			return nil, fmt.Errorf("store: list registries: %w", err)
		}
		added := 0
		for _, registry := range batch {
			if registry == nil {
				continue
			}
			if _, exists := seen[registry.ID]; exists {
				continue
			}
			seen[registry.ID] = struct{}{}
			items = append(items, registry)
			added++
		}
		if len(batch) == 0 || added == 0 || (total > 0 && len(items) >= total) || len(batch) < registryPageSize {
			return items, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
}

func findRegistriesByCode(ctx context.Context, lister RegistryLister, gatewayID ids.GatewayID, code string) ([]*registrydomain.Registry, error) {
	code = strings.TrimSpace(code)
	if indexed, ok := lister.(catalogRegistryLister); ok {
		items, err := indexed.ListByGatewayAndCatalogCode(ctx, gatewayID, code)
		if err != nil {
			return nil, fmt.Errorf("store: list registries by catalog code: %w", err)
		}
		items = slices.Clone(items)
		sortRegistries(items)
		return items, nil
	}

	items, err := listRegistriesByGateway(ctx, lister, gatewayID)
	if err != nil {
		return nil, err
	}
	out := make([]*registrydomain.Registry, 0, 1)
	for _, registry := range items {
		if registry.MCPTarget != nil && registry.MCPTarget.Code == code {
			out = append(out, registry)
		}
	}
	sortRegistries(out)
	return out, nil
}

func findRegistryByCode(ctx context.Context, lister RegistryLister, gatewayID ids.GatewayID, code string) (*registrydomain.Registry, error) {
	all, err := findRegistriesByCode(ctx, lister, gatewayID, code)
	if err != nil || len(all) == 0 {
		return nil, err
	}
	return all[0], nil
}

func listRegistriesForInstalls(
	ctx context.Context,
	lister RegistryLister,
	gatewayID ids.GatewayID,
	installs []*installationdomain.Installation,
) ([]*registrydomain.Registry, error) {
	byID, idsIndexed := lister.(registryIDLister)
	byCode, codesIndexed := lister.(catalogRegistryLister)
	if !idsIndexed || !codesIndexed {
		return listRegistriesByGateway(ctx, lister, gatewayID)
	}

	registryIDs := make([]ids.RegistryID, 0, len(installs))
	codes := make(map[string]struct{})
	for _, install := range installs {
		if install == nil {
			continue
		}
		if install.RegistryID.IsNil() {
			codes[install.CatalogCode] = struct{}{}
			continue
		}
		registryIDs = append(registryIDs, install.RegistryID)
	}
	items, err := byID.ListByGatewayAndIDs(ctx, gatewayID, registryIDs)
	if err != nil {
		return nil, fmt.Errorf("store: list registries by id: %w", err)
	}
	seen := make(map[ids.RegistryID]struct{}, len(items))
	for _, registry := range items {
		if registry != nil {
			seen[registry.ID] = struct{}{}
		}
	}
	for code := range codes {
		matches, err := byCode.ListByGatewayAndCatalogCode(ctx, gatewayID, code)
		if err != nil {
			return nil, fmt.Errorf("store: list registries by catalog code: %w", err)
		}
		for _, registry := range matches {
			if registry == nil {
				continue
			}
			if _, exists := seen[registry.ID]; exists {
				continue
			}
			seen[registry.ID] = struct{}{}
			items = append(items, registry)
		}
	}
	return items, nil
}

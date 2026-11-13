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

package secretstore

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	refdomain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
)

const usagesPageSize = 200

// Usage is one entity field of a gateway that references a store.
type Usage struct {
	Entity    string
	ID        string
	Name      string
	Field     string
	Reference string
	// State and ErrorClass are what the gateway's planes last reported about
	// the reference: set by Source.Annotate.
	State      string
	ErrorClass string
}

// RegistryLister pages through a gateway's registries as stored.
type RegistryLister interface {
	List(ctx context.Context, filter registry.ListFilter) ([]*registry.Registry, int, error)
}

//go:generate mockery --name=UsagesFinder --dir=. --output=./mocks --filename=secretstore_usages_finder_mock.go --case=underscore --with-expecter

// UsagesFinder lists the references a gateway holds.
type UsagesFinder interface {
	// Usages returns every field of the gateway that references a store,
	// grouped by store name and sorted.
	Usages(ctx context.Context, gatewayID ids.GatewayID) (map[string][]Usage, error)
}

type usagesFinder struct {
	registries RegistryLister
	entities   []EntityLister
}

// NewUsagesFinder returns a UsagesFinder over the stored registries and the
// entities the listers read.
func NewUsagesFinder(registries RegistryLister, entities ...EntityLister) UsagesFinder {
	return &usagesFinder{registries: registries, entities: entities}
}

func (f *usagesFinder) Usages(ctx context.Context, gatewayID ids.GatewayID) (map[string][]Usage, error) {
	out := map[string][]Usage{}
	seen := 0
	for page := 1; ; page++ {
		batch, total, err := f.registries.List(ctx, registry.ListFilter{GatewayID: gatewayID, Page: page, Size: usagesPageSize})
		if err != nil {
			return nil, fmt.Errorf("secret stores: list registries: %w", err)
		}
		for _, reg := range batch {
			addUsages(out, registryRefs(reg))
		}
		seen += len(batch)
		if len(batch) == 0 || seen >= total {
			break
		}
	}
	for _, list := range f.entities {
		entities, err := list(ctx, gatewayID)
		if err != nil {
			return nil, fmt.Errorf("secret stores: %w", err)
		}
		for _, e := range entities {
			addUsages(out, e)
		}
	}
	for name := range out {
		sort.Slice(out[name], func(i, j int) bool {
			a, b := out[name][i], out[name][j]
			if a.Entity != b.Entity {
				return a.Entity < b.Entity
			}
			if a.Name != b.Name {
				return a.Name < b.Name
			}
			return a.Field < b.Field
		})
	}
	return out, nil
}

func addUsages(out map[string][]Usage, e NamedRefs) {
	for _, u := range e.Uses {
		ref, _, err := refdomain.Parse(u.Raw)
		if err != nil {
			continue
		}
		out[ref.Store] = append(out[ref.Store], Usage{
			Entity: string(e.Entity), ID: e.ID, Name: e.Name,
			Field: strings.Join(u.Path, "."), Reference: u.Raw,
		})
	}
}

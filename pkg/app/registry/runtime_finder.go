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

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// RegistryMaterializer turns the secret references held by registries into
// values, returning the input map untouched when none holds a reference.
type RegistryMaterializer interface {
	Registries(ctx context.Context, gatewayID ids.GatewayID, byID map[ids.RegistryID]*domain.Registry) map[ids.RegistryID]*domain.Registry
}

//go:generate mockery --name=RuntimeFinder --dir=. --output=./mocks --filename=registry_runtime_finder_mock.go --case=underscore --with-expecter

// RuntimeFinder is the Finder of code that calls a registry's upstream
// (connection tests, model listing, MCP introspection): FindByID returns a
// copy whose secret references are resolved. Admin reads use Finder, which
// returns registries as stored, so a resolved value never reaches a
// response or the shared registry cache.
type RuntimeFinder interface {
	Finder
}

type runtimeFinder struct {
	Finder
	materializer RegistryMaterializer
}

// NewRuntimeFinder wraps inner so that FindByID resolves references. List
// returns registries as stored.
func NewRuntimeFinder(inner Finder, m RegistryMaterializer) RuntimeFinder {
	return &runtimeFinder{Finder: inner, materializer: m}
}

func (f *runtimeFinder) FindByID(ctx context.Context, gatewayID ids.GatewayID, id ids.RegistryID) (*domain.Registry, error) {
	reg, err := f.Finder.FindByID(ctx, gatewayID, id)
	if err != nil || f.materializer == nil {
		return reg, err
	}
	return f.materializer.Registries(ctx, gatewayID, map[ids.RegistryID]*domain.Registry{id: reg})[id], nil
}

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

package catalog

import (
	"context"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
)

// RegistryAvailability narrows a catalog listing to the models one registry's
// credentials can actually invoke. It owns which checks run and in what order,
// so every caller narrows a listing identically — the admin catalog endpoint
// and the data-plane diagnostics probe alike.
//
//go:generate mockery --name=RegistryAvailability --dir=. --output=./mocks --filename=catalog_registry_availability_mock.go --case=underscore --with-expecter
type RegistryAvailability interface {
	// Narrow drops the models these credentials cannot use. Like the filters it
	// composes it never fails: any doubt yields the input unchanged, since a
	// too-long list still fails at request time with the provider's own
	// message, while a spuriously empty picker is a dead end.
	Narrow(ctx context.Context, in ServerlessFilterInput) []domain.Model
}

var _ RegistryAvailability = (*registryAvailability)(nil)

type registryAvailability struct {
	serverless ServerlessFilter
	live       LiveAvailabilityFilter
}

func NewRegistryAvailability(
	serverless ServerlessFilter,
	live LiveAvailabilityFilter,
) RegistryAvailability {
	return &registryAvailability{serverless: serverless, live: live}
}

func (a *registryAvailability) Narrow(ctx context.Context, in ServerlessFilterInput) []domain.Model {
	// Availability is a property of one credential set, so there is nothing to
	// narrow against until the caller names the registry.
	if in.GatewayID.IsNil() || in.RegistryID.IsNil() {
		return in.Models
	}
	// Bedrock availability comes from the AWS control plane; every other
	// provider's from its authenticated models endpoint. Each filter no-ops on
	// the providers it does not own, so the order only decides which one
	// answers, never whether both run.
	in.Models = a.serverless.Filter(ctx, in)
	return a.live.Filter(ctx, in)
}

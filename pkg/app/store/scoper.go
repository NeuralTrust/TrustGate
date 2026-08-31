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

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// InstallLister is the read side the CatalogScoper needs: what a principal has
// installed on a gateway.
type InstallLister interface {
	ListByPrincipal(ctx context.Context, gatewayID ids.GatewayID, principalSub string) ([]*installationdomain.Installation, error)
}

// Scoper builds the per-principal surface of the MCP Store: the shared
// registries the calling principal has actively installed. It leaves any other
// (real) consumer untouched.
//
//go:generate mockery --name=Scoper --dir=. --output=./mocks --filename=store_scoper_mock.go --case=underscore --with-expecter
type Scoper interface {
	Scope(ctx context.Context, rc *appconsumer.RoutableConsumer) (*appconsumer.RoutableConsumer, error)
}

type scoper struct {
	installs   InstallLister
	registries RegistryLister
}

// NewScoper wires the CatalogScoper over the installation store and the gateway
// registry list.
func NewScoper(installs InstallLister, registries RegistryLister) (Scoper, error) {
	if installs == nil || registries == nil {
		return nil, ErrUnavailable
	}
	return &scoper{installs: installs, registries: registries}, nil
}

func (s *scoper) Scope(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
) (*appconsumer.RoutableConsumer, error) {
	if rc == nil || rc.Consumer == nil || !consumerdomain.IsStoreConsumer(rc.Consumer) {
		return rc, nil
	}
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil || principal.Subject == "" {
		return rc, nil
	}

	installs, err := s.installs.ListByPrincipal(ctx, rc.Consumer.GatewayID, principal.Subject)
	if err != nil {
		return nil, fmt.Errorf("store scoper: list installations: %w", err)
	}
	active := make(map[string]struct{}, len(installs))
	for _, in := range installs {
		if in.IsActive() {
			active[in.CatalogCode] = struct{}{}
		}
	}
	if len(active) == 0 {
		return rc, nil
	}

	regs, err := s.installedRegistries(ctx, rc.Consumer.GatewayID, active)
	if err != nil {
		return nil, err
	}

	// Copy so the shared synthetic Store consumer is never mutated across
	// concurrent principals.
	scoped := *rc
	scoped.Registries = regs
	return &scoped, nil
}

func (s *scoper) installedRegistries(
	ctx context.Context,
	gatewayID ids.GatewayID,
	activeCodes map[string]struct{},
) ([]*registrydomain.Registry, error) {
	items, _, err := s.registries.List(ctx, registrydomain.ListFilter{
		GatewayID: gatewayID,
		Page:      1,
		Size:      registryListPageSize,
	})
	if err != nil {
		return nil, fmt.Errorf("store scoper: list registries: %w", err)
	}
	out := make([]*registrydomain.Registry, 0, len(activeCodes))
	for _, reg := range items {
		if reg == nil || reg.MCPTarget == nil {
			continue
		}
		if _, ok := activeCodes[reg.MCPTarget.Code]; ok {
			out = append(out, reg)
		}
	}
	return out, nil
}

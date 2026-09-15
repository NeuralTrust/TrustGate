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

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

// GrantService is the admin surface over MCP Store access grants: list a
// gateway's grants and set (or clear) one — the Access page's write path. Every
// write signals a config-snapshot rebuild so the data planes pick the grant up.
//
//go:generate mockery --name=GrantService --dir=. --output=./mocks --filename=store_grant_service_mock.go --case=underscore --with-expecter
type GrantService interface {
	storeaccessdomain.Reader
	// Upsert writes a grant verbatim (the approver's path: add the requester).
	Upsert(ctx context.Context, g *storeaccessdomain.Grant) error
	// Set replaces the grant for (code, registry) with the given members; empty
	// members clear it. An instance grant must name a registry of this gateway
	// that carries the code (ErrUnknownInstance otherwise).
	Set(ctx context.Context, in SetGrantRequest) (*storeaccessdomain.Grant, error)
}

// SetGrantRequest is one grant to write. RegistryID nil = code-level.
type SetGrantRequest struct {
	GatewayID   ids.GatewayID
	CatalogCode string
	RegistryID  ids.RegistryID
	Groups      []string
	Users       []string
}

type grantService struct {
	repo       storeaccessdomain.Repository
	registries RegistryLister
	catalog    CatalogReader
	signaler   configsyncport.SnapshotSignaler
}

// NewGrantService wires the grant admin service. catalog validates the code
// (only catalog servers are grantable); signaler may be nil.
func NewGrantService(
	repo storeaccessdomain.Repository,
	registries RegistryLister,
	catalog CatalogReader,
	signaler configsyncport.SnapshotSignaler,
) (GrantService, error) {
	if repo == nil || registries == nil || catalog == nil {
		return nil, ErrUnavailable
	}
	return &grantService{repo: repo, registries: registries, catalog: catalog, signaler: signaler}, nil
}

func (s *grantService) ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*storeaccessdomain.Grant, error) {
	return s.repo.ListByGateway(ctx, gatewayID)
}

func (s *grantService) Set(ctx context.Context, in SetGrantRequest) (*storeaccessdomain.Grant, error) {
	grant, err := storeaccessdomain.New(in.GatewayID, in.CatalogCode, in.RegistryID, in.Groups, in.Users)
	if err != nil {
		return nil, err
	}
	if _, ok := s.catalog.GetByCode(grant.CatalogCode); !ok {
		return nil, fmt.Errorf("%w: %q", ErrCatalogEntryNotFound, grant.CatalogCode)
	}
	if grant.IsInstance() {
		instances, err := findRegistriesByCode(ctx, s.registries, in.GatewayID, grant.CatalogCode)
		if err != nil {
			return nil, err
		}
		if pickRegistry(instances, grant.RegistryID) == nil {
			return nil, fmt.Errorf("%w: %s is not an instance of %q", ErrUnknownInstance, grant.RegistryID, grant.CatalogCode)
		}
	}
	if err := s.repo.Upsert(ctx, grant); err != nil {
		return nil, err
	}
	s.signal(ctx)
	return grant, nil
}

// Upsert lets the service stand in as the approver's GrantStore, so an approval
// also signals the snapshot.
func (s *grantService) Upsert(ctx context.Context, g *storeaccessdomain.Grant) error {
	if err := s.repo.Upsert(ctx, g); err != nil {
		return err
	}
	s.signal(ctx)
	return nil
}

func (s *grantService) signal(ctx context.Context) {
	if s.signaler != nil {
		s.signaler.Signal(ctx)
	}
}

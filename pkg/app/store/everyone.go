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

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

// EveryoneService is the admin surface over a gateway's Everyone object: read
// it and replace (or remove) it. Every write signals a snapshot rebuild so the
// data planes pick it up.
//
//go:generate mockery --name=EveryoneService --dir=. --output=./mocks --filename=store_everyone_service_mock.go --case=underscore --with-expecter
type EveryoneService interface {
	storeaccessdomain.EveryoneReader
	// Set replaces the gateway's object; an empty Mode removes it.
	Set(ctx context.Context, in SetEveryoneRequest) (*storeaccessdomain.Everyone, error)
}

// SetEveryoneRequest is the whole object to write. Mode "" means "remove".
type SetEveryoneRequest struct {
	GatewayID      ids.GatewayID
	Mode           string
	Grants         []storeaccessdomain.EveryoneGrant
	ExcludedGroups []string
}

type everyoneService struct {
	repo       storeaccessdomain.EveryoneRepository
	registries RegistryLister
	catalog    CatalogReader
	signaler   configsyncport.SnapshotSignaler
}

// NewEveryoneService wires the Everyone admin service. catalog and registries
// validate each grant like a Store grant; signaler may be nil.
func NewEveryoneService(
	repo storeaccessdomain.EveryoneRepository,
	registries RegistryLister,
	catalog CatalogReader,
	signaler configsyncport.SnapshotSignaler,
) (EveryoneService, error) {
	if repo == nil || registries == nil || catalog == nil {
		return nil, ErrUnavailable
	}
	return &everyoneService{repo: repo, registries: registries, catalog: catalog, signaler: signaler}, nil
}

func (s *everyoneService) GetEveryone(ctx context.Context, gatewayID ids.GatewayID) (*storeaccessdomain.Everyone, error) {
	return s.repo.GetEveryone(ctx, gatewayID)
}

func (s *everyoneService) Set(ctx context.Context, in SetEveryoneRequest) (*storeaccessdomain.Everyone, error) {
	if strings.TrimSpace(in.Mode) == "" {
		if in.GatewayID.IsNil() {
			return nil, fmt.Errorf("store: gateway is required: %w", commonerrors.ErrValidation)
		}
		if err := s.repo.DeleteEveryone(ctx, in.GatewayID); err != nil {
			return nil, err
		}
		s.signal(ctx)
		return nil, nil
	}
	everyone, err := storeaccessdomain.NewEveryone(in.GatewayID, in.Mode, in.Grants, in.ExcludedGroups)
	if err != nil {
		return nil, err
	}
	for _, g := range everyone.Grants {
		if err := s.validateGrant(ctx, in.GatewayID, g); err != nil {
			return nil, err
		}
	}
	if err := s.repo.UpsertEveryone(ctx, everyone); err != nil {
		return nil, err
	}
	s.signal(ctx)
	return everyone, nil
}

func (s *everyoneService) validateGrant(ctx context.Context, gatewayID ids.GatewayID, g storeaccessdomain.EveryoneGrant) error {
	_, ok, err := storeEntry(ctx, s.catalog, s.registries, gatewayID, g.CatalogCode)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: unknown server %q", storeaccessdomain.ErrInvalidEveryone, g.CatalogCode)
	}
	if !g.IsInstance() {
		return nil
	}
	instances, err := findRegistriesByCode(ctx, s.registries, gatewayID, g.CatalogCode)
	if err != nil {
		return err
	}
	if pickRegistry(instances, g.RegistryID) == nil {
		return fmt.Errorf("%w: %s is not an instance of %q", ErrUnknownInstance, g.RegistryID, g.CatalogCode)
	}
	return nil
}

func (s *everyoneService) signal(ctx context.Context) {
	if s.signaler != nil {
		s.signaler.Signal(ctx)
	}
}

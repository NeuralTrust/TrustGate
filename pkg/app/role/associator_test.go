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

package role_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	approle "github.com/NeuralTrust/TrustGate/pkg/app/role"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrymocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/cachetest"
)

type associatorRoleRepositoryStub struct {
	role      *domain.Role
	detachErr error
}

func (s associatorRoleRepositoryStub) Save(context.Context, *domain.Role) error   { return nil }
func (s associatorRoleRepositoryStub) Update(context.Context, *domain.Role) error { return nil }
func (s associatorRoleRepositoryStub) Delete(context.Context, ids.GatewayID, ids.RoleID) error {
	return nil
}
func (s associatorRoleRepositoryStub) FindByID(context.Context, ids.RoleID) (*domain.Role, error) {
	if s.role == nil {
		return nil, domain.ErrNotFound
	}
	return s.role, nil
}
func (s associatorRoleRepositoryStub) FindByIDs(context.Context, ids.GatewayID, []ids.RoleID) ([]*domain.Role, error) {
	return nil, nil
}
func (s associatorRoleRepositoryStub) List(context.Context, domain.ListFilter) ([]*domain.Role, int, error) {
	return nil, 0, nil
}
func (s associatorRoleRepositoryStub) ListByGateway(context.Context, ids.GatewayID) ([]*domain.Role, error) {
	return nil, nil
}
func (s associatorRoleRepositoryStub) AttachRegistry(context.Context, ids.RoleID, ids.RegistryID) error {
	return nil
}
func (s associatorRoleRepositoryStub) DetachRegistry(context.Context, ids.RoleID, ids.RegistryID) error {
	return nil
}
func (s associatorRoleRepositoryStub) DetachRegistryIfUnreferenced(context.Context, ids.GatewayID, ids.RoleID, ids.RegistryID) (*domain.Role, error) {
	return s.role, s.detachErr
}

func TestAssociator_DetachRegistry_RejectsModelPolicyReference(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	roleID := ids.New[ids.RoleKind]()
	registryID := ids.New[ids.RegistryKind]()

	role := &domain.Role{
		ID:            roleID,
		GatewayID:     gwID,
		ModelPolicies: domain.ModelPolicies{registryID: {Allowed: []string{"gpt-4o"}}},
	}
	associator := approle.NewAssociator(
		associatorRoleRepositoryStub{role: role, detachErr: commonerrors.ErrConflict},
		registrymocks.NewRepository(t),
		cache.NewTTLMapManager(cache.RoleCacheTTL),
		cachetest.NoopPublisher(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)

	err := associator.DetachRegistry(context.Background(), gwID, roleID, registryID)
	if !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

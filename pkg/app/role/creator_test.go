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
	"io"
	"log/slog"
	"testing"

	approle "github.com/NeuralTrust/AgentGateway/pkg/app/role"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
)

type repositoryStub struct{}

func (repositoryStub) Save(context.Context, *domain.Role) error   { return nil }
func (repositoryStub) Update(context.Context, *domain.Role) error { return nil }
func (repositoryStub) Delete(context.Context, ids.RoleID) error   { return nil }
func (repositoryStub) FindByID(context.Context, ids.RoleID) (*domain.Role, error) {
	return nil, domain.ErrNotFound
}
func (repositoryStub) FindByIDs(context.Context, ids.GatewayID, []ids.RoleID) ([]*domain.Role, error) {
	return nil, nil
}
func (repositoryStub) List(context.Context, domain.ListFilter) ([]*domain.Role, int, error) {
	return nil, 0, nil
}
func (repositoryStub) ListByGateway(context.Context, ids.GatewayID) ([]*domain.Role, error) {
	return nil, nil
}
func (repositoryStub) AttachRegistry(context.Context, ids.RoleID, ids.RegistryID) error { return nil }
func (repositoryStub) DetachRegistry(context.Context, ids.RoleID, ids.RegistryID) error { return nil }
func (repositoryStub) DetachRegistryIfUnreferenced(context.Context, ids.GatewayID, ids.RoleID, ids.RegistryID) (*domain.Role, error) {
	return nil, nil
}

func TestCreator_Create_SavesRoleWithoutInitialModelPolicies(t *testing.T) {
	t.Parallel()
	creator := approle.NewCreator(
		repositoryStub{},
		cache.NewTTLMapManager(cache.RoleCacheTTL),
		cachetest.NoopPublisher(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	role, err := creator.Create(context.Background(), approle.CreateInput{
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      "analyst",
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if len(role.ModelPolicies) != 0 {
		t.Fatalf("ModelPolicies = %v, want empty on create", role.ModelPolicies)
	}
}

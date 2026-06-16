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

package role

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

type ListFilter struct {
	GatewayID    ids.GatewayID
	NameContains string
	Page         int
	Size         int
}

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=role_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, r *Role) error
	Update(ctx context.Context, r *Role) error
	Delete(ctx context.Context, id ids.RoleID) error
	FindByID(ctx context.Context, id ids.RoleID) (*Role, error)
	FindByIDs(ctx context.Context, gatewayID ids.GatewayID, roleIDs []ids.RoleID) ([]*Role, error)
	List(ctx context.Context, filter ListFilter) (items []*Role, total int, err error)
	ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*Role, error)
	AttachRegistry(ctx context.Context, roleID ids.RoleID, registryID ids.RegistryID) error
	DetachRegistry(ctx context.Context, roleID ids.RoleID, registryID ids.RegistryID) error
	DetachRegistryIfUnreferenced(ctx context.Context, gatewayID ids.GatewayID, roleID ids.RoleID, registryID ids.RegistryID) (*Role, error)
}

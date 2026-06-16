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

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

type ListFilter struct {
	GatewayID    ids.GatewayID
	NameContains string
	Page         int
	Size         int
}

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=registry_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, b *Registry) error
	Update(ctx context.Context, b *Registry) error
	Delete(ctx context.Context, id ids.RegistryID) error
	FindByID(ctx context.Context, id ids.RegistryID) (*Registry, error)
	FindByIDs(ctx context.Context, gatewayID ids.GatewayID, registryIDs []ids.RegistryID) ([]*Registry, error)
	List(ctx context.Context, filter ListFilter) (items []*Registry, total int, err error)
}

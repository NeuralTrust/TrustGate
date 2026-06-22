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

package consumer

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type ListFilter struct {
	GatewayID    ids.GatewayID
	NameContains string
	Page         int
	Size         int
}

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=consumer_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, c *Consumer) error
	Update(ctx context.Context, c *Consumer) error
	Delete(ctx context.Context, gatewayID ids.GatewayID, id ids.ConsumerID) error
	FindByID(ctx context.Context, id ids.ConsumerID) (*Consumer, error)
	List(ctx context.Context, filter ListFilter) (items []*Consumer, total int, err error)

	ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*Consumer, error)
	ListByAuthID(ctx context.Context, authID ids.AuthID) ([]*Consumer, error)

	FindActiveBySlug(ctx context.Context, slug string) (*Consumer, error)

	AttachRegistry(ctx context.Context, consumerID ids.ConsumerID, registryID ids.RegistryID, weight *int) error
	DetachRegistry(ctx context.Context, consumerID ids.ConsumerID, registryID ids.RegistryID) error
	DetachRegistryIfUnreferenced(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, registryID ids.RegistryID) (*Consumer, error)
	AttachRole(ctx context.Context, consumerID ids.ConsumerID, roleID ids.RoleID) error
	DetachRole(ctx context.Context, consumerID ids.ConsumerID, roleID ids.RoleID) error
	AttachAuth(ctx context.Context, consumerID ids.ConsumerID, authID ids.AuthID) error
	DetachAuth(ctx context.Context, consumerID ids.ConsumerID, authID ids.AuthID) error
	AttachPolicy(ctx context.Context, consumerID ids.ConsumerID, policyID ids.PolicyID) error
	DetachPolicy(ctx context.Context, consumerID ids.ConsumerID, policyID ids.PolicyID) error
}

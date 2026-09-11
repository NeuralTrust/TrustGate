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
	"github.com/NeuralTrust/TrustGate/pkg/domain/listing"
)

// SortableFields are the whitelist of query fields accepted by list sort.
var SortableFields = []string{"name", "created_at", "updated_at", "type"}

type ListFilter struct {
	GatewayID ids.GatewayID
	Search    string
	Type      Type
	Active    *bool
	AuthID    ids.AuthID
	Page      listing.Page
	Sort      listing.Sort
}

// Reader exposes the read-only queries over the consumer store.
type Reader interface {
	FindByID(ctx context.Context, id ids.ConsumerID) (*Consumer, error)
	FindActiveBySlug(ctx context.Context, slug string) (*Consumer, error)
	List(ctx context.Context, filter ListFilter) (items []*Consumer, total int, err error)
	ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*Consumer, error)
	ListByAuthID(ctx context.Context, authID ids.AuthID) ([]*Consumer, error)
}

// Writer persists consumer aggregate lifecycle changes.
type Writer interface {
	Save(ctx context.Context, c *Consumer) error
	// Update persists the consumer row and, when registries or auths is
	// non-nil, replaces that association set in the same transaction. A nil
	// argument leaves the existing links of that kind untouched.
	Update(ctx context.Context, c *Consumer, registries *RegistryBindings, auths *[]ids.AuthID) error
	Delete(ctx context.Context, gatewayID ids.GatewayID, id ids.ConsumerID) error
}

// Associator manages the links between a consumer and its related aggregates.
type Associator interface {
	AttachRegistry(ctx context.Context, consumerID ids.ConsumerID, registryID ids.RegistryID, weight *int) error
	DetachRegistry(ctx context.Context, consumerID ids.ConsumerID, registryID ids.RegistryID) error
	DetachRegistryIfUnreferenced(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, registryID ids.RegistryID) (*Consumer, error)
	AttachAuth(ctx context.Context, consumerID ids.ConsumerID, authID ids.AuthID) error
	DetachAuth(ctx context.Context, consumerID ids.ConsumerID, authID ids.AuthID) error
	AttachPolicy(ctx context.Context, consumerID ids.ConsumerID, policyID ids.PolicyID) error
	DetachPolicy(ctx context.Context, consumerID ids.ConsumerID, policyID ids.PolicyID) error
}

//go:generate go run github.com/vektra/mockery/v2@v2.53.5 --name=Repository --dir=. --output=./mocks --filename=consumer_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Reader
	Writer
	Associator
}

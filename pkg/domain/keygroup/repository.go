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

package keygroup

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// Reader is the read side every plane has: the group budgets of one gateway.
// On the control plane it is the Postgres repository; on a data plane with no
// database it reads the config snapshot.
type Reader interface {
	ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*Budget, error)
}

// Repository is the control-plane store, keyed by (gateway, group).
//
//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=key_group_budget_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Reader
	// List pages every budget across gateways (the snapshot compiler's bulk
	// read).
	List(ctx context.Context, page, size int) ([]*Budget, int, error)
	// Upsert creates or replaces the budget of (gateway, group) and returns
	// the stored budget; a replaced budget keeps its creation time.
	Upsert(ctx context.Context, b *Budget) (*Budget, error)
	// Delete removes the budget of (gateway, group), or answers ErrNotFound.
	Delete(ctx context.Context, gatewayID ids.GatewayID, groupID string) error
}

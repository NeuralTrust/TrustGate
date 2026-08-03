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

package gateway

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// StatePurger reclaims the shared-cache state a gateway owns. Implementations
// are only ever invoked for a gateway that has already been deleted, never on
// an update or cache-invalidation path.
//
//go:generate mockery --name=StatePurger --dir=. --output=./mocks --filename=gateway_state_purger_mock.go --case=underscore --with-expecter
type StatePurger interface {
	PurgeGatewayState(ctx context.Context, gatewayID ids.GatewayID) error
}

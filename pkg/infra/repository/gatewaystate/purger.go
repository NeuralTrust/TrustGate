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

// Package gatewaystate reclaims the Redis state left behind by deleted gateways.
package gatewaystate

import (
	"context"
	"fmt"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/redis/go-redis/v9"
)

const scanBatch = 200

var _ appgateway.StatePurger = (*Purger)(nil)

// Purger deletes every Redis key carrying a gateway's id.
//
// A deleted gateway leaves state across keyspaces owned by different components
// — the credential vault, dynamic client registrations, sessions, rate-limit
// counters and load-balancer status — and most of it is written by the data
// planes, which the control plane cannot reach through any single repository.
// Two of those keyspaces (vault credentials and dynamic client registrations)
// are stored without a TTL, so nothing else would ever reclaim them.
//
// Matching on the id alone is sound only because the gateway is already gone.
// This must never run on an update or cache-invalidation path: there the same
// match reaps the live credentials of a working gateway, which is exactly the
// incident this type exists to avoid repeating.
type Purger struct {
	rdb *redis.Client
}

func NewPurger(rdb *redis.Client) *Purger {
	return &Purger{rdb: rdb}
}

// PurgeGatewayState removes every key whose name contains gatewayID.
func (p *Purger) PurgeGatewayState(ctx context.Context, gatewayID ids.GatewayID) error {
	if p.rdb == nil {
		return nil
	}

	pattern := "*" + gatewayID.String() + "*"
	var cursor uint64
	for {
		keys, next, err := p.rdb.Scan(ctx, cursor, pattern, scanBatch).Result()
		if err != nil {
			return fmt.Errorf("gatewaystate: scan %q: %w", pattern, err)
		}
		if len(keys) > 0 {
			if err := p.rdb.Del(ctx, keys...).Err(); err != nil {
				return fmt.Errorf("gatewaystate: delete %d keys: %w", len(keys), err)
			}
		}
		cursor = next
		if cursor == 0 {
			return nil
		}
	}
}

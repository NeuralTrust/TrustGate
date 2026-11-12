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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/dataplane"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// InstanceLister reads the data-plane instances recorded for one config-sync
// scope, which for a gateway with its own data plane is the gateway id.
type InstanceLister interface {
	ListInstances(ctx context.Context, scope string) ([]dataplane.Instance, error)
}

// LLMAvailabilityService says whether a gateway's data planes serve the LLM
// Store, so the console offers personal keys only where they work.
type LLMAvailabilityService interface {
	LLMAvailability(ctx context.Context, gatewayID ids.GatewayID) (dataplane.StoreAvailability, error)
}

type llmAvailability struct {
	gateways  GatewayFinder
	instances InstanceLister
	now       func() time.Time
}

// NewLLMAvailabilityService builds the service. now defaults to time.Now.
func NewLLMAvailabilityService(gateways GatewayFinder, instances InstanceLister, now func() time.Time) LLMAvailabilityService {
	if now == nil {
		now = time.Now
	}
	return &llmAvailability{gateways: gateways, instances: instances, now: now}
}

func (s *llmAvailability) LLMAvailability(ctx context.Context, gatewayID ids.GatewayID) (dataplane.StoreAvailability, error) {
	gw, err := s.gateways.FindByID(ctx, gatewayID)
	if err != nil {
		return dataplane.StoreAvailability{}, fmt.Errorf("store: load gateway: %w", err)
	}
	if !gw.ServedByHybridDataPlane() {
		return dataplane.HostedStoreAvailability(), nil
	}
	instances, err := s.instances.ListInstances(ctx, gatewayID.String())
	if err != nil {
		return dataplane.StoreAvailability{}, fmt.Errorf("store: list data-plane instances: %w", err)
	}
	return dataplane.ResolveStoreAvailability(instances, s.now()), nil
}

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

package strategies

import (
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer/algorithm"
)

type RoundRobin struct {
	mu         sync.Mutex
	registries []*registry.Registry
	current    int
}

func NewRoundRobin(registries []*registry.Registry) *RoundRobin {
	return &RoundRobin{registries: registries}
}

func (rr *RoundRobin) Next(req *infracontext.RequestContext, exclude map[ids.RegistryID]struct{}) *registry.Registry {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	n := len(rr.registries)
	if n == 0 {
		return nil
	}
	for i := 0; i < n; i++ {
		b := rr.registries[rr.current]
		rr.current = (rr.current + 1) % n
		if !isExcluded(b.ID, exclude) {
			return b
		}
	}
	return nil
}

func (rr *RoundRobin) Name() string {
	return algorithm.RoundRobin
}

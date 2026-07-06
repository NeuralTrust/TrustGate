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
	"context"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

type LeastConnections struct {
	mu         sync.Mutex
	registries []*registry.Registry
}

func NewLeastConnections(registries []*registry.Registry) *LeastConnections {
	return &LeastConnections{registries: registries}
}

func (lc *LeastConnections) Next(_ context.Context, _ *infracontext.RequestContext, exclude map[ids.RegistryID]struct{}) *registry.Registry {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	n := len(lc.registries)
	if n == 0 {
		return nil
	}
	for i := 0; i < n; i++ {
		selected := lc.registries[0]
		lc.registries = append(lc.registries[1:], lc.registries[0])
		if !isExcluded(selected.ID, exclude) {
			return selected
		}
	}
	return nil
}

func (lc *LeastConnections) Name() string {
	return algorithm.LeastConnections
}

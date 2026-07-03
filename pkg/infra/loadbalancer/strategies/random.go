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
	"crypto/rand"
	"math/big"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

type Random struct {
	mu         sync.Mutex
	registries []*registry.Registry
}

func NewRandom(registries []*registry.Registry) *Random {
	return &Random{registries: registries}
}

func (r *Random) Next(_ context.Context, _ *infracontext.RequestContext, exclude map[ids.RegistryID]struct{}) *registry.Registry {
	r.mu.Lock()
	defer r.mu.Unlock()
	candidates := filterExcluded(r.registries, exclude)
	if len(candidates) == 0 {
		return nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(candidates))))
	if err != nil {
		return candidates[0]
	}
	return candidates[n.Int64()]
}

func (r *Random) Name() string {
	return algorithm.Random
}

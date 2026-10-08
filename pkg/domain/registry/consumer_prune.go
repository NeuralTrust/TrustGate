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

import "github.com/NeuralTrust/TrustGate/pkg/domain/ids"

// Names of the consumer routing structures a registry delete can prune.
const (
	PrunedModelPolicies = "model_policies"
	PrunedLBConfig      = "lb_config"
	PrunedSmartRouting  = "smart_routing"
	PrunedFallback      = "fallback"
)

// ConsumerPrune records what one consumer lost to a registry delete: the
// structures rewritten in place, and the ones that could not survive losing the
// reference and were nulled whole.
type ConsumerPrune struct {
	ConsumerID ids.ConsumerID
	Rewritten  []string
	Nulled     []string
}

// Changed reports whether the prune touched the consumer at all.
func (p ConsumerPrune) Changed() bool {
	return len(p.Rewritten) > 0 || len(p.Nulled) > 0
}

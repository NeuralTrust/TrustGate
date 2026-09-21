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
	PrunedToolkit       = "toolkit"
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

// PolicyPrune records one policy whose mcp_scope lost the deleted registry.
// Emptied reports that no destination survived and the scope was left as {},
// so the policy matches nothing until an operator gives it a new destination.
type PolicyPrune struct {
	PolicyID ids.PolicyID
	Emptied  bool
}

// PruneReport lists every consumer and policy a registry delete had to
// rewrite. The delete answers 204 and no foreign key can cascade the JSONB
// references, so this report is the only account of what the gateway lost.
type PruneReport struct {
	Consumers []ConsumerPrune
	Policies  []PolicyPrune
}

// Empty reports whether the delete left every consumer and policy untouched.
func (r PruneReport) Empty() bool {
	return len(r.Consumers) == 0 && len(r.Policies) == 0
}

// Merge appends the consumers and policies another report recorded.
func (r *PruneReport) Merge(other PruneReport) {
	r.Consumers = append(r.Consumers, other.Consumers...)
	r.Policies = append(r.Policies, other.Policies...)
}

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
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
)

// PruneRegistry removes every routing reference to registryID from the consumer
// and reports what it had to change, plus whether anything changed at all.
// Structures that cannot survive losing the reference are dropped whole rather
// than left empty: a pool with no members, a smart-routing ladder that lost its
// cheapest tier and a fallback with no chain are all set to nil, so a pruned
// consumer still satisfies Validate.
func (c *Consumer) PruneRegistry(registryID ids.RegistryID) (registry.ConsumerPrune, bool) {
	if c == nil || registryID.IsNil() {
		return registry.ConsumerPrune{}, false
	}
	prune := registry.ConsumerPrune{ConsumerID: c.ID}
	c.pruneModelPolicies(registryID, &prune)
	c.pruneLBConfig(registryID, &prune)
	c.pruneFallback(registryID, &prune)
	c.pruneToolkit(registryID, &prune)
	return prune, prune.Changed()
}

func (c *Consumer) pruneModelPolicies(registryID ids.RegistryID, prune *registry.ConsumerPrune) {
	if _, ok := c.ModelPolicies[registryID]; !ok {
		return
	}
	delete(c.ModelPolicies, registryID)
	if len(c.ModelPolicies) == 0 {
		c.ModelPolicies = nil
		prune.Nulled = append(prune.Nulled, registry.PrunedModelPolicies)
		return
	}
	prune.Rewritten = append(prune.Rewritten, registry.PrunedModelPolicies)
}

func (c *Consumer) pruneLBConfig(registryID ids.RegistryID, prune *registry.ConsumerPrune) {
	if c.LBConfig == nil {
		return
	}
	members := make([]LBPoolMember, 0, len(c.LBConfig.Members))
	for _, member := range c.LBConfig.Members {
		if member.RegistryID != registryID {
			members = append(members, member)
		}
	}
	tiers, tiersChanged, ladderSurvives := c.prunedTiers(registryID)
	if len(members) == len(c.LBConfig.Members) && !tiersChanged {
		return
	}
	if len(members) == 0 {
		c.LBConfig = nil
		prune.Nulled = append(prune.Nulled, registry.PrunedLBConfig)
		return
	}
	c.LBConfig.Members = members
	prune.Rewritten = append(prune.Rewritten, registry.PrunedLBConfig)
	if !tiersChanged {
		return
	}
	if !ladderSurvives {
		c.LBConfig.SmartRouting = nil
		if c.LBConfig.Algorithm == algorithm.SmartRouting {
			c.LBConfig.Algorithm = algorithm.RoundRobin
		}
		prune.Nulled = append(prune.Nulled, registry.PrunedSmartRouting)
		return
	}
	c.LBConfig.SmartRouting.Tiers = tiers
}

// RUN-1501: a ladder that loses a middle or top tier is safe to keep - the band
// it served falls to the tier below it, which is cheaper. Losing the *cheapest*
// tier instead raises the ladder's floor, and every score under the new floor
// gets re-targeted upward by SmartRouting.LowestTier, silently promoting the
// cheapest traffic in the pool to the priciest survivor. The gateway cannot
// invent a cheap route in place of the deleted one, so the ladder does not
// survive that: the caller drops it whole and the pool degrades to its plain
// algorithm, which treats every band alike instead of promoting one.
func (c *Consumer) prunedTiers(
	registryID ids.RegistryID,
) (tiers []registry.SmartRoutingTier, changed, ladderSurvives bool) {
	if c.LBConfig.SmartRouting == nil {
		return nil, false, false
	}
	original := c.LBConfig.SmartRouting.Tiers
	tiers = make([]registry.SmartRoutingTier, 0, len(original))
	for _, tier := range original {
		if tier.RegistryID != registryID {
			tiers = append(tiers, tier)
		}
	}
	if len(tiers) == len(original) {
		return original, false, true
	}
	oldFloor, hadFloor := (&registry.SmartRoutingConfig{Tiers: original}).LowestTier()
	newFloor, hasFloor := (&registry.SmartRoutingConfig{Tiers: tiers}).LowestTier()
	return tiers, true, hasFloor && (!hadFloor || newFloor.MinScore == oldFloor.MinScore)
}

func (c *Consumer) pruneFallback(registryID ids.RegistryID, prune *registry.ConsumerPrune) {
	if c.Fallback == nil {
		return
	}
	chain := make(registry.Registries, 0, len(c.Fallback.Chain))
	for _, id := range c.Fallback.Chain {
		if id != registryID {
			chain = append(chain, id)
		}
	}
	if len(chain) == len(c.Fallback.Chain) {
		return
	}
	if len(chain) == 0 {
		c.Fallback = nil
		prune.Nulled = append(prune.Nulled, registry.PrunedFallback)
		return
	}
	c.Fallback.Chain = chain
	prune.Rewritten = append(prune.Rewritten, registry.PrunedFallback)
}

func (c *Consumer) pruneToolkit(registryID ids.RegistryID, prune *registry.ConsumerPrune) {
	if c.MCP == nil || len(c.MCP.Toolkit) == 0 {
		return
	}
	toolkit := make(Toolkit, 0, len(c.MCP.Toolkit))
	for _, entry := range c.MCP.Toolkit {
		if entry.RegistryID != registryID {
			toolkit = append(toolkit, entry)
		}
	}
	if len(toolkit) == len(c.MCP.Toolkit) {
		return
	}
	if len(toolkit) == 0 {
		c.MCP.Toolkit = nil
		prune.Nulled = append(prune.Nulled, registry.PrunedToolkit)
		return
	}
	c.MCP.Toolkit = toolkit
	prune.Rewritten = append(prune.Rewritten, registry.PrunedToolkit)
}

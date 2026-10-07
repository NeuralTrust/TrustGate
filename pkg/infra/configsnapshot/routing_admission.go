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

package configsnapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	admissionEncode = "encode"
	admissionDecode = "decode"
)

// admitConsumers withdraws the smart-routing ladder of every consumer that
// fails validate, so that consumer's pool fails closed on its own instead of
// one inadmissible row withholding the snapshot from every other tenant. The
// input slice is never modified: on encode it belongs to the served snapshot.
func admitConsumers(consumers []consumerdomain.Consumer, stage string, validate func(int) error) []consumerdomain.Consumer {
	admitted := consumers
	cloned := false
	for i := range consumers {
		err := validate(i)
		if err == nil {
			continue
		}
		if !cloned {
			admitted = slices.Clone(consumers)
			cloned = true
		}
		lb := *admitted[i].LBConfig
		// Keep a malformed smart envelope on the smart strategy path: dropping
		// its ladder must never turn it into a runnable legacy pool.
		lb.Algorithm = algorithm.SmartRouting
		lb.SmartRouting = nil
		admitted[i].LBConfig = &lb
		slog.Error("config snapshot quarantined consumer smart routing",
			slog.String("component", "configsnapshot"),
			slog.String("stage", stage),
			slog.String("gateway_id", admitted[i].GatewayID.String()),
			slog.String("consumer_id", admitted[i].ID.String()),
			slog.String("error", err.Error()))
		recordRoutingQuarantine(stage)
	}
	return admitted
}

// recordRoutingQuarantine counts quarantined consumers by codec stage only:
// consumer and tenant identifiers stay in the log, never in metric labels.
func recordRoutingQuarantine(stage string) {
	counter, err := otel.Meter("trustgate/configsnapshot").Int64Counter(
		"trustgate.configsnapshot.routing.quarantined",
		metric.WithDescription("consumers whose smart routing was withheld from a config snapshot because it failed admission"),
	)
	if err != nil {
		slog.Warn("failed to create routing quarantine counter", slog.String("error", err.Error()))
		return
	}
	// The snapshot codec interface carries no context.
	counter.Add(context.Background(), 1, metric.WithAttributes(attribute.String("stage", stage)))
}

// Smart settings are migration output, including when the pool or consumer is
// disabled. An old producer must not silently turn an omitted historical flag
// into false, or publish a legacy pool that could become active later.
func validateConsumerSmartRoutingJSON(raw []byte, c *consumerdomain.Consumer, owners map[ids.RegistryID]ids.GatewayID) error {
	if !hasSmartRouting(c) {
		return nil
	}
	var wire struct {
		LBConfig struct {
			SmartRouting struct {
				SR1 struct {
					TTL    *int  `json:"cache_ttl_seconds"`
					Escape *bool `json:"escape_hatch_enabled"`
				} `json:"sr1"`
			} `json:"smart_routing"`
		} `json:"lb_config"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return fmt.Errorf("decode session settings: %w", err)
	}
	settings := wire.LBConfig.SmartRouting.SR1
	if settings.TTL == nil || settings.Escape == nil {
		return fmt.Errorf("smart routing snapshot requires explicit cache_ttl_seconds and boolean escape_hatch_enabled")
	}
	return validateConsumerSmartRouting(c, owners)
}

func hasSmartRouting(c *consumerdomain.Consumer) bool {
	return c.LBConfig != nil && (c.LBConfig.Algorithm == algorithm.SmartRouting || c.LBConfig.SmartRouting != nil)
}

func registryOwners(registries []registrydomain.Registry) map[ids.RegistryID]ids.GatewayID {
	owners := make(map[ids.RegistryID]ids.GatewayID, len(registries))
	for _, r := range registries {
		owners[r.ID] = r.GatewayID
	}
	return owners
}

func validateConsumerSmartRouting(c *consumerdomain.Consumer, owners map[ids.RegistryID]ids.GatewayID) error {
	if !hasSmartRouting(c) {
		return nil
	}
	if c.LBConfig.Algorithm != algorithm.SmartRouting {
		return fmt.Errorf("smart_routing requires the smart-routing algorithm")
	}
	// Validate a copy as enabled: inactive consumers and disabled pools are part
	// of the migration preflight, and must pass the same admission fence.
	lb := *c.LBConfig
	lb.Enabled = true
	known := make(map[ids.RegistryID]struct{}, len(c.RegistryIDs))
	for _, id := range c.RegistryIDs {
		if owner, ok := owners[id]; ok && owner == c.GatewayID {
			known[id] = struct{}{}
		}
	}
	if c.Fallback != nil {
		for _, id := range c.Fallback.Chain {
			if owner, ok := owners[id]; ok && owner == c.GatewayID {
				known[id] = struct{}{}
			}
		}
	}
	if err := c.ModelPolicies.Validate(known); err != nil {
		return err
	}
	if err := lb.ValidateTierRegistries(known); err != nil {
		return err
	}
	return lb.Validate(c.ModelPolicies)
}

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

package proxy

import (
	"context"
	"fmt"
	"strings"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/modelmatch"
)

type exclusionReason int

const (
	exclusionUnexplained exclusionReason = iota
	exclusionAllowList
	exclusionCatalogAbsent
)

func (r exclusionReason) String() string {
	switch r {
	case exclusionAllowList:
		return "restricted by its model allow-list"
	case exclusionCatalogAbsent:
		return "not in the provider catalog"
	default:
		return "not eligible for this request"
	}
}

type registryExclusion struct {
	label  string
	reason exclusionReason
}

func (f *forwarder) modelExclusions(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	model string,
) []registryExclusion {
	if rc == nil || rc.Consumer == nil {
		return nil
	}
	seen := make(map[ids.RegistryID]struct{}, len(rc.Registries)+len(rc.FallbackBackends))
	out := make([]registryExclusion, 0, len(rc.Registries)+len(rc.FallbackBackends))
	for _, registries := range [2][]*domain.Registry{rc.Registries, rc.FallbackBackends} {
		for _, reg := range registries {
			if reg == nil {
				continue
			}
			if _, dup := seen[reg.ID]; dup {
				continue
			}
			seen[reg.ID] = struct{}{}
			label := registryLabel(reg)
			if label == "" {
				continue
			}
			out = append(out, registryExclusion{label: label, reason: f.exclusionReasonFor(ctx, rc, reg, model)})
		}
	}
	return out
}

func (f *forwarder) exclusionReasonFor(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	reg *domain.Registry,
	model string,
) exclusionReason {
	policy, _ := rc.Consumer.ModelPolicies.For(reg.ID)
	candidate := routingdomain.Candidate{Allowed: policy.Allowed}
	if !candidate.DefersModelChoice() {
		if !modelmatch.IsPattern(model) && !candidate.PolicyAllowsModel(model) {
			return exclusionAllowList
		}
		return exclusionUnexplained
	}
	if f.listing != nil && f.listing.Lists(ctx, reg.Provider(), model) == appcatalog.VerdictAbsent {
		return exclusionCatalogAbsent
	}
	return exclusionUnexplained
}

func registryLabel(reg *domain.Registry) string {
	if name := strings.TrimSpace(reg.Name); name != "" {
		return name
	}
	return reg.Provider()
}

func renderExclusions(exclusions []registryExclusion) string {
	labelsOnly := true
	for _, e := range exclusions {
		if e.reason != exclusionUnexplained {
			labelsOnly = false
			break
		}
	}
	parts := make([]string, 0, len(exclusions))
	for _, e := range exclusions {
		if labelsOnly {
			parts = append(parts, e.label)
			continue
		}
		parts = append(parts, e.label+": "+e.reason.String())
	}
	if labelsOnly {
		return strings.Join(parts, ", ")
	}
	return strings.Join(parts, "; ")
}

func (f *forwarder) noRegistryServesModelError(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	model string,
) error {
	exclusions := f.modelExclusions(ctx, rc, model)
	if len(exclusions) == 0 {
		return fmt.Errorf("%w: %q", routingdomain.ErrNoRegistryServesModel, model)
	}
	return fmt.Errorf("%w: %q (%s)",
		routingdomain.ErrNoRegistryServesModel, model, renderExclusions(exclusions))
}

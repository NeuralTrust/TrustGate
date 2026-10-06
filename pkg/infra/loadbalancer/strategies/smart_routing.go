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
	"log/slog"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

// ComplexityScorer returns raw difficulty from the immutable routing artifact.
type ComplexityScorer interface {
	ScoreSR1(ctx context.Context, input, tenantID string) (float64, error)
	Configured() bool
}

// SmartRouting implements the frozen cold-point policy with an optional escape.
type SmartRouting struct {
	routes   []routingdomain.Route
	config   *registry.SmartRoutingConfig
	scorer   ComplexityScorer
	logger   *slog.Logger
	warnOnce sync.Once
	sr1State SR1Store
}

func NewSmartRouting(
	routes []routingdomain.Route,
	config *registry.SmartRoutingConfig,
	scorer ComplexityScorer,
	logger *slog.Logger,
) *SmartRouting {
	if normalized, err := config.Normalize(); err == nil {
		config = normalized
	}
	return &SmartRouting{
		routes: routes,
		config: config,
		scorer: scorer,
		logger: logger,
	}
}

func (s *SmartRouting) Name() string { return algorithm.SmartRouting }

func (s *SmartRouting) Next(
	ctx context.Context,
	req *infracontext.RequestContext,
	exclude map[routingdomain.RouteKey]struct{},
) *routingdomain.Route {
	candidates := filterExcluded(s.routes, exclude)
	if len(candidates) == 0 {
		return nil
	}
	return s.nextSR1(ctx, req, candidates)
}

func (s *SmartRouting) record(req *infracontext.RequestContext, tierApplied bool) {
	if req == nil {
		return
	}
	req.RoutingDecision = &infracontext.RoutingDecision{TierApplied: tierApplied}
}

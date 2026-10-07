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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

var (
	errSR1ScorerUnavailable = errors.New("scorer unavailable")
	errSR1ScoreUnavailable  = errors.New("raw difficulty score unavailable")
)

func (s *SmartRouting) nextSR1(ctx context.Context, req *infracontext.RequestContext, candidates []routingdomain.Route) *routingdomain.Route {
	if s.config == nil {
		s.record(req, false)
		return nil
	}
	if req == nil {
		return s.sr1Fallback(ctx, req, candidates, "", -1, "request unavailable")
	}
	tiers := s.config.Tiers
	ttl := s.sr1TTL()
	escapeEnabled := s.config.SR1.EscapeHatchEnabled
	input, turn, newUser, inputErr := sr1Input(req.Body)
	if inputErr != nil {
		turn, newUser = "invalid", false
	}
	turnHash := sha256.Sum256([]byte(turn + ":" + req.PreviousResponseID))
	turnID := hex.EncodeToString(turnHash[:])
	key := ""
	floor := -1
	if req.SessionID != "" {
		if s.sr1State == nil {
			return s.sr1Fallback(ctx, req, candidates, key, floor, "state store unavailable")
		}
		var err error
		key, err = s.sr1Key(req)
		if err != nil {
			return s.sr1Fallback(ctx, req, candidates, key, floor, "invalid conversation scope")
		}
		decision, stateErr := s.sr1State.Probe(ctx, key, turnID, len(tiers), ttl, newUser, escapeEnabled)
		if stateErr != nil {
			return s.sr1Fallback(ctx, req, candidates, key, floor, "state selection unavailable")
		}
		floor = decision.Rung
		if !decision.NeedsScore {
			return s.sr1Select(req, candidates, floor)
		}
	}
	if inputErr != nil || input == "" {
		return s.sr1Fallback(ctx, req, candidates, key, floor, "latest user input unavailable")
	}
	desired, err := s.sr1Score(ctx, input, req.GatewayID)
	if err != nil {
		return s.sr1Fallback(ctx, req, candidates, key, floor, err.Error())
	}
	rung := desired
	if key != "" {
		rung, err = s.sr1State.Choose(ctx, key, turnID, desired, len(tiers), ttl, newUser, escapeEnabled)
		if err != nil {
			return s.sr1Fallback(ctx, req, candidates, key, floor, "state selection unavailable")
		}
	}
	return s.sr1Select(req, candidates, rung)
}

func (s *SmartRouting) sr1Key(req *infracontext.RequestContext) (string, error) {
	scope, err := json.Marshal([]string{req.GatewayID, req.ConsumerID, req.SessionID})
	if err != nil {
		return "", err
	}
	keyHash := sha256.Sum256(append(scope[:len(scope)-1], s.scopeSuffix...))
	return "tg:sr1:" + hex.EncodeToString(keyHash[:]), nil
}

func (s *SmartRouting) sr1TTL() time.Duration {
	return time.Duration(s.config.SR1.CacheTTLSeconds) * time.Second
}

func (s *SmartRouting) sr1Select(req *infracontext.RequestContext, candidates []routingdomain.Route, rung int) *routingdomain.Route {
	available := 0
	var selected *routingdomain.Route
	for i, tier := range s.config.Tiers {
		if route := sr1Route(tier, candidates); route != nil {
			available++
			if selected == nil && i >= rung {
				selected = route
			}
		}
	}
	s.record(req, selected != nil && available > 1)
	return selected
}

func (s *SmartRouting) sr1Fallback(ctx context.Context, req *infracontext.RequestContext, candidates []routingdomain.Route, key string, floor int, reason string) *routingdomain.Route {
	s.record(req, false)
	if s.logger != nil {
		s.warnOnce.Do(func() { s.logger.Warn("SR-1 used strongest available rung", slog.String("reason", reason)) })
	}
	if key != "" && s.sr1State != nil {
		if stored, err := s.sr1State.Read(ctx, key, len(s.config.Tiers), s.sr1TTL()); err == nil && stored > floor {
			floor = stored
		}
	}
	for i := len(s.config.Tiers) - 1; i >= 0 && i >= floor; i-- {
		if route := sr1Route(s.config.Tiers[i], candidates); route != nil {
			return route
		}
	}
	return nil
}

func (s *SmartRouting) sr1Score(ctx context.Context, input, tenantID string) (int, error) {
	if s.scorer == nil || !s.scorer.Configured() {
		return 0, errSR1ScorerUnavailable
	}
	score, err := s.scorer.ScoreSR1(ctx, input, tenantID)
	if err != nil || math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 1 {
		return 0, errSR1ScoreUnavailable
	}
	desired := 0
	for i, tier := range s.config.Tiers {
		if score >= tier.MinScore {
			desired = i
		}
	}
	return desired, nil
}

func sr1Route(tier registry.SmartRoutingTier, candidates []routingdomain.Route) *routingdomain.Route {
	for _, route := range candidates {
		if route.Registry != nil && route.Registry.ID == tier.RegistryID && route.Model == tier.RouteModel() {
			return pick(route)
		}
	}
	return nil
}

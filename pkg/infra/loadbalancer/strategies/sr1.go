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
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

// SR1Scorer verifies that raw scores came from the frozen SR-1 artifact.
type SR1Scorer interface {
	ScoreSR1(ctx context.Context, input, tenantID string) (float64, error)
}

// NewSmartRoutingWithSR1 adds shared state for the sole cold-point routing policy.
func NewSmartRoutingWithSR1(routes []routingdomain.Route, config *registry.SmartRoutingConfig, scorer ComplexityScorer, state SR1Store, logger *slog.Logger) *SmartRouting {
	strategy := NewSmartRouting(routes, config, scorer, logger)
	strategy.sr1State = state
	return strategy
}

func (s *SmartRouting) nextSR1(ctx context.Context, req *infracontext.RequestContext, candidates []routingdomain.Route) *routingdomain.Route {
	config, err := s.config.Normalize()
	if err != nil {
		s.record(req, false)
		return nil
	}
	tiers := config.Tiers
	ttl := time.Duration(config.SR1.CacheTTLSeconds) * time.Second
	escapeEnabled := config.SR1.EscapeEnabled()
	selectRung := func(rung int) *routingdomain.Route {
		for i := rung; i < len(tiers); i++ {
			if route := sr1Route(tiers[i], candidates); route != nil {
				s.record(req, true)
				return route
			}
		}
		s.record(req, false)
		return nil
	}
	fallback := func(reason string) *routingdomain.Route {
		s.record(req, false)
		if s.logger != nil {
			s.warnOnce.Do(func() { s.logger.Warn("SR-1 used strongest available rung", slog.String("reason", reason)) })
		}
		for i := len(tiers) - 1; i >= 0; i-- {
			if route := sr1Route(tiers[i], candidates); route != nil {
				if req != nil && req.SessionID != "" && s.sr1State != nil {
					key, err := s.sr1Key(req)
					if err == nil {
						floor, stateErr := s.sr1State.Choose(ctx, key, "failure", i, len(tiers), ttl, false, false)
						if stateErr == nil && i < floor {
							return nil
						}
					}
				}
				return route
			}
		}
		return nil
	}
	if req == nil {
		return fallback("request unavailable")
	}
	input, turn, newUser, inputErr := sr1Input(req.Body)
	if inputErr != nil {
		turn, newUser = "invalid", false
	}
	turnHash := sha256.Sum256([]byte(turn + ":" + req.PreviousResponseID))
	turnID := hex.EncodeToString(turnHash[:])
	key := ""
	if req.SessionID != "" {
		if s.sr1State == nil {
			return fallback("state store unavailable")
		}
		key, err = s.sr1Key(req)
		if err != nil {
			return fallback("invalid conversation scope")
		}
		decision, stateErr := s.sr1State.Probe(ctx, key, turnID, len(tiers), ttl, newUser, escapeEnabled)
		if stateErr != nil {
			return fallback("state selection unavailable")
		}
		if !decision.NeedsScore {
			return selectRung(decision.Rung)
		}
	}
	if inputErr != nil {
		return fallback("latest user input unavailable")
	}
	desired := len(tiers) - 1
	if input != "" {
		if s.scorer == nil || !s.scorer.Configured() {
			return fallback("scorer unavailable")
		}
		score, err := s.scorer.ScoreSR1(ctx, input, req.GatewayID)
		if err != nil || math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 1 {
			return fallback("raw difficulty score unavailable")
		}
		desired = 0
		for i, tier := range tiers {
			if score >= tier.MinScore {
				desired = i
			}
		}
	}
	rung := desired
	if key != "" {
		rung, err = s.sr1State.Choose(ctx, key, turnID, desired, len(tiers), ttl, newUser, escapeEnabled)
		if err != nil {
			return fallback("state selection unavailable")
		}
	}
	return selectRung(rung)
}

func (s *SmartRouting) sr1Key(req *infracontext.RequestContext) (string, error) {
	scope, err := json.Marshal([]any{req.GatewayID, req.ConsumerID, req.SessionID, s.config})
	if err != nil {
		return "", err
	}
	keyHash := sha256.Sum256(scope)
	return "tg:sr1:" + hex.EncodeToString(keyHash[:]), nil
}

func sr1Route(tier registry.SmartRoutingTier, candidates []routingdomain.Route) *routingdomain.Route {
	for _, route := range candidates {
		if route.Registry != nil && route.Registry.ID == tier.RegistryID && (tier.RouteModel() == "" || route.Model == tier.RouteModel()) {
			return pick(route)
		}
	}
	return nil
}

func sr1Input(body []byte) (string, string, bool, error) {
	var request map[string]json.RawMessage
	if err := json.Unmarshal(body, &request); err != nil {
		return "", "", false, err
	}
	for _, field := range []string{"prompt", "input"} {
		var text string
		if json.Unmarshal(request[field], &text) == nil && strings.TrimSpace(text) != "" {
			return text, "prompt:" + text, true, nil
		}
	}
	messages := request["messages"]
	if len(messages) == 0 {
		messages = request["input"]
	}
	var items []struct {
		Role      string          `json:"role"`
		Type      string          `json:"type"`
		Content   json.RawMessage `json:"content"`
		ToolCalls json.RawMessage `json:"tool_calls"`
	}
	if err := json.Unmarshal(messages, &items); err != nil {
		return "", "", false, err
	}
	for i := len(items) - 1; i >= 0; i-- {
		if items[i].Role != "user" {
			continue
		}
		if sr1ToolOnly(items[i].Content) {
			continue
		}
		text := sr1Text(items[i].Content)
		if strings.TrimSpace(text) == "" {
			return "", "", false, errors.New("latest user turn has no text")
		}
		newUser := true
		for _, suffix := range items[i+1:] {
			if suffix.Role != "assistant" || suffix.Type == "function_call" || len(suffix.ToolCalls) > 0 && string(suffix.ToolCalls) != "null" && string(suffix.ToolCalls) != "[]" {
				newUser = false
				break
			}
			var blocks []struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(suffix.Content, &blocks) == nil {
				for _, block := range blocks {
					if block.Type == "tool_use" {
						newUser = false
					}
				}
			}
		}
		return text, fmt.Sprintf("%d:%s", i, text), newUser, nil
	}
	if len(items) > 0 {
		last := items[len(items)-1]
		if last.Role == "tool" || last.Type == "function_call_output" || sr1ToolOnly(last.Content) {
			return "", "continuation", false, nil
		}
	}
	return "", "", false, errors.New("no user turn")
}

func sr1Text(content json.RawMessage) string {
	var text string
	if json.Unmarshal(content, &text) == nil {
		return text
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(content, &blocks) != nil {
		return ""
	}
	parts := []string{}
	for _, block := range blocks {
		if block.Type == "text" || block.Type == "input_text" {
			parts = append(parts, block.Text)
		}
	}
	return strings.Join(parts, "\n")
}

func sr1ToolOnly(content json.RawMessage) bool {
	var blocks []struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(content, &blocks) != nil || len(blocks) == 0 {
		return false
	}
	for _, block := range blocks {
		if block.Type != "tool_result" {
			return false
		}
	}
	return true
}

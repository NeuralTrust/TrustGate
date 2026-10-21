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

package middleware

import (
	"bytes"
	"math/rand"

	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/trafficlabels"
	appusage "github.com/NeuralTrust/TrustGate/pkg/app/usage"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
)

const defaultLabelIntakeMaxBodyBytes = 512 << 10

// TrafficLabelsMiddleware offers the chat requests of a gateway with traffic
// labeling on, from consumers that hold label sets, to the async labeling intake.
// It never blocks or alters the request.
type TrafficLabelsMiddleware struct {
	intake       trafficlabels.Intake
	recorder     trafficlabels.Recorder
	maxBodyBytes int
	enabled      bool
}

func NewTrafficLabelsMiddleware(
	intake trafficlabels.Intake,
	recorder trafficlabels.Recorder,
	cfg *config.Config,
) *TrafficLabelsMiddleware {
	maxBody := defaultLabelIntakeMaxBodyBytes
	if cfg != nil && cfg.TrafficLabels.IntakeMaxBodyBytes > 0 {
		maxBody = cfg.TrafficLabels.IntakeMaxBodyBytes
	}
	return &TrafficLabelsMiddleware{
		intake:       intake,
		recorder:     recorder,
		maxBodyBytes: maxBody,
		enabled:      cfg != nil && cfg.Telemetry.Enabled,
	}
}

// Middleware reads the candidate before the request runs, since plugins may
// rewrite the body, and offers it only once the request was served: a request
// refused for usage, rate limit or a server error is not labeled.
func (m *TrafficLabelsMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		candidate, ok := m.candidate(c)
		err := c.Next()
		if ok {
			m.offer(candidate, err == nil && appusage.BillableStatus(c.Response().StatusCode()))
		}
		return err
	}
}

func (m *TrafficLabelsMiddleware) offer(candidate trafficlabels.Candidate, served bool) {
	if !served {
		if !candidate.BufferOnly {
			m.recorder.Intake(trafficlabels.OutcomeNotServed)
		}
		return
	}
	m.intake.Submit(candidate)
}

func (m *TrafficLabelsMiddleware) candidate(c *fiber.Ctx) (trafficlabels.Candidate, bool) {
	if m.intake == nil || !m.enabled {
		return trafficlabels.Candidate{}, false
	}
	ctx := c.UserContext()
	gw, ok := appgateway.FromContext(ctx)
	if !ok || !gw.TrafficLabeling.IsEnabled() {
		return trafficlabels.Candidate{}, false
	}
	rc, ok := appconsumer.ConsumerFromContext(ctx)
	if !ok || rc.Consumer == nil || len(rc.Consumer.LabelSets) == 0 {
		return trafficlabels.Candidate{}, false
	}
	rt := trace.FromContext(ctx)
	if rt == nil {
		return trafficlabels.Candidate{}, false
	}
	route, ok := proxyRouteFor(c)
	if !ok || route.Capability != resolver.CapabilityChat {
		return trafficlabels.Candidate{}, false
	}
	sessionID := EffectiveSessionID(c)
	bufferOnly := false
	if rate := gw.TrafficLabeling.Rate(); rate < 1 && rand.Float64() >= rate { // #nosec G404 -- sampling, not a secret
		m.recorder.Intake(trafficlabels.OutcomeSampledOut)
		// A Responses continuation only carries its new turn, so a turn left
		// out of sampling still feeds the conversation buffer; otherwise the
		// next sampled turn would be labeled without it.
		if route.SourceFormat != adapter.FormatOpenAIResponses || sessionID == "" {
			return trafficlabels.Candidate{}, false
		}
		bufferOnly = true
	}
	body, ok := m.body(c, bufferOnly)
	if !ok {
		return trafficlabels.Candidate{}, false
	}
	return trafficlabels.Candidate{
		GatewayID:    gw.ID.String(),
		TenantID:     gw.TenantID(),
		ConsumerID:   rc.Consumer.ID.String(),
		TraceID:      rt.TraceID(),
		SessionID:    sessionID,
		SourceFormat: route.SourceFormat,
		Body:         bytes.Clone(body),
		Config:       gw.TrafficLabeling,
		LabelSets:    rc.Consumer.LabelSets,
		ReceivedAt:   rt.StartedAt().UTC(),
		BufferOnly:   bufferOnly,
	}, true
}

func (m *TrafficLabelsMiddleware) body(c *fiber.Ctx, bufferOnly bool) ([]byte, bool) {
	tooLarge := func() ([]byte, bool) {
		if !bufferOnly {
			m.recorder.Intake(trafficlabels.OutcomeBodyTooLarge)
		}
		return nil, false
	}
	body := c.Request().Body()
	if len(body) > m.maxBodyBytes {
		return tooLarge()
	}
	return body, len(body) > 0
}

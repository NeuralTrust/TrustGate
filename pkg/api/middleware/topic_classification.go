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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/topicclassifier"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
)

const defaultTopicIntakeMaxBodyBytes = 512 << 10

type TopicClassificationMiddleware struct {
	intake       topicclassifier.Intake
	recorder     topicclassifier.Recorder
	maxBodyBytes int
}

func NewTopicClassificationMiddleware(
	intake topicclassifier.Intake,
	recorder topicclassifier.Recorder,
	cfg *config.Config,
) *TopicClassificationMiddleware {
	maxBody := defaultTopicIntakeMaxBodyBytes
	if cfg != nil && cfg.TopicClassifier.IntakeMaxBodyBytes > 0 {
		maxBody = cfg.TopicClassifier.IntakeMaxBodyBytes
	}
	return &TopicClassificationMiddleware{intake: intake, recorder: recorder, maxBodyBytes: maxBody}
}

func (m *TopicClassificationMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		m.offer(c)
		return c.Next()
	}
}

func (m *TopicClassificationMiddleware) offer(c *fiber.Ctx) {
	if m.intake == nil {
		return
	}
	ctx := c.UserContext()
	gw, ok := appgateway.FromContext(ctx)
	if !ok || !gw.TopicClassification.IsEnabled() {
		return
	}
	rt := trace.FromContext(ctx)
	if rt == nil {
		return
	}
	route, ok := proxyRouteFor(c)
	if !ok || route.Capability != resolver.CapabilityChat {
		return
	}
	if rate := gw.TopicClassification.Rate(); rate < 1 && rand.Float64() >= rate { // #nosec G404 -- sampling, not a secret
		m.recorder.Intake(topicclassifier.OutcomeSampledOut)
		return
	}
	// Checked on the raw body first so an oversized compressed body is never decompressed.
	body := c.Request().Body()
	if len(body) > m.maxBodyBytes {
		m.recorder.Intake(topicclassifier.OutcomeBodyTooLarge)
		return
	}
	// c.Body() scans every header and re-decodes on each call; only an encoded body needs it.
	if len(c.Request().Header.ContentEncoding()) > 0 {
		body = c.Body()
		if len(body) > m.maxBodyBytes {
			m.recorder.Intake(topicclassifier.OutcomeBodyTooLarge)
			return
		}
	}
	if len(body) == 0 {
		return
	}
	m.intake.Submit(topicclassifier.Candidate{
		GatewayID:    gw.ID.String(),
		TraceID:      rt.TraceID(),
		SourceFormat: route.SourceFormat,
		Body:         bytes.Clone(body),
		Config:       gw.TopicClassification,
		ReceivedAt:   time.Now().UTC(),
	})
}

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
	"context"
	"math/rand"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/topicclassifier"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
)

// defaultTopicIntakeMaxBodyBytes caps the body copied for classification when
// the config sets no cap. Only the latest user messages, at most
// topic.MaxTextChars of them, are ever classified.
const defaultTopicIntakeMaxBodyBytes = 512 << 10

// TopicClassificationMiddleware offers the prompt of every chat request of a
// gateway with topic classification enabled to the async classifier. It sits
// before the handler, so requests a plugin later blocks are classified too,
// and it never blocks or fails the request: when the classifier cannot take
// more work, the candidate is dropped. Sampling happens here, before the body
// is copied, so requests that will not be classified cost nothing more.
type TopicClassificationMiddleware struct {
	intake       topicclassifier.Intake
	recorder     topicclassifier.Recorder
	maxBodyBytes int
}

// NewTopicClassificationMiddleware builds the middleware on top of intake. A
// nil recorder records nothing.
func NewTopicClassificationMiddleware(intake topicclassifier.Intake, recorder topicclassifier.Recorder, cfg *config.Config) *TopicClassificationMiddleware {
	maxBody := defaultTopicIntakeMaxBodyBytes
	if cfg != nil && cfg.TopicClassifier.IntakeMaxBodyBytes > 0 {
		maxBody = cfg.TopicClassifier.IntakeMaxBodyBytes
	}
	if recorder == nil {
		recorder = topicclassifier.NopRecorder{}
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
	// The raw body is checked first so an oversized compressed body is never
	// decompressed here; the decoded one is checked again below.
	if len(c.Request().Body()) > m.maxBodyBytes {
		m.recorder.Intake(topicclassifier.OutcomeBodyTooLarge)
		return
	}
	body := c.Body()
	if len(body) == 0 {
		return
	}
	if len(body) > m.maxBodyBytes {
		m.recorder.Intake(topicclassifier.OutcomeBodyTooLarge)
		return
	}
	m.intake.Submit(topicclassifier.Candidate{
		GatewayID:    gw.ID.String(),
		ConsumerID:   consumerIDFromContext(ctx),
		TraceID:      rt.TraceID(),
		SourceFormat: route.SourceFormat,
		Body:         bytes.Clone(body),
		Config:       gw.TopicClassification,
		ReceivedAt:   time.Now().UTC(),
	})
}

func consumerIDFromContext(ctx context.Context) string {
	authCtx, ok := appauth.AuthContextFromContext(ctx)
	if !ok || authCtx == nil || authCtx.ConsumerID.IsNil() {
		return ""
	}
	return authCtx.ConsumerID.String()
}

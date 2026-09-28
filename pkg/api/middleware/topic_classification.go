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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/topicclassifier"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
)

// TopicClassificationMiddleware offers the prompt of every chat request of a
// gateway with topic classification enabled to the async classifier. It sits
// before the handler, so requests a plugin later blocks are classified too,
// and it never blocks or fails the request: when the classifier cannot take
// more work, the candidate is dropped.
type TopicClassificationMiddleware struct {
	intake       topicclassifier.Intake
	maxBodyBytes int
}

// NewTopicClassificationMiddleware builds the middleware on top of intake.
func NewTopicClassificationMiddleware(intake topicclassifier.Intake, cfg *config.Config) *TopicClassificationMiddleware {
	maxBody := 0
	if cfg != nil {
		maxBody = cfg.TopicClassifier.IntakeMaxBodyBytes
	}
	return &TopicClassificationMiddleware{intake: intake, maxBodyBytes: maxBody}
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
	body := c.Body()
	if len(body) == 0 || (m.maxBodyBytes > 0 && len(body) > m.maxBodyBytes) {
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

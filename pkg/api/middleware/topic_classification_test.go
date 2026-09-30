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

package middleware_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/topicclassifier"
	topicmocks "github.com/NeuralTrust/TrustGate/pkg/app/topicclassifier/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/topic"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const chatBody = `{"model":"gpt-4o","messages":[{"role":"user","content":"where is my refund"}]}`

type recordingIntake struct {
	mu         sync.Mutex
	candidates []topicclassifier.Candidate
	accept     bool
}

func (r *recordingIntake) Submit(c topicclassifier.Candidate) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.candidates = append(r.candidates, c)
	return r.accept
}

func (r *recordingIntake) Start()                         {}
func (r *recordingIntake) Shutdown(context.Context) error { return nil }

func (r *recordingIntake) submitted() []topicclassifier.Candidate {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]topicclassifier.Candidate(nil), r.candidates...)
}

type topicClassificationSetup struct {
	gateway  *gatewaydomain.Gateway
	noTrace  bool
	consumer ids.ConsumerID
	maxBody  int
	accept   bool
	// outcomes are the Intake outcomes the middleware must record, in any order.
	outcomes []string
}

func classifiedGateway(enabled bool) *gatewaydomain.Gateway {
	gw, _ := gatewaydomain.New("acme")
	gw.TopicClassification = &topic.Config{
		Enabled: enabled,
		Topics:  []topic.Topic{{Name: "billing", Definition: "refunds and invoices"}},
	}
	return gw
}

func sampledGateway(rate float64) *gatewaydomain.Gateway {
	gw := classifiedGateway(true)
	gw.TopicClassification.SamplingRate = &rate
	return gw
}

func newTopicClassificationApp(t *testing.T, s topicClassificationSetup) (*fiber.App, *recordingIntake) {
	t.Helper()
	intake := &recordingIntake{accept: s.accept}
	cfg := &config.Config{TopicClassifier: config.TopicClassifierConfig{IntakeMaxBodyBytes: s.maxBody}}
	recorder := topicmocks.NewRecorder(t)
	for _, outcome := range s.outcomes {
		recorder.EXPECT().Intake(outcome).Once()
	}
	mw := middleware.NewTopicClassificationMiddleware(intake, recorder, cfg)

	app := fiber.New()
	app.Post("/*",
		func(c *fiber.Ctx) error {
			ctx := c.UserContext()
			if s.gateway != nil {
				ctx = appgateway.WithGateway(ctx, s.gateway)
			}
			if !s.noTrace {
				ctx = trace.NewContext(ctx, trace.New("trace-123", trace.Metadata{}))
			}
			if !s.consumer.IsNil() {
				ctx = appauth.WithAuthContext(ctx, &appauth.AuthContext{ConsumerID: s.consumer})
			}
			c.SetUserContext(ctx)
			return c.Next()
		},
		mw.Middleware(),
		func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusOK).Send(c.Body())
		},
	)
	return app, intake
}

func postTo(t *testing.T, app *fiber.App, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(raw)
}

func TestTopicClassification_OffersChatRequestsOfEnabledGateways(t *testing.T) {
	t.Parallel()
	consumer := ids.New[ids.ConsumerKind]()
	gw := classifiedGateway(true)
	app, intake := newTopicClassificationApp(t, topicClassificationSetup{gateway: gw, consumer: consumer, accept: true})

	status, echoed := postTo(t, app, "/acme/v1/chat/completions", chatBody)

	assert.Equal(t, fiber.StatusOK, status)
	assert.Equal(t, chatBody, echoed, "the request must reach the handler untouched")
	got := intake.submitted()
	require.Len(t, got, 1)
	assert.Equal(t, gw.ID.String(), got[0].GatewayID)
	assert.Equal(t, consumer.String(), got[0].ConsumerID)
	assert.Equal(t, "trace-123", got[0].TraceID)
	assert.Equal(t, adapter.FormatOpenAI, got[0].SourceFormat)
	assert.Equal(t, chatBody, string(got[0].Body))
	assert.Same(t, gw.TopicClassification, got[0].Config)
	assert.False(t, got[0].ReceivedAt.IsZero())
}

func TestTopicClassification_SkipsWhatItMustNotClassify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup topicClassificationSetup
		path  string
		body  string
	}{
		{name: "gateway without the feature", setup: topicClassificationSetup{gateway: classifiedGateway(false)}, path: "/acme/v1/chat/completions", body: chatBody},
		{name: "gateway never configured", setup: topicClassificationSetup{gateway: &gatewaydomain.Gateway{}}, path: "/acme/v1/chat/completions", body: chatBody},
		{name: "no gateway in context", setup: topicClassificationSetup{}, path: "/acme/v1/chat/completions", body: chatBody},
		{name: "no trace", setup: topicClassificationSetup{gateway: classifiedGateway(true), noTrace: true}, path: "/acme/v1/chat/completions", body: chatBody},
		{name: "embeddings route", setup: topicClassificationSetup{gateway: classifiedGateway(true)}, path: "/acme/v1/embeddings", body: `{"input":"hello","model":"text-embedding-3-small"}`},
		{name: "unknown route", setup: topicClassificationSetup{gateway: classifiedGateway(true)}, path: "/acme/whatever", body: chatBody},
		{name: "body over the cap", setup: topicClassificationSetup{gateway: classifiedGateway(true), maxBody: 16, outcomes: []string{topicclassifier.OutcomeBodyTooLarge}}, path: "/acme/v1/chat/completions", body: chatBody},
		{name: "empty body", setup: topicClassificationSetup{gateway: classifiedGateway(true)}, path: "/acme/v1/chat/completions", body: ""},
		{name: "sampled out", setup: topicClassificationSetup{gateway: sampledGateway(0), outcomes: []string{topicclassifier.OutcomeSampledOut}}, path: "/acme/v1/chat/completions", body: chatBody},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			app, intake := newTopicClassificationApp(t, tt.setup)
			status, echoed := postTo(t, app, tt.path, tt.body)
			assert.Equal(t, fiber.StatusOK, status)
			assert.Equal(t, tt.body, echoed)
			assert.Empty(t, intake.submitted())
		})
	}
}

func TestTopicClassification_FullIntakeNeverAffectsTheRequest(t *testing.T) {
	t.Parallel()
	app, intake := newTopicClassificationApp(t, topicClassificationSetup{gateway: classifiedGateway(true), accept: false})

	status, echoed := postTo(t, app, "/acme/v1/chat/completions", chatBody)

	assert.Equal(t, fiber.StatusOK, status)
	assert.Equal(t, chatBody, echoed)
	assert.Len(t, intake.submitted(), 1)
}

func TestTopicClassification_WithoutConsumerLeavesItEmpty(t *testing.T) {
	t.Parallel()
	app, intake := newTopicClassificationApp(t, topicClassificationSetup{gateway: classifiedGateway(true), accept: true})

	postTo(t, app, "/acme/v1/chat/completions", chatBody)

	got := intake.submitted()
	require.Len(t, got, 1)
	assert.Empty(t, got[0].ConsumerID)
}

func TestTopicClassification_NilIntakeIsInert(t *testing.T) {
	t.Parallel()
	mw := middleware.NewTopicClassificationMiddleware(nil, topicmocks.NewRecorder(t), nil)
	app := fiber.New()
	app.Post("/*",
		func(c *fiber.Ctx) error {
			c.SetUserContext(appgateway.WithGateway(c.UserContext(), classifiedGateway(true)))
			return c.Next()
		},
		mw.Middleware(),
		func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) },
	)
	status, _ := postTo(t, app, "/acme/v1/chat/completions", chatBody)
	assert.Equal(t, fiber.StatusOK, status)
}

func TestTopicClassification_FullSamplingOffersEveryRequest(t *testing.T) {
	t.Parallel()
	app, intake := newTopicClassificationApp(t, topicClassificationSetup{gateway: sampledGateway(1), accept: true})
	for range 5 {
		postTo(t, app, "/acme/v1/chat/completions", chatBody)
	}
	assert.Len(t, intake.submitted(), 5)
}

func TestTopicClassification_UnsetCapFallsBackToTheDefault(t *testing.T) {
	t.Parallel()
	app, intake := newTopicClassificationApp(t, topicClassificationSetup{
		gateway:  classifiedGateway(true),
		maxBody:  -1,
		accept:   true,
		outcomes: []string{topicclassifier.OutcomeBodyTooLarge},
	})

	postTo(t, app, "/acme/v1/chat/completions", chatBody)
	require.Len(t, intake.submitted(), 1, "a small body passes the default cap")

	huge := `{"model":"gpt-4o","messages":[{"role":"user","content":"` + strings.Repeat("x", 600<<10) + `"}]}`
	postTo(t, app, "/acme/v1/chat/completions", huge)
	assert.Len(t, intake.submitted(), 1, "a cap of zero or less is not \"no cap\"")
}

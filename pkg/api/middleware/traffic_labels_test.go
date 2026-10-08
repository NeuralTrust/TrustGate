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
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/trafficlabels"
	labelmocks "github.com/NeuralTrust/TrustGate/pkg/app/trafficlabels/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const chatBody = `{"model":"gpt-4o","messages":[{"role":"user","content":"where is my refund"}]}`

type recordingIntake struct {
	mu         sync.Mutex
	candidates []trafficlabels.Candidate
	accept     bool
}

func (r *recordingIntake) Submit(c trafficlabels.Candidate) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.candidates = append(r.candidates, c)
	return r.accept
}

func (r *recordingIntake) Start()                         {}
func (r *recordingIntake) Shutdown(context.Context) error { return nil }

func (r *recordingIntake) submitted() []trafficlabels.Candidate {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]trafficlabels.Candidate(nil), r.candidates...)
}

type trafficLabelsSetup struct {
	gateway *gatewaydomain.Gateway
	// consumer is the resolved consumer; nil means the default labeled one.
	consumer   *consumerdomain.Consumer
	noConsumer bool
	noTrace    bool
	session    *infracontext.Session
	maxBody    int
	accept     bool
	// outcomes are the Intake outcomes the middleware must record, in any order.
	outcomes []string
}

func labeledGateway(enabled bool) *gatewaydomain.Gateway {
	gw, _ := gatewaydomain.New("acme")
	gw.TrafficLabeling = &trafficlabel.Config{
		Enabled:    enabled,
		RegistryID: ids.New[ids.RegistryKind]().String(),
		Model:      "gpt-4o-mini",
	}
	return gw
}

func sampledGateway(rate float64) *gatewaydomain.Gateway {
	gw := labeledGateway(true)
	gw.TrafficLabeling.SamplingRate = &rate
	return gw
}

func labeledConsumer() *consumerdomain.Consumer {
	return &consumerdomain.Consumer{
		ID:   ids.New[ids.ConsumerKind](),
		Type: consumerdomain.TypeLLM,
		LabelSets: []trafficlabel.LabelSet{{
			ID: "set-topic", Name: "Topic",
			Labels: []trafficlabel.Label{{Name: "Billing", Description: "refunds and invoices"}, {Name: "Legal"}},
		}},
	}
}

func unlabeledConsumer() *consumerdomain.Consumer {
	c := labeledConsumer()
	c.LabelSets = nil
	return c
}

func newTrafficLabelsApp(t *testing.T, s trafficLabelsSetup) (*fiber.App, *recordingIntake) {
	t.Helper()
	intake := &recordingIntake{accept: s.accept}
	cfg := &config.Config{TrafficLabels: config.TrafficLabelsConfig{IntakeMaxBodyBytes: s.maxBody}}
	recorder := labelmocks.NewRecorder(t)
	for _, outcome := range s.outcomes {
		recorder.EXPECT().Intake(outcome).Once()
	}
	mw := middleware.NewTrafficLabelsMiddleware(intake, recorder, cfg)

	app := fiber.New()
	app.Post("/*",
		func(c *fiber.Ctx) error {
			ctx := c.UserContext()
			if s.gateway != nil {
				ctx = appgateway.WithGateway(ctx, s.gateway)
			}
			if !s.noConsumer {
				consumer := s.consumer
				if consumer == nil {
					consumer = labeledConsumer()
				}
				ctx = appconsumer.WithConsumer(ctx, &appconsumer.RoutableConsumer{Consumer: consumer})
			}
			if !s.noTrace {
				ctx = trace.NewContext(ctx, trace.New("trace-123", trace.Metadata{}))
			}
			if s.session != nil {
				ctx = infracontext.WithSession(ctx, *s.session)
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

func TestTrafficLabels_OffersChatRequestsOfEnabledGateways(t *testing.T) {
	t.Parallel()
	gw := labeledGateway(true)
	consumer := labeledConsumer()
	app, intake := newTrafficLabelsApp(t, trafficLabelsSetup{gateway: gw, consumer: consumer, accept: true})

	status, echoed := postTo(t, app, "/acme/v1/chat/completions", chatBody)

	assert.Equal(t, fiber.StatusOK, status)
	assert.Equal(t, chatBody, echoed, "the request must reach the handler untouched")
	got := intake.submitted()
	require.Len(t, got, 1)
	assert.Equal(t, gw.ID.String(), got[0].GatewayID)
	assert.Equal(t, "trace-123", got[0].TraceID)
	assert.Equal(t, adapter.FormatOpenAI, got[0].SourceFormat)
	assert.Equal(t, chatBody, string(got[0].Body))
	assert.Same(t, gw.TrafficLabeling, got[0].Config)
	assert.Equal(t, consumer.ID.String(), got[0].ConsumerID)
	assert.Equal(t, consumer.LabelSets, got[0].LabelSets)
	assert.False(t, got[0].ReceivedAt.IsZero())
}

func TestTrafficLabels_SkipsWhatItMustNotClassify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup trafficLabelsSetup
		path  string
		body  string
	}{
		{name: "gateway without the feature", setup: trafficLabelsSetup{gateway: labeledGateway(false)}, path: "/acme/v1/chat/completions", body: chatBody},
		{name: "gateway never configured", setup: trafficLabelsSetup{gateway: &gatewaydomain.Gateway{}}, path: "/acme/v1/chat/completions", body: chatBody},
		{name: "no gateway in context", setup: trafficLabelsSetup{}, path: "/acme/v1/chat/completions", body: chatBody},
		{name: "gateway without a registry", setup: trafficLabelsSetup{gateway: func() *gatewaydomain.Gateway {
			gw := labeledGateway(true)
			gw.TrafficLabeling.RegistryID = ""
			return gw
		}()}, path: "/acme/v1/chat/completions", body: chatBody},
		{name: "no consumer in context", setup: trafficLabelsSetup{gateway: labeledGateway(true), noConsumer: true}, path: "/acme/v1/chat/completions", body: chatBody},
		{name: "consumer without label sets", setup: trafficLabelsSetup{gateway: labeledGateway(true), consumer: unlabeledConsumer()}, path: "/acme/v1/chat/completions", body: chatBody},
		{name: "no trace", setup: trafficLabelsSetup{gateway: labeledGateway(true), noTrace: true}, path: "/acme/v1/chat/completions", body: chatBody},
		{name: "non-chat route", setup: trafficLabelsSetup{gateway: labeledGateway(true)}, path: "/acme/v1/embeddings", body: `{"input":"hello","model":"text-embedding-3-small"}`},
		{name: "unknown route", setup: trafficLabelsSetup{gateway: labeledGateway(true)}, path: "/acme/whatever", body: chatBody},
		{name: "body over the cap", setup: trafficLabelsSetup{gateway: labeledGateway(true), maxBody: 16, outcomes: []string{trafficlabels.OutcomeBodyTooLarge}}, path: "/acme/v1/chat/completions", body: chatBody},
		{name: "empty body", setup: trafficLabelsSetup{gateway: labeledGateway(true)}, path: "/acme/v1/chat/completions", body: ""},
		{name: "sampled out", setup: trafficLabelsSetup{gateway: sampledGateway(0), outcomes: []string{trafficlabels.OutcomeSampledOut}}, path: "/acme/v1/chat/completions", body: chatBody},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			app, intake := newTrafficLabelsApp(t, tt.setup)
			status, echoed := postTo(t, app, tt.path, tt.body)
			assert.Equal(t, fiber.StatusOK, status)
			assert.Equal(t, tt.body, echoed)
			assert.Empty(t, intake.submitted())
		})
	}
}

func TestTrafficLabels_FullIntakeNeverAffectsTheRequest(t *testing.T) {
	t.Parallel()
	app, intake := newTrafficLabelsApp(t, trafficLabelsSetup{gateway: labeledGateway(true), accept: false})

	status, echoed := postTo(t, app, "/acme/v1/chat/completions", chatBody)

	assert.Equal(t, fiber.StatusOK, status)
	assert.Equal(t, chatBody, echoed)
	assert.Len(t, intake.submitted(), 1)
}

func TestTrafficLabels_NilIntakeIsInert(t *testing.T) {
	t.Parallel()
	mw := middleware.NewTrafficLabelsMiddleware(nil, labelmocks.NewRecorder(t), nil)
	app := fiber.New()
	app.Post("/*",
		func(c *fiber.Ctx) error {
			c.SetUserContext(appgateway.WithGateway(c.UserContext(), labeledGateway(true)))
			return c.Next()
		},
		mw.Middleware(),
		func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) },
	)
	status, _ := postTo(t, app, "/acme/v1/chat/completions", chatBody)
	assert.Equal(t, fiber.StatusOK, status)
}

func TestTrafficLabels_FullSamplingOffersEveryRequest(t *testing.T) {
	t.Parallel()
	app, intake := newTrafficLabelsApp(t, trafficLabelsSetup{gateway: sampledGateway(1), accept: true})
	for range 5 {
		postTo(t, app, "/acme/v1/chat/completions", chatBody)
	}
	assert.Len(t, intake.submitted(), 5)
}

func TestTrafficLabels_UnsetCapFallsBackToTheDefault(t *testing.T) {
	t.Parallel()
	app, intake := newTrafficLabelsApp(t, trafficLabelsSetup{
		gateway:  labeledGateway(true),
		maxBody:  -1,
		accept:   true,
		outcomes: []string{trafficlabels.OutcomeBodyTooLarge},
	})

	postTo(t, app, "/acme/v1/chat/completions", chatBody)
	require.Len(t, intake.submitted(), 1, "a small body passes the default cap")

	huge := `{"model":"gpt-4o","messages":[{"role":"user","content":"` + strings.Repeat("x", 600<<10) + `"}]}`
	postTo(t, app, "/acme/v1/chat/completions", huge)
	assert.Len(t, intake.submitted(), 1, "a cap of zero or less is not \"no cap\"")
}

const responsesContinuationBody = `{"model":"gpt-4o","previous_response_id":"resp_prev1","input":"and the second invoice?"}`

func clientSession(id string) *infracontext.Session {
	return &infracontext.Session{ID: id, Source: infracontext.SessionSourceKnownHeader, Exposed: true}
}

func TestTrafficLabels_CarriesTheEffectiveSessionID(t *testing.T) {
	t.Parallel()

	app, intake := newTrafficLabelsApp(t, trafficLabelsSetup{gateway: labeledGateway(true), accept: true, session: clientSession("sess-1")})
	postTo(t, app, "/acme/v1/responses", responsesContinuationBody)
	got := intake.submitted()
	require.Len(t, got, 1)
	assert.Equal(t, "sess-1", got[0].SessionID)
	assert.False(t, got[0].BufferOnly)

	hidden := &infracontext.Session{ID: "generated-1", Source: infracontext.SessionSourceGenerated}
	app, intake = newTrafficLabelsApp(t, trafficLabelsSetup{gateway: labeledGateway(true), accept: true, session: hidden})
	postTo(t, app, "/acme/v1/chat/completions", chatBody)
	got = intake.submitted()
	require.Len(t, got, 1)
	assert.Empty(t, got[0].SessionID, "a hidden generated id is not a conversation")
}

// A sampled-out Responses turn still feeds the conversation buffer, or the
// next sampled continuation would be labeled without it.
func TestTrafficLabels_SampledOutResponsesTurnIsSubmittedForTheBufferOnly(t *testing.T) {
	t.Parallel()
	app, intake := newTrafficLabelsApp(t, trafficLabelsSetup{
		gateway:  sampledGateway(0),
		session:  clientSession("sess-1"),
		accept:   true,
		outcomes: []string{trafficlabels.OutcomeSampledOut},
	})

	status, echoed := postTo(t, app, "/acme/v1/responses", responsesContinuationBody)

	assert.Equal(t, fiber.StatusOK, status)
	assert.Equal(t, responsesContinuationBody, echoed)
	got := intake.submitted()
	require.Len(t, got, 1)
	assert.True(t, got[0].BufferOnly)
	assert.Equal(t, "sess-1", got[0].SessionID)
	assert.Equal(t, adapter.FormatOpenAIResponses, got[0].SourceFormat)
}

func TestTrafficLabels_SampledOutWithoutAConversationIsDropped(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		body    string
		session *infracontext.Session
	}{
		{name: "chat completions with a session", path: "/acme/v1/chat/completions", body: chatBody, session: clientSession("sess-1")},
		{name: "responses without a session", path: "/acme/v1/responses", body: responsesContinuationBody},
		{name: "responses with a hidden generated id", path: "/acme/v1/responses", body: responsesContinuationBody,
			session: &infracontext.Session{ID: "generated-1", Source: infracontext.SessionSourceGenerated}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			app, intake := newTrafficLabelsApp(t, trafficLabelsSetup{
				gateway:  sampledGateway(0),
				session:  tt.session,
				outcomes: []string{trafficlabels.OutcomeSampledOut},
			})
			postTo(t, app, tt.path, tt.body)
			assert.Empty(t, intake.submitted())
		})
	}
}

func TestTrafficLabels_BufferOnlyOverTheCapIsNotCountedTwice(t *testing.T) {
	t.Parallel()
	app, intake := newTrafficLabelsApp(t, trafficLabelsSetup{
		gateway:  sampledGateway(0),
		session:  clientSession("sess-1"),
		maxBody:  16,
		outcomes: []string{trafficlabels.OutcomeSampledOut},
	})
	postTo(t, app, "/acme/v1/responses", responsesContinuationBody)
	assert.Empty(t, intake.submitted())
}

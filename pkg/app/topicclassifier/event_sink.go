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

package topicclassifier

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/topic"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
)

// GatewayFinder resolves the gateway a classification belongs to, for its
// tenant, retention and exporters.
//
//go:generate mockery --name=GatewayFinder --dir=. --output=./mocks --filename=gateway_finder_mock.go --case=underscore --with-expecter
type GatewayFinder interface {
	FindByID(ctx context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error)
}

// TopicPublisher hands topic classification events to telemetry exporters.
//
//go:generate mockery --name=TopicPublisher --dir=. --output=./mocks --filename=topic_publisher_mock.go --case=underscore --with-expecter
type TopicPublisher interface {
	PublishTopic(ctx context.Context, evt *events.TopicClassification, exporters []telemetrydomain.ExporterConfig)
}

// gatewayCacheTTL bounds how stale the tenant, retention and exporters of a
// gateway may be when publishing, in exchange for not looking the gateway up
// once per classified request.
const gatewayCacheTTL = 30 * time.Second

var _ Sink = (*eventSink)(nil)

type cachedGateway struct {
	gw      *gatewaydomain.Gateway
	expires time.Time
}

type eventSink struct {
	gateways  GatewayFinder
	publisher TopicPublisher
	now       func() time.Time

	mu    sync.Mutex
	known map[ids.GatewayID]cachedGateway
}

// NewEventSink builds the Sink that publishes classifications as telemetry
// events through the gateway's exporters.
func NewEventSink(gateways GatewayFinder, publisher TopicPublisher) Sink {
	return &eventSink{
		gateways:  gateways,
		publisher: publisher,
		now:       time.Now,
		known:     make(map[ids.GatewayID]cachedGateway),
	}
}

func (s *eventSink) gateway(ctx context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error) {
	now := s.now()
	s.mu.Lock()
	cached, ok := s.known[id]
	s.mu.Unlock()
	if ok && now.Before(cached.expires) {
		return cached.gw, nil
	}
	gw, err := s.gateways.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.known[id] = cachedGateway{gw: gw, expires: now.Add(gatewayCacheTTL)}
	s.mu.Unlock()
	return gw, nil
}

func (s *eventSink) Publish(ctx context.Context, req topic.Request, cls topic.Classification) error {
	id, err := ids.Parse[ids.GatewayKind](req.GatewayID)
	if err != nil {
		return fmt.Errorf("topic sink: gateway id %q: %w", req.GatewayID, err)
	}
	gw, err := s.gateway(ctx, id)
	if err != nil {
		return fmt.Errorf("topic sink: find gateway: %w", err)
	}
	now := s.now()
	requested := req.ReceivedAt
	if requested.IsZero() {
		requested = now
	}
	scores := make([]events.TopicScore, len(cls.Scores))
	for i, sc := range cls.Scores {
		scores[i] = events.TopicScore{Topic: sc.Topic, Probability: sc.Probability, Matched: sc.Matched}
	}
	evt := &events.TopicClassification{
		SchemaVersion: events.SchemaVersion,
		TraceID:       req.TraceID,
		GatewayID:     req.GatewayID,
		TenantID:      gw.TenantID(),
		OccurredOn:    now.UnixMilli(),
		RequestedOn:   requested.UnixMilli(),
		Retention:     retentionFor(gw, requested),
		Scores:        scores,
		Matched:       slices.Clone(cls.Matched),
		Windows:       cls.Windows,
		ModelVersion:  cls.ModelVersion,
		CatalogHash:   req.CatalogHash,
		Threshold:     req.Threshold,
	}
	var exporters []telemetrydomain.ExporterConfig
	if gw.Telemetry != nil {
		exporters = gw.Telemetry.Exporters
	}
	s.publisher.PublishTopic(ctx, evt, exporters)
	return nil
}

// retentionFor stamps the same expiry the request event gets, counted from
// when the request arrived, so a classification never outlives its request.
func retentionFor(gw *gatewaydomain.Gateway, requested time.Time) *events.Retention {
	window, ok := gw.RetentionWindow()
	if !ok || window <= 0 {
		return nil
	}
	return &events.Retention{Plan: gw.Entitlements.Tier, ExpiresAt: requested.Add(window).UnixMilli()}
}

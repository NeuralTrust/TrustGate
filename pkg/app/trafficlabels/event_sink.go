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

package trafficlabels

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
)

//go:generate mockery --name=GatewayFinder --dir=. --output=./mocks --filename=gateway_finder_mock.go --case=underscore --with-expecter
type GatewayFinder interface {
	FindByID(ctx context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error)
}

//go:generate mockery --name=LabelPublisher --dir=. --output=./mocks --filename=label_publisher_mock.go --case=underscore --with-expecter
type LabelPublisher interface {
	PublishTrafficLabels(ctx context.Context, evt *events.TrafficLabels, exporters []telemetrydomain.ExporterConfig)
}

const gatewayCacheTTL = 30 * time.Second

var ErrUnpublishable = errors.New("traffic labels sink: classification cannot be published")

var _ Sink = (*eventSink)(nil)

type cachedGateway struct {
	gw      *gatewaydomain.Gateway
	expires time.Time
}

type eventSink struct {
	gateways  GatewayFinder
	publisher LabelPublisher
	now       func() time.Time

	mu    sync.Mutex
	known map[ids.GatewayID]cachedGateway
}

func NewEventSink(gateways GatewayFinder, publisher LabelPublisher) Sink {
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
		if cached.gw == nil {
			return nil, fmt.Errorf("%w: gateway %s not found", ErrUnpublishable, id)
		}
		return cached.gw, nil
	}
	gw, err := s.gateways.FindByID(ctx, id)
	notFound := errors.Is(err, commonerrors.ErrNotFound)
	if err != nil && !notFound {
		return nil, fmt.Errorf("traffic labels sink: find gateway: %w", err)
	}
	s.remember(id, gw, now)
	if notFound {
		return nil, fmt.Errorf("%w: gateway %s not found", ErrUnpublishable, id)
	}
	return gw, nil
}

func (s *eventSink) remember(id ids.GatewayID, gw *gatewaydomain.Gateway, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for known, entry := range s.known {
		if !now.Before(entry.expires) {
			delete(s.known, known)
		}
	}
	s.known[id] = cachedGateway{gw: gw, expires: now.Add(gatewayCacheTTL)}
}

func (s *eventSink) Publish(ctx context.Context, req trafficlabel.Request, cls trafficlabel.Classification) error {
	id, err := ids.Parse[ids.GatewayKind](req.GatewayID)
	if err != nil {
		return fmt.Errorf("%w: gateway id %q: %w", ErrUnpublishable, req.GatewayID, err)
	}
	gw, err := s.gateway(ctx, id)
	if err != nil {
		return err
	}
	now := s.now()
	requested := req.ReceivedAt
	if requested.IsZero() {
		requested = now
	}
	evt := &events.TrafficLabels{
		SchemaVersion: events.TrafficLabelsSchemaVersion,
		TraceID:       req.TraceID,
		GatewayID:     req.GatewayID,
		ConsumerID:    req.ConsumerID,
		TenantID:      gw.TenantID(),
		OccurredOn:    now.UnixMilli(),
		RequestedOn:   requested.UnixMilli(),
		Retention:     retentionFor(gw, requested),
		Results:       labelResults(cls.Resolve(req.LabelSets)),
		RegistryID:    req.RegistryID,
		Model:         req.Model,
		CatalogHash:   req.CatalogHash,
		InputTokens:   cls.InputTokens,
		OutputTokens:  cls.OutputTokens,
		LatencyMs:     cls.Latency.Milliseconds(),
	}
	var exporters []telemetrydomain.ExporterConfig
	if gw.Telemetry != nil {
		exporters = gw.Telemetry.Exporters
	}
	s.publisher.PublishTrafficLabels(ctx, evt, exporters)
	return nil
}

func labelResults(results []trafficlabel.SetResult) []events.LabelResult {
	out := make([]events.LabelResult, len(results))
	for i, r := range results {
		out[i] = events.LabelResult{LabelSetID: r.LabelSetID, LabelSetName: r.LabelSetName, Label: r.Label}
	}
	return out
}

func retentionFor(gw *gatewaydomain.Gateway, requested time.Time) *events.Retention {
	window, ok := gw.RetentionWindow()
	if !ok || window <= 0 {
		return nil
	}
	return &events.Retention{Plan: gw.Entitlements.Tier, ExpiresAt: requested.Add(window).UnixMilli()}
}

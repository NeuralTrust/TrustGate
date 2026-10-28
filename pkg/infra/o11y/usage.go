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

package o11y

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const usageRecordsMetric = "agentgateway.usage.records"

var _ usagedomain.OutcomeRecorder = (*UsageRecordsMetrics)(nil)

// UsageRecordsMetrics counts usage records by outcome. It records nothing when
// operational metrics are off.
type UsageRecordsMetrics struct {
	records  metric.Int64Counter
	outcomes map[string]metric.MeasurementOption
}

// NewUsageRecordsMetrics builds the counter on the global meter provider, which
// the SDK dependency guarantees is installed.
func NewUsageRecordsMetrics(cfg *config.Config, _ *SDK) (*UsageRecordsMetrics, error) {
	if cfg == nil || !cfg.Telemetry.OpsMetricsEnabled {
		return &UsageRecordsMetrics{}, nil
	}
	return newUsageRecordsMetrics(otel.Meter(instrumentationScope))
}

func newUsageRecordsMetrics(meter metric.Meter) (*UsageRecordsMetrics, error) {
	records, err := meter.Int64Counter(usageRecordsMetric, metric.WithUnit("{record}"),
		metric.WithDescription("Usage records by outcome: emitted, dropped, skipped or export_failed."))
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", usageRecordsMetric, err)
	}
	m := &UsageRecordsMetrics{records: records, outcomes: make(map[string]metric.MeasurementOption)}
	for _, outcome := range usagedomain.Outcomes() {
		m.outcomes[outcome] = metric.WithAttributeSet(attribute.NewSet(outcomeKey.String(outcome)))
	}
	return m, nil
}

// Outcome adds n records ending in outcome.
func (m *UsageRecordsMetrics) Outcome(outcome string, n int) {
	if m == nil || m.records == nil || n <= 0 {
		return
	}
	opt, ok := m.outcomes[outcome]
	if !ok {
		opt = metric.WithAttributes(outcomeKey.String(outcome))
	}
	m.records.Add(context.Background(), int64(n), opt)
}

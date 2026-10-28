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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
)

func TestUsageRecordsMetrics_CountsByOutcome(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	m, err := newUsageRecordsMetrics(provider.Meter("test"))
	require.NoError(t, err)

	m.Outcome(usagedomain.OutcomeEmitted, 3)
	m.Outcome(usagedomain.OutcomeDropped, 1)
	m.Outcome(usagedomain.OutcomeSkipped, 0)

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	counts := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, md := range sm.Metrics {
			if md.Name != usageRecordsMetric {
				continue
			}
			for _, dp := range md.Data.(metricdata.Sum[int64]).DataPoints {
				outcome, _ := dp.Attributes.Value(attribute.Key("outcome"))
				counts[outcome.AsString()] += dp.Value
			}
		}
	}
	assert.Equal(t, map[string]int64{usagedomain.OutcomeEmitted: 3, usagedomain.OutcomeDropped: 1}, counts)
}

func TestUsageRecordsMetrics_DisabledIsNoop(t *testing.T) {
	t.Parallel()
	m, err := NewUsageRecordsMetrics(&config.Config{}, nil)
	require.NoError(t, err)
	m.Outcome(usagedomain.OutcomeDropped, 1)
}

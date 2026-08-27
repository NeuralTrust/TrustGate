package o11y

import (
	"context"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestUptimeIsReportedWithoutAnyTraffic(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	if err := registerUptimeGauge(provider.Meter(instrumentationScope)); err != nil {
		t.Fatalf("registerUptimeGauge: %v", err)
	}

	// Deliberately serve no requests: both other instruments are request-driven,
	// so without this an idle gateway is indistinguishable from one whose
	// exporter is broken (AUT-625).
	var collected metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &collected); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, scope := range collected.ScopeMetrics {
		for _, measurement := range scope.Metrics {
			if measurement.Name != UptimeMetric {
				continue
			}
			gauge, ok := measurement.Data.(metricdata.Gauge[float64])
			if !ok || len(gauge.DataPoints) != 1 {
				t.Fatalf("%s is not a float64 gauge with exactly one datapoint", UptimeMetric)
			}
			if gauge.DataPoints[0].Value < 0 {
				t.Fatalf("%s = %v, want a non-negative age", UptimeMetric, gauge.DataPoints[0].Value)
			}
			return
		}
	}
	t.Fatalf("%s absent with zero requests served", UptimeMetric)
}

func TestUptimeMetricNameMatchesFleetContract(t *testing.T) {
	// One watchdog inventory row covers every service only because this name is
	// identical across the fleet; renaming it drops the gateway out of coverage.
	if UptimeMetric != "nt.service.uptime" {
		t.Fatalf("UptimeMetric = %q, want nt.service.uptime", UptimeMetric)
	}
}

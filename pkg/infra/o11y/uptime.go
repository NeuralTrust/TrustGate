package o11y

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/metric"
)

// UptimeMetric is a fleet-wide contract rather than a TrustGate metric:
// watchdog's telemetry-emission inventory covers every service with a single
// row keyed on this exact name, so renaming it here drops the gateway out of
// coverage silently (AUT-625).
const UptimeMetric = "nt.service.uptime"

var processStart = time.Now()

// registerUptimeGauge emits a liveness heartbeat on every collection, whether
// or not the gateway is serving traffic.
//
// Callers must already hold a meter from the installed global MeterProvider.
// An asynchronous instrument created against the no-op provider stays bound to
// it for the process lifetime, so it would silently never report.
func registerUptimeGauge(meter metric.Meter) error {
	_, err := meter.Float64ObservableGauge(
		UptimeMetric,
		metric.WithUnit("s"),
		metric.WithDescription("Seconds since process start. Its presence is the liveness signal; a drop in value is a restart."),
		metric.WithFloat64Callback(func(_ context.Context, observer metric.Float64Observer) error {
			observer.Observe(time.Since(processStart).Seconds())
			return nil
		}),
	)
	if err != nil {
		return fmt.Errorf("create uptime gauge: %w", err)
	}
	return nil
}

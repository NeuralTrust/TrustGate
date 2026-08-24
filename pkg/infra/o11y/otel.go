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
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/version"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	// ServiceName is the OTLP service.name every operational signal carries. It
	// is the name operators and watchdog query on, and it distinguishes this
	// gateway from the legacy one (service.name=legacy-gateway).
	ServiceName = "trustgate"

	// gatewayAttribute stays on the resource alongside service.name so a query
	// can select "any NeuralTrust gateway" while both generations run.
	gatewayAttribute = "nt.gateway"

	instrumentationScope = "github.com/NeuralTrust/TrustGate/operational"

	tracesSignalPath  = "/v1/traces"
	metricsSignalPath = "/v1/metrics"

	// fallbackSamplingRatio applies when the configured ratio is out of range.
	// Sampling nothing is spelled OPS_TRACES_ENABLED=false, not ratio 0.
	fallbackSamplingRatio = 1.0
)

// SDK owns the OpenTelemetry SDK providers behind operational telemetry: bounded
// HTTP metrics and one server span per request.
//
// Product request events are a different pipeline with a different lifetime and
// a different failure mode (pkg/infra/telemetry/otlp, OTLP logs), so they do not
// share these providers. What they do share is the collector, which is why both
// read the OTEL_EXPORTER_OTLP_* family — but each from its own endpoint key,
// because the product endpoint already ends in /v1/logs.
type SDK struct {
	traces  *sdktrace.TracerProvider
	metrics *sdkmetric.MeterProvider
}

// NewSDK builds the operational providers and installs them globally, which is
// what lets otel.Meter callers and future instrumentation libraries find them.
//
// Both signals are off by default. When one is switched on without an endpoint
// this fails at boot rather than starting a gateway that silently exports
// nothing — the exact failure AUT-576 took 30 days to notice.
func NewSDK(cfg *config.Config, logger *slog.Logger) (*SDK, error) {
	sdk := &SDK{}
	tel := cfg.Telemetry

	if tel.OpsTracesEnabled {
		provider, err := newTracerProvider(cfg)
		if err != nil {
			return nil, err
		}
		sdk.traces = provider
		otel.SetTracerProvider(provider)
		logger.Info("operational traces enabled",
			slog.String("service", ServiceName),
			slog.Float64("samplingRatio", samplingRatio(tel.OpsTracesSamplingRatio)))
	}

	if tel.OpsMetricsEnabled {
		provider, err := newMeterProvider(cfg)
		if err != nil {
			return nil, err
		}
		sdk.metrics = provider
		otel.SetMeterProvider(provider)
		logger.Info("operational metrics enabled", slog.String("service", ServiceName))
	}

	return sdk, nil
}

// Tracer returns the operational tracer, or nil when traces are disabled. A nil
// tracer is the signal callers use to skip span work altogether.
func (s *SDK) Tracer() trace.Tracer {
	if s == nil || s.traces == nil {
		return nil
	}
	return s.traces.Tracer(instrumentationScope)
}

// Shutdown flushes both providers. Without it the last batch dies with the
// process, which on a rolling deploy is exactly the window an operator is
// looking at.
func (s *SDK) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	var errs []error
	if s.traces != nil {
		if err := s.traces.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("operational traces: %w", err))
		}
	}
	if s.metrics != nil {
		if err := s.metrics.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("operational metrics: %w", err))
		}
	}
	return errors.Join(errs...)
}

func newTracerProvider(cfg *config.Config) (*sdktrace.TracerProvider, error) {
	endpoint, err := signalEndpoint(
		cfg.Telemetry.OTLP.TracesEndpoint, tracesSignalPath, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
	)
	if err != nil {
		return nil, err
	}
	opts := []otlptracehttp.Option{otlptracehttp.WithEndpointURL(endpoint)}
	if headers := cfg.Telemetry.OTLP.Headers; len(headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(headers))
	}
	if timeout := cfg.Telemetry.OTLP.Timeout; timeout > 0 {
		opts = append(opts, otlptracehttp.WithTimeout(timeout))
	}
	exporter, err := otlptracehttp.New(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("operational traces exporter: %w", err)
	}
	ratio := samplingRatio(cfg.Telemetry.OpsTracesSamplingRatio)
	return sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(newResource(cfg)),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
	), nil
}

func newMeterProvider(cfg *config.Config) (*sdkmetric.MeterProvider, error) {
	endpoint, err := signalEndpoint(
		cfg.Telemetry.OTLP.MetricsEndpoint, metricsSignalPath, "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
	)
	if err != nil {
		return nil, err
	}
	opts := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpointURL(endpoint)}
	if headers := cfg.Telemetry.OTLP.Headers; len(headers) > 0 {
		opts = append(opts, otlpmetrichttp.WithHeaders(headers))
	}
	if timeout := cfg.Telemetry.OTLP.Timeout; timeout > 0 {
		opts = append(opts, otlpmetrichttp.WithTimeout(timeout))
	}
	exporter, err := otlpmetrichttp.New(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("operational metrics exporter: %w", err)
	}
	return sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(newResource(cfg)),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)),
	), nil
}

func newResource(cfg *config.Config) *resource.Resource {
	return resource.NewWithAttributes(semconv.SchemaURL,
		semconv.ServiceNameKey.String(ServiceName),
		semconv.ServiceVersionKey.String(version.Version),
		semconv.DeploymentEnvironmentNameKey.String(cfg.AppEnv),
		attribute.String(gatewayAttribute, ServiceName),
	)
}

// signalEndpoint normalises an OTLP/HTTP endpoint into a full URL. WithEndpointURL
// takes the path verbatim and treats it as set, which suppresses the SDK's own
// per-signal path, so a bare authority has to gain one here or every batch would
// POST to the collector root.
func signalEndpoint(raw, signalPath, envKey string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("o11y: %s is required when the matching signal is enabled", envKey)
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("o11y: invalid %s %q: %w", envKey, raw, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("o11y: %s %q has no host", envKey, raw)
	}
	if strings.Trim(u.Path, "/") == "" {
		u.Path = signalPath
	}
	return u.String(), nil
}

// samplingRatio clamps the configured ratio: a negative value would drop every
// span and a value above one is meaningless, and either way a typo must not turn
// the freshness signal off.
func samplingRatio(configured float64) float64 {
	switch {
	case configured <= 0, configured > 1:
		return fallbackSamplingRatio
	default:
		return configured
	}
}

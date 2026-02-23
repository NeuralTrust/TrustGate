package o11y

import (
	"fmt"
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

// OTelClient wraps an httpx.Client with OpenTelemetry tracing.
// When no TracerProvider is registered globally (CE), all operations are no-op.
type OTelClient struct {
	inner  httpx.Client
	tracer trace.Tracer
}

func NewOTelClient(inner httpx.Client, opts ...trace.TracerOption) httpx.Client {
	return &OTelClient{
		inner:  inner,
		tracer: otel.Tracer(tracerName, opts...),
	}
}

func (c *OTelClient) Do(req *http.Request) (*http.Response, error) {
	ctx, span := c.tracer.Start(req.Context(), fmt.Sprintf("HTTP %s", req.Method),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			semconv.HTTPRequestMethodKey.String(req.Method),
			semconv.URLFull(req.URL.String()),
			semconv.ServerAddress(req.URL.Host),
		),
	)
	defer span.End()

	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	resp, err := c.inner.Do(req.WithContext(ctx))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(semconv.HTTPResponseStatusCode(resp.StatusCode))
	if resp.StatusCode >= http.StatusBadRequest {
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", resp.StatusCode))
	}

	return resp, nil
}

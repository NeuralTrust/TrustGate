package o11y

import (
	"context"
	"fmt"
	"time"

	"github.com/valyala/fasthttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "github.com/NeuralTrust/TrustGate/pkg/infra/o11y"

// OTelFastHTTPClient wraps a *fasthttp.Client with OpenTelemetry tracing.
// Context is passed explicitly since fasthttp requests don't carry one.
// When no TracerProvider is registered globally (CE), all operations are no-op.
type OTelFastHTTPClient struct {
	Inner  *fasthttp.Client
	tracer trace.Tracer
}

func NewOTelFastHTTPClient(inner *fasthttp.Client, opts ...trace.TracerOption) *OTelFastHTTPClient {
	return &OTelFastHTTPClient{
		Inner:  inner,
		tracer: otel.Tracer(tracerName, opts...),
	}
}

func (c *OTelFastHTTPClient) Do(ctx context.Context, req *fasthttp.Request, resp *fasthttp.Response) error {
	ctx, span := c.startSpan(ctx, req)
	defer span.End()

	c.injectContext(ctx, req)

	err := c.Inner.Do(req, resp)
	c.finishSpan(span, resp, err)
	return err
}

func (c *OTelFastHTTPClient) DoRedirects(ctx context.Context, req *fasthttp.Request, resp *fasthttp.Response, maxRedirects int) error {
	ctx, span := c.startSpan(ctx, req)
	defer span.End()

	c.injectContext(ctx, req)

	err := c.Inner.DoRedirects(req, resp, maxRedirects)
	c.finishSpan(span, resp, err)
	return err
}

func (c *OTelFastHTTPClient) DoTimeout(ctx context.Context, req *fasthttp.Request, resp *fasthttp.Response, timeout time.Duration) error {
	ctx, span := c.startSpan(ctx, req)
	defer span.End()

	c.injectContext(ctx, req)

	err := c.Inner.DoTimeout(req, resp, timeout)
	c.finishSpan(span, resp, err)
	return err
}

func (c *OTelFastHTTPClient) startSpan(ctx context.Context, req *fasthttp.Request) (context.Context, trace.Span) {
	method := string(req.Header.Method())
	return c.tracer.Start(ctx, fmt.Sprintf("HTTP %s", method),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			semconv.HTTPRequestMethodKey.String(method),
			semconv.URLFull(req.URI().String()),
			semconv.ServerAddress(string(req.Host())),
		),
	)
}

func (c *OTelFastHTTPClient) injectContext(ctx context.Context, req *fasthttp.Request) {
	otel.GetTextMapPropagator().Inject(ctx, &fasthttpRequestCarrier{req: req})
}

func (c *OTelFastHTTPClient) finishSpan(span trace.Span, resp *fasthttp.Response, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return
	}

	statusCode := resp.StatusCode()
	span.SetAttributes(semconv.HTTPResponseStatusCode(statusCode))
	if statusCode >= 400 {
		span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", statusCode))
	}
}

// fasthttpRequestCarrier adapts fasthttp request headers to the
// propagation.TextMapCarrier interface for W3C trace context injection/extraction.
type fasthttpRequestCarrier struct {
	req *fasthttp.Request
}

func (c *fasthttpRequestCarrier) Get(key string) string {
	return string(c.req.Header.Peek(key))
}

func (c *fasthttpRequestCarrier) Set(key, value string) {
	c.req.Header.Set(key, value)
}

func (c *fasthttpRequestCarrier) Keys() []string {
	var keys []string
	c.req.Header.VisitAll(func(k, _ []byte) {
		keys = append(keys, string(k))
	})
	return keys
}

var _ propagation.TextMapCarrier = (*fasthttpRequestCarrier)(nil)

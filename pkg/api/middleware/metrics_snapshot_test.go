package middleware

import (
	"testing"
	"time"

	appmetricsmocks "github.com/NeuralTrust/TrustGate/pkg/app/metrics/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func TestMetricsCapturesOwnedFiberBuffers(t *testing.T) {
	for _, protocol := range []string{"llm", "mcp"} {
		t.Run(protocol, func(t *testing.T) {
			app := fiber.New()
			raw := &fasthttp.RequestCtx{}
			raw.Request.SetRequestURI("/original/v1/chat/completions")
			raw.Request.Header.SetMethod("POST")
			raw.Request.Header.Set("X-Test", "original")
			raw.Response.Header.Set("X-Test", "response")
			raw.Request.SetBodyString("payload")
			c := app.AcquireCtx(raw)
			defer app.ReleaseCtx(c)
			var req *infracontext.RequestContext
			var resp *infracontext.ResponseContext
			if protocol == "llm" {
				m := &MetricsMiddleware{}
				req, resp = m.buildRequestContext(c, "gw"), m.buildResponseContext(c, "gw")
			} else {
				m := &MCPMetricsMiddleware{}
				req, resp = m.buildRequestContext(c, "gw"), m.buildResponseContext(c, "gw")
			}
			c.Path("/healthz")
			for i := range raw.Request.Header.Peek("X-Test") {
				raw.Request.Header.Peek("X-Test")[i] = 'x'
			}
			for i := range raw.Response.Header.Peek("X-Test") {
				raw.Response.Header.Peek("X-Test")[i] = 'x'
			}
			for i := range c.Body() {
				c.Body()[i] = 'x'
			}
			require.Equal(t, "/original/v1/chat/completions", req.Path)
			require.Equal(t, "original", req.Headers["X-Test"][0])
			require.Equal(t, "response", resp.Headers["X-Test"][0])
			require.Equal(t, "payload", string(req.Body))
		})
	}
}

func TestMetricsDelayedCompletionSurvivesRequestReuse(t *testing.T) {
	for _, protocol := range []string{"llm", "mcp"} {
		t.Run(protocol, func(t *testing.T) {
			worker := appmetricsmocks.NewWorker(t)
			worker.EXPECT().Process(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Run(func(rt *trace.RequestTrace, req *infracontext.RequestContext, resp *infracontext.ResponseContext, _, _ time.Time, _ []telemetrydomain.ExporterConfig) {
					require.Equal(t, "/original/v1/chat/completions", req.Path)
					require.Equal(t, req.Path, rt.Metadata().Path)
					require.Equal(t, "original", req.Headers["X-Test"][0])
					require.Equal(t, "original", rt.Metadata().EndUser)
					require.Equal(t, "payload", string(req.Body))
					require.Equal(t, "response", string(resp.Body))
				}).Return().Once()
			cfg := &config.Config{}
			cfg.Telemetry.Enabled = true
			app := fiber.New()
			app.Get("/healthz", func(c *fiber.Ctx) error { return c.SendString("healthy") })
			if protocol == "llm" {
				app.Use(NewMetricsMiddleware(worker, cfg).Middleware())
			} else {
				app.Use(NewMCPMetricsMiddleware(worker, cfg).Middleware())
			}
			var pending *trace.RequestTrace
			app.Post("/*", func(c *fiber.Ctx) error {
				pending = trace.FromContext(c.UserContext())
				pending.AddAsync()
				pending.SetEndUser(c.Get("X-Test"))
				return c.SendString("response")
			})
			raw := &fasthttp.RequestCtx{}
			raw.Request.SetRequestURI("/original/v1/chat/completions")
			raw.Request.Header.SetMethod("POST")
			raw.Request.Header.Set("X-Test", "original")
			raw.Request.SetBodyString("payload")
			app.Handler()(raw)
			require.NotNil(t, pending)
			for i := range raw.Request.Header.Peek("X-Test") {
				raw.Request.Header.Peek("X-Test")[i] = 'x'
			}
			raw.Request.SetRequestURI("/healthz")
			raw.Request.Header.SetMethod("GET")
			raw.Request.SetBodyString("changed")
			app.Handler()(raw)
			pending.Done()
		})
	}
}

func TestStreamFinalizerOwnsOutputUntilAsyncCompletion(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)
	worker.EXPECT().Process(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ *trace.RequestTrace, _ *infracontext.RequestContext, resp *infracontext.ResponseContext, _, _ time.Time, _ []telemetrydomain.ExporterConfig) {
			require.Equal(t, "data: original", string(resp.Body))
			require.Equal(t, "text/event-stream", resp.Headers["Content-Type"][0])
			require.True(t, resp.Streaming)
		}).Return().Once()
	rt := trace.New("stream", trace.Metadata{})
	rt.AddAsync()
	output := []byte("data: original")
	headers := map[string][]string{"Content-Type": {"text/event-stream"}}
	m := &MetricsMiddleware{worker: worker}
	m.streamFinalizer(rt, time.Now(), "gw", nil)(&infracontext.RequestContext{}, output, 200, headers)
	for i := range output {
		output[i] = 'x'
	}
	headers["Content-Type"][0] = "changed"
	rt.Done()
}

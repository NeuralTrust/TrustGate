package metrics

import (
	"context"
	"log/slog"
	"time"

	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/events"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
)

// Exporter publishes a consolidated event to its transport (e.g. Kafka).
type Exporter interface {
	Publish(ctx context.Context, evt *events.Event) error
	Close()
}

// Pipeline folds a request trace into a single consolidated event and publishes
// it. When telemetry is disabled the container injects a nil pipeline and the
// worker skips it.
type Pipeline struct {
	builder  *Builder
	exporter Exporter
	logger   *slog.Logger
}

func NewPipeline(builder *Builder, exporter Exporter, logger *slog.Logger) *Pipeline {
	return &Pipeline{builder: builder, exporter: exporter, logger: logger}
}

func (p *Pipeline) publish(
	requestTrace *trace.RequestTrace,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	startTime, endTime time.Time,
) {
	if p == nil || p.exporter == nil || p.builder == nil {
		return
	}
	ctx := context.Background()
	evt := p.builder.Build(ctx, requestTrace, req, resp, startTime, endTime)
	if err := p.exporter.Publish(ctx, evt); err != nil {
		p.logger.Error("failed to publish metrics event",
			slog.String("gateway_id", req.GatewayID),
			slog.String("error", err.Error()))
	}
}

func (p *Pipeline) close() {
	if p == nil || p.exporter == nil {
		return
	}
	p.exporter.Close()
}

package plugins

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type PluginWrapper struct {
	Plugin           pluginiface.Plugin
	MetricsCollector *metrics.Collector
}

func NewPluginWrapper(plugin pluginiface.Plugin, collector *metrics.Collector) *PluginWrapper {
	return &PluginWrapper{
		Plugin:           plugin,
		MetricsCollector: collector,
	}
}

func (w *PluginWrapper) Execute(
	ctx context.Context,
	cfg types.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
) (*types.PluginResponse, error) {
	evtCtx := metrics.NewEventContext(cfg.Name, string(req.Stage), w.MetricsCollector)

	start := time.Now()
	pluginResp, err := w.Plugin.Execute(ctx, cfg, req, resp, evtCtx)
	latency := time.Since(start)
	evtCtx.SetSLatency(latency)
	if err != nil {
		var pluginErr *types.PluginError
		if errors.As(err, &pluginErr) {
			evtCtx.SetStatusCode(pluginErr.StatusCode)
		}
		evtCtx.SetError(err)
		evtCtx.Publish()
		return nil, err
	}

	if pluginResp != nil {
		evtCtx.SetStatusCode(pluginResp.StatusCode)
	} else {
		evtCtx.SetStatusCode(http.StatusOK)
	}

	evtCtx.Publish()
	return pluginResp, nil
}

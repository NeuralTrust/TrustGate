package plugins

import (
	"context"

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
	pluginResp, err := w.Plugin.Execute(ctx, cfg, req, resp, evtCtx)
	if err != nil {
		evtCtx.SetError(err)
	}
	evtCtx.Publish()
	return pluginResp, err
}

package plugins

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/pluginiface"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
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
	cfg pluginTypes.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
) (*pluginTypes.PluginResponse, error) {
	evtCtx := metrics.NewEventContext(cfg.Name, string(req.Stage), w.MetricsCollector)

	if modeVal, ok := cfg.Settings["mode"]; ok {
		if modeStr, ok := modeVal.(string); ok {
			evtCtx.SetMode(pluginTypes.Option(modeStr))
		}
	}

	start := time.Now()
	pluginResp, err := w.Plugin.Execute(ctx, cfg, req, resp, evtCtx)
	latency := time.Since(start)
	evtCtx.SetSLatency(latency)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			evtCtx.SetStatusCode(http.StatusOK)
			evtCtx.Publish()
			return &pluginTypes.PluginResponse{StatusCode: http.StatusOK}, nil
		}
		if pluginErr, ok := errors.AsType[*pluginTypes.PluginError](err); ok {
			evtCtx.SetStatusCode(pluginErr.StatusCode)
		}
		if !evtCtx.HasDecision() {
			evtCtx.SetDecision(pluginTypes.DecisionBlock)
		}
		evtCtx.SetError(err)
		evtCtx.Publish()
		return nil, err
	}

	if pluginResp == nil {
		pluginResp = &pluginTypes.PluginResponse{
			StatusCode: http.StatusOK,
		}
	}

	evtCtx.SetStatusCode(pluginResp.StatusCode)
	evtCtx.Publish()
	return pluginResp, nil
}

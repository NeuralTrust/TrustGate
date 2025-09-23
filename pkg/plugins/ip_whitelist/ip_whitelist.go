package ip_whitelist

import (
	"context"
	"fmt"
	"net"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

const PluginName = "ip_whitelist"

type Config struct {
	CIDRs   []string `mapstructure:"cidrs"`
	IPs     []string `mapstructure:"ips"`
	Enabled bool     `mapstructure:"enabled"`
}

type Plugin struct {
	logger *logrus.Logger
}

func NewIPWhitelistPlugin(logger *logrus.Logger) pluginiface.Plugin {
	return &Plugin{logger: logger}
}

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) RequiredPlugins() []string { return nil }

func (p *Plugin) Stages() []types.Stage { return []types.Stage{types.PreRequest} }

func (p *Plugin) AllowedStages() []types.Stage { return []types.Stage{types.PreRequest} }

func (p *Plugin) ValidateConfig(config types.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}
	if !cfg.Enabled {
		return nil
	}
	for _, c := range cfg.CIDRs {
		if _, _, err := net.ParseCIDR(c); err != nil {
			return fmt.Errorf("invalid CIDR '%s'", c)
		}
	}
	for _, ip := range cfg.IPs {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid IP '%s'", ip)
		}
	}
	if len(cfg.CIDRs) == 0 && len(cfg.IPs) == 0 {
		return fmt.Errorf("at least one of cidrs or ips must be provided when enabled")
	}
	return nil
}

func (p *Plugin) Execute(
	ctx context.Context,
	cfg types.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	evtCtx *metrics.EventContext,
) (*types.PluginResponse, error) {
	var conf Config
	if err := mapstructure.Decode(cfg.Settings, &conf); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}
	if !conf.Enabled {
		return &types.PluginResponse{StatusCode: 200, Message: "ip whitelist disabled"}, nil
	}

	ip := p.extractIPFromContext(ctx)
	if ip == "" {
		p.logger.Warn("ip whitelist: fingerprint not found or invalid")
		if evtCtx != nil {
			evtCtx.SetExtras(IPWhitelistData{Matched: false, IP: ""})
		}
		return nil, &types.PluginError{StatusCode: 403, Message: "forbidden", Err: fmt.Errorf("ip not found")}
	}

	matched, allowIP, allowCIDR := p.match(ip, conf)
	if evtCtx != nil {
		evtCtx.SetExtras(IPWhitelistData{Matched: matched, IP: ip, AllowedIP: allowIP, AllowedCIDR: allowCIDR})
	}
	if matched {
		return &types.PluginResponse{StatusCode: 200, Message: "ip allowed"}, nil
	}
	return nil, &types.PluginError{StatusCode: 403, Message: "forbidden", Err: fmt.Errorf("ip not allowed")}
}

func (p *Plugin) extractIPFromContext(ctx context.Context) string {
	val := ctx.Value(common.FingerprintIdContextKey)
	if val == nil {
		return ""
	}
	id, ok := val.(string)
	if !ok || id == "" {
		return ""
	}
	fp, err := fingerprint.NewFromID(id)
	if err != nil || fp == nil {
		return ""
	}
	return fp.IP
}

func (p *Plugin) match(ip string, conf Config) (bool, string, string) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false, "", ""
	}
	for _, allow := range conf.IPs {
		if ip == allow {
			return true, allow, ""
		}
	}
	for _, c := range conf.CIDRs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		if n.Contains(parsed) {
			return true, "", c
		}
	}
	return false, "", ""
}

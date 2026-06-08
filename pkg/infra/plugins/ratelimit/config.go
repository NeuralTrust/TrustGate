package ratelimit

import (
	"fmt"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/plugins/pluginutil"
)

const defaultRetryAfter = "60"

// limitOrder is the precedence in which limit types are evaluated: most
// granular first. The first exceeded type rejects the request.
var limitOrder = []string{keyPerFingerprint, keyPerIP, keyPerUser, keyGlobal}

const (
	keyPerFingerprint = "per_fingerprint"
	keyPerIP          = "per_ip"
	keyPerUser        = "per_user"
	keyGlobal         = "global"
)

type limitConfig struct {
	Limit  int    `mapstructure:"limit"`
	Window string `mapstructure:"window"`
}

type config struct {
	Limits  map[string]limitConfig `mapstructure:"limits"`
	Actions actionsConfig          `mapstructure:"actions"`
}

type actionsConfig struct {
	Type       string `mapstructure:"type"`
	RetryAfter string `mapstructure:"retry_after"`
}

func parseConfig(settings map[string]any) (*config, error) {
	cfg, err := pluginutil.Parse[config](settings)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.Actions.RetryAfter == "" {
		cfg.Actions.RetryAfter = defaultRetryAfter
	}
	return &cfg, nil
}

func (c *config) validate() error {
	if len(c.Limits) == 0 {
		return fmt.Errorf("rate_limiter: at least one limit is required")
	}
	for limitType, lc := range c.Limits {
		if lc.Limit <= 0 {
			return fmt.Errorf("rate_limiter: limit for %q must be positive", limitType)
		}
		if lc.Window == "" {
			return fmt.Errorf("rate_limiter: window for %q is required", limitType)
		}
		if _, err := time.ParseDuration(lc.Window); err != nil {
			return fmt.Errorf("rate_limiter: invalid window for %q: %w", limitType, err)
		}
	}
	if c.Actions.Type != "" && c.Actions.Type != "reject" && c.Actions.Type != "block" {
		return fmt.Errorf("rate_limiter: actions.type must be 'reject' or 'block'")
	}
	return nil
}

package tokenratelimit

import (
	"fmt"
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/plugins/pluginutil"
)

type windowConfig struct {
	Unit string `mapstructure:"unit"`
	Max  int    `mapstructure:"max"`
}

type config struct {
	IdentifierHeader string       `mapstructure:"identifier_header"`
	Window           windowConfig `mapstructure:"window"`
}

var validUnits = map[string]int{
	"second": 1,
	"minute": 60,
	"hour":   3600,
	"day":    86400,
}

func parseConfig(settings map[string]any) (*config, error) {
	cfg, err := pluginutil.Parse[config](settings)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *config) validate() error {
	if c.Window.Max <= 0 {
		return fmt.Errorf("token_rate_limiter: window.max must be > 0")
	}
	if _, ok := validUnits[strings.ToLower(c.Window.Unit)]; !ok {
		return fmt.Errorf("token_rate_limiter: window.unit must be one of second, minute, hour, day")
	}
	return nil
}

func (c *config) windowSeconds() int {
	if secs, ok := validUnits[strings.ToLower(c.Window.Unit)]; ok {
		return secs
	}
	return validUnits["minute"]
}

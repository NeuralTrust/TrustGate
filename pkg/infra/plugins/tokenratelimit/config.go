// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

// config is the token_rate_limiter settings. Whether the budget is enforced
// gateway-wide or per consumer is decided by the policy scope (Policy.Global) at
// runtime.
//
// GroupByHeader optionally sub-partitions the budget within the policy scope by
// the value of a request header (e.g. a tenant or end-user id), so each distinct
// header value gets its own budget. When empty (or the header is absent on a
// request), the budget is keyed by the scope subject (gateway or consumer).
type config struct {
	Window        windowConfig `mapstructure:"window"`
	GroupByHeader string       `mapstructure:"group_by_header"`
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

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

package ratelimit

import (
	"fmt"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/plugins/pluginutil"
)

const defaultRetryAfter = "60"

// config is the rate_limiter settings. The limit is a single sliding window;
// whether it is enforced gateway-wide or per consumer is decided by the policy
// scope (Policy.Global) at runtime, not by configuration.
//
// GroupByHeader optionally sub-partitions the counter within the policy scope by
// the value of a request header (e.g. a tenant or end-user id), so each distinct
// header value gets its own budget. When empty (or the header is absent on a
// request), the counter is keyed by the scope subject (gateway or consumer).
type config struct {
	Limit         int    `mapstructure:"limit"`
	Window        string `mapstructure:"window"`
	RetryAfter    string `mapstructure:"retry_after"`
	GroupByHeader string `mapstructure:"group_by_header"`
}

func parseConfig(settings map[string]any) (*config, error) {
	cfg, err := pluginutil.Parse[config](settings)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.RetryAfter == "" {
		cfg.RetryAfter = defaultRetryAfter
	}
	return &cfg, nil
}

func (c *config) validate() error {
	if c.Limit <= 0 {
		return fmt.Errorf("rate_limiter: limit must be positive")
	}
	if c.Window == "" {
		return fmt.Errorf("rate_limiter: window is required")
	}
	if _, err := time.ParseDuration(c.Window); err != nil {
		return fmt.Errorf("rate_limiter: invalid window: %w", err)
	}
	return nil
}

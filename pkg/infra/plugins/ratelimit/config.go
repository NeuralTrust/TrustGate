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
	"math"
	"strconv"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

const minWindow = time.Second

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
		cfg.RetryAfter = defaultRetryAfter(cfg.Window)
	}
	return &cfg, nil
}

// defaultRetryAfter is the window itself: telling a client to come back in a
// fixed minute when the budget returns in ten seconds wastes the difference.
// The window has already been validated as a duration of at least one second.
func defaultRetryAfter(window string) string {
	parsed, err := time.ParseDuration(window)
	if err != nil {
		return "60"
	}
	seconds := int64(math.Ceil(parsed.Seconds()))
	return strconv.FormatInt(seconds, 10)
}

func (c *config) validate() error {
	if c.Limit <= 0 {
		return fmt.Errorf("rate_limiter: limit must be positive")
	}
	if c.Window == "" {
		return fmt.Errorf("rate_limiter: window is required")
	}
	window, err := time.ParseDuration(c.Window)
	if err != nil {
		return fmt.Errorf("rate_limiter: invalid window: %w", err)
	}
	// Requests are counted at one-second resolution, so a shorter window would
	// be silently rounded up and a non-positive one would let everything
	// through while still looking like a limit.
	if window < minWindow {
		return fmt.Errorf("rate_limiter: window must be at least %s, got %s", minWindow, c.Window)
	}
	return nil
}

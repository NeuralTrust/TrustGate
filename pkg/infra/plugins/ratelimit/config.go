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
	"strings"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/limitper"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

const minWindow = time.Second

// retryAfterReset makes Retry-After the seconds until the counter admits a
// request again, instead of a fixed value.
const retryAfterReset = "reset"

// config is the rate_limiter settings. The limit is a single sliding window;
// whether it is enforced gateway-wide or per consumer is decided by the policy's
// gateway-wide placement (global or MCP-wide) at runtime. LimitPer narrows the
// counter to one application, key, group or model within that scope.
//
// GroupBy optionally sub-partitions the counter within the policy scope, so
// each caller gets its own budget: by the verified subject the request runs
// as ("subject"), by a verified token claim named in GroupByClaim ("claim"),
// or by a request header named in GroupByHeader ("header"; a header alone,
// with GroupBy empty, is the older spelling of the same). A request with no
// value for the partition, and every request when it is unset, is counted
// against the scope subject (gateway or consumer).
type config struct {
	Limit         int    `mapstructure:"limit"`
	Window        string `mapstructure:"window"`
	RetryAfter    string `mapstructure:"retry_after"`
	GroupBy       string `mapstructure:"group_by"`
	GroupByClaim  string `mapstructure:"group_by_claim"`
	GroupByHeader string `mapstructure:"group_by_header"`
	// MaxParallel caps the requests in progress at once, open streams included,
	// across gateway replicas. Zero is no cap.
	MaxParallel   int `mapstructure:"max_parallel"`
	limitper.Spec `mapstructure:",squash"`

	partition appplugins.GroupBy
}

var limitModes = []string{limitper.Shared, limitper.Application, limitper.APIKey, limitper.Group, limitper.Model, limitper.Header}

func parseConfig(settings map[string]any) (*config, error) {
	cfg, err := pluginutil.Parse[config](settings)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.RetryAfter = canonicalRetryAfter(cfg.RetryAfter)
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

// canonicalRetryAfter makes "Reset" and " reset " the reset mode and leaves a
// fixed value as it is.
func canonicalRetryAfter(v string) string {
	if canonical := strings.ToLower(strings.TrimSpace(v)); canonical == retryAfterReset {
		return canonical
	}
	return v
}

func (c *config) retryAfterResets() bool { return c.RetryAfter == retryAfterReset }

func (c *config) validate() error {
	if c.Limit <= 0 {
		return fmt.Errorf("rate_limiter: limit must be positive")
	}
	if c.MaxParallel < 0 {
		return fmt.Errorf("rate_limiter: max_parallel must not be negative")
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
	partition, err := appplugins.ParseGroupBy(c.GroupBy, c.GroupByClaim, c.GroupByHeader)
	if err != nil {
		return fmt.Errorf("rate_limiter: %w", err)
	}
	c.partition = partition
	return c.Validate("rate_limiter", limitModes, partition)
}

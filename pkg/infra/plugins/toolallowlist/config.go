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

package toolallowlist

import (
	"fmt"
	"path"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

const (
	onEmptyReject      = "reject"
	onEmptyPassThrough = "pass_through_empty"
	onEmptyStripField  = "strip_tools_field"
)

var validScopes = map[string]struct{}{
	"consumer": {},
	"global":   {},
}

type config struct {
	Scope              string   `mapstructure:"scope"`
	AllowTools         []string `mapstructure:"allow_tools"`
	DenyTools          []string `mapstructure:"deny_tools"`
	OnEmptyAfterFilter string   `mapstructure:"on_empty_after_filter"`
}

func parseConfig(settings map[string]any) (*config, error) {
	cfg, err := pluginutil.Parse[config](settings)
	if err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *config) applyDefaults() {
	if c.OnEmptyAfterFilter == "" {
		c.OnEmptyAfterFilter = onEmptyReject
	}
}

func (c *config) validate() error {
	if len(c.AllowTools) == 0 && len(c.DenyTools) == 0 {
		return fmt.Errorf("tool_allowlist: at least one of allow_tools or deny_tools must be provided")
	}
	patterns := make([]string, 0, len(c.AllowTools)+len(c.DenyTools))
	patterns = append(patterns, c.AllowTools...)
	patterns = append(patterns, c.DenyTools...)
	for _, p := range patterns {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("tool_allowlist: tool patterns must not be blank")
		}
		if _, err := path.Match(p, ""); err != nil {
			return fmt.Errorf("tool_allowlist: invalid tool pattern %q: %w", p, err)
		}
	}
	switch c.OnEmptyAfterFilter {
	case onEmptyReject, onEmptyPassThrough, onEmptyStripField:
	default:
		return fmt.Errorf("tool_allowlist: on_empty_after_filter must be one of reject, pass_through_empty, strip_tools_field")
	}
	if c.Scope != "" {
		if _, ok := validScopes[c.Scope]; !ok {
			return fmt.Errorf("tool_allowlist: scope must be one of consumer, global")
		}
	}
	return nil
}

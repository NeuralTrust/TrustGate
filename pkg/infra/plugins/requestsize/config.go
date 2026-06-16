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

package requestsize

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/plugins/pluginutil"
)

type sizeUnit string

const (
	unitBytes     sizeUnit = "bytes"
	unitKilobytes sizeUnit = "kilobytes"
	unitMegabytes sizeUnit = "megabytes"
)

const (
	defaultAllowedPayloadSize = 10
	defaultMaxCharsPerRequest = 100_000
)

type config struct {
	AllowedPayloadSize   int      `mapstructure:"allowed_payload_size"`
	SizeUnit             sizeUnit `mapstructure:"size_unit"`
	MaxCharsPerRequest   int64    `mapstructure:"max_chars_per_request"`
	RequireContentLength bool     `mapstructure:"require_content_length"`
}

func parseConfig(settings map[string]any) (*config, error) {
	cfg, err := pluginutil.Parse[config](settings)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	return &cfg, nil
}

func (c *config) validate() error {
	if c.AllowedPayloadSize <= 0 {
		return fmt.Errorf("request_size_limiter: allowed_payload_size must be > 0")
	}
	switch c.SizeUnit {
	case "", unitBytes, unitKilobytes, unitMegabytes:
	default:
		return fmt.Errorf("request_size_limiter: size_unit must be one of bytes, kilobytes, megabytes")
	}
	if c.MaxCharsPerRequest < 0 {
		return fmt.Errorf("request_size_limiter: max_chars_per_request cannot be negative")
	}
	return nil
}

func (c *config) applyDefaults() {
	if c.SizeUnit == "" {
		c.SizeUnit = unitMegabytes
	}
	if c.AllowedPayloadSize <= 0 {
		c.AllowedPayloadSize = defaultAllowedPayloadSize
	}
	if c.MaxCharsPerRequest <= 0 {
		c.MaxCharsPerRequest = defaultMaxCharsPerRequest
	}
}

func (c *config) maxSizeBytes() int {
	switch c.SizeUnit {
	case unitBytes:
		return c.AllowedPayloadSize
	case unitKilobytes:
		return c.AllowedPayloadSize * 1024
	default: // megabytes
		return c.AllowedPayloadSize * 1024 * 1024
	}
}

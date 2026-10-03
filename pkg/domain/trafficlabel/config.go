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

package trafficlabel

import (
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

const (
	MaxTextChars         = 10_000
	DefaultMessageWindow = 3
	MaxMessageWindow     = 50
	DefaultSamplingRate  = 1.0
	MaxModelChars        = 256
)

var ErrInvalidConfig = fmt.Errorf("traffic_labeling: %w", commonerrors.ErrValidation)

// Config is the gateway's traffic labeling setting: which registry and model
// classify its chat requests, and how much of each request is looked at.
type Config struct {
	Enabled       bool     `json:"enabled"`
	RegistryID    string   `json:"registry_id,omitempty"`
	Model         string   `json:"model,omitempty"`
	MessageWindow int      `json:"message_window,omitempty"`
	SamplingRate  *float64 `json:"sampling_rate,omitempty"`
}

func (c *Config) IsEnabled() bool {
	return c != nil && c.Enabled && c.RegistryID != "" && c.Model != ""
}

func (c *Config) Window() int {
	if c == nil || c.MessageWindow <= 0 {
		return DefaultMessageWindow
	}
	return c.MessageWindow
}

func (c *Config) Rate() float64 {
	if c == nil || c.SamplingRate == nil {
		return DefaultSamplingRate
	}
	return *c.SamplingRate
}

// Registry returns the parsed registry id, and false when none is set or it is
// not a valid id.
func (c *Config) Registry() (ids.RegistryID, bool) {
	if c == nil || c.RegistryID == "" {
		return ids.RegistryID{}, false
	}
	id, err := ids.Parse[ids.RegistryKind](c.RegistryID)
	if err != nil || id.IsNil() {
		return ids.RegistryID{}, false
	}
	return id, true
}

// Normalized returns a trimmed copy of the config with the defaults made
// explicit. It never mutates the receiver.
func (c *Config) Normalized() *Config {
	if c == nil {
		return nil
	}
	out := *c
	out.RegistryID = strings.ToLower(strings.TrimSpace(c.RegistryID))
	out.Model = strings.TrimSpace(c.Model)
	out.MessageWindow = c.Window()
	rate := c.Rate()
	out.SamplingRate = &rate
	return &out
}

// Validate checks the config without modifying it. Whether the registry exists
// and fits is checked by the application layer.
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}
	registryID := strings.TrimSpace(c.RegistryID)
	model := strings.TrimSpace(c.Model)
	if c.Enabled && registryID == "" {
		return fmt.Errorf("%w: registry_id is required when enabled", ErrInvalidConfig)
	}
	if c.Enabled && model == "" {
		return fmt.Errorf("%w: model is required when enabled", ErrInvalidConfig)
	}
	if registryID != "" {
		if id, err := ids.Parse[ids.RegistryKind](registryID); err != nil || id.IsNil() {
			return fmt.Errorf("%w: registry_id must be a uuid", ErrInvalidConfig)
		}
	}
	if utf8.RuneCountInString(model) > MaxModelChars {
		return fmt.Errorf("%w: model is longer than %d characters", ErrInvalidConfig, MaxModelChars)
	}
	if c.SamplingRate != nil && !inUnitInterval(*c.SamplingRate) {
		return fmt.Errorf("%w: sampling_rate must be between 0 and 1", ErrInvalidConfig)
	}
	if c.MessageWindow < 0 || c.MessageWindow > MaxMessageWindow {
		return fmt.Errorf("%w: message_window must be between 1 and %d", ErrInvalidConfig, MaxMessageWindow)
	}
	return nil
}

func inUnitInterval(v float64) bool {
	return !math.IsNaN(v) && v >= 0 && v <= 1
}

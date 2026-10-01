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

package topic

import (
	"fmt"
	"strings"
	"unicode/utf8"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

const (
	MaxTopics               = 10
	MaxTextChars            = 10_000
	DefaultMessageWindow    = 3
	MaxMessageWindow        = 50
	MaxTopicNameChars       = 64
	MaxTopicDefinitionChars = 2_000
)

var ErrInvalidConfig = fmt.Errorf("topic_classification: %w", commonerrors.ErrValidation)

type Topic struct {
	Name       string `json:"name"`
	Definition string `json:"definition"`
}

type Config struct {
	Enabled       bool     `json:"enabled"`
	Topics        []Topic  `json:"topics,omitempty"`
	Threshold     *float64 `json:"threshold,omitempty"`
	MessageWindow int      `json:"message_window,omitempty"`
	SamplingRate  *float64 `json:"sampling_rate,omitempty"`
}

func (c *Config) IsEnabled() bool {
	return c != nil && c.Enabled && len(c.Topics) > 0
}

func (c *Config) Window() int {
	if c == nil || c.MessageWindow <= 0 {
		return DefaultMessageWindow
	}
	return c.MessageWindow
}

func (c *Config) Rate() float64 {
	if c == nil || c.SamplingRate == nil {
		return 1
	}
	return *c.SamplingRate
}

func (c *Config) Validate() error {
	if c == nil {
		return nil
	}
	if c.Enabled && len(c.Topics) == 0 {
		return fmt.Errorf("%w: at least one topic is required when enabled", ErrInvalidConfig)
	}
	if len(c.Topics) > MaxTopics {
		return fmt.Errorf("%w: at most %d topics are allowed, got %d", ErrInvalidConfig, MaxTopics, len(c.Topics))
	}
	seen := make(map[string]struct{}, len(c.Topics))
	for i := range c.Topics {
		t := &c.Topics[i]
		t.Name = strings.TrimSpace(t.Name)
		t.Definition = strings.TrimSpace(t.Definition)
		if t.Name == "" {
			return fmt.Errorf("%w: topics[%d].name is required", ErrInvalidConfig, i)
		}
		if t.Definition == "" {
			return fmt.Errorf("%w: topics[%d].definition is required", ErrInvalidConfig, i)
		}
		if utf8.RuneCountInString(t.Name) > MaxTopicNameChars {
			return fmt.Errorf("%w: topics[%d].name is longer than %d characters", ErrInvalidConfig, i, MaxTopicNameChars)
		}
		if utf8.RuneCountInString(t.Definition) > MaxTopicDefinitionChars {
			return fmt.Errorf("%w: topics[%d].definition is longer than %d characters", ErrInvalidConfig, i, MaxTopicDefinitionChars)
		}
		if _, dup := seen[t.Name]; dup {
			return fmt.Errorf("%w: topic %q is duplicated", ErrInvalidConfig, t.Name)
		}
		seen[t.Name] = struct{}{}
	}
	if c.Threshold != nil && !inUnitInterval(*c.Threshold) {
		return fmt.Errorf("%w: threshold must be between 0 and 1", ErrInvalidConfig)
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
	return v >= 0 && v <= 1
}

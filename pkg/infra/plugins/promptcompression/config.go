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

package promptcompression

import (
	"errors"
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

const PluginName = "prompt_compression"

var (
	ErrNoTransforms  = errors.New("prompt_compression: at least one transform must be enabled")
	ErrNegativeMin   = errors.New("prompt_compression: min_length must not be negative")
	ErrUnknownRole   = errors.New("prompt_compression: target_roles contains an empty role")
	ErrBadBlankLines = errors.New("prompt_compression: max_consecutive_blank_lines must be >= 1")
)

// Settings is the operator-facing configuration for the prompt compression
// plugin. Every transform is lossless or near-lossless and deterministic, so
// the same input always compresses to the same bytes — which keeps provider
// prompt-cache prefixes stable across turns.
type Settings struct {
	// CompressJSON minifies standalone JSON message content and fenced ```json
	// blocks with encoding/json Compact (whitespace-only, fully lossless).
	CompressJSON bool `mapstructure:"compress_json"`
	// NormalizeWhitespace trims trailing spaces per line and collapses long runs
	// of blank lines.
	NormalizeWhitespace bool `mapstructure:"normalize_whitespace"`
	// StripANSI removes ANSI escape (color/cursor) sequences, common in captured
	// terminal and CI logs.
	StripANSI bool `mapstructure:"strip_ansi"`
	// MaxConsecutiveBlankLines caps runs of blank lines when NormalizeWhitespace
	// is on. Defaults to 1.
	MaxConsecutiveBlankLines int `mapstructure:"max_consecutive_blank_lines"`
	// MinLength skips messages whose content is shorter than this many bytes, so
	// tiny stable messages are never rewritten (avoids cache churn for no gain).
	MinLength int `mapstructure:"min_length"`
	// TargetRoles restricts compression to messages with these roles (e.g.
	// "tool", "user"). Empty means all roles, including the system prompt.
	TargetRoles []string `mapstructure:"target_roles"`

	roleSet map[string]struct{}
}

func parseConfig(settings map[string]any) (Settings, error) {
	cfg, err := pluginutil.Parse[Settings](settings)
	if err != nil {
		return Settings{}, err
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return Settings{}, err
	}
	cfg.index()
	return cfg, nil
}

func (s *Settings) applyDefaults() {
	if s.MaxConsecutiveBlankLines == 0 {
		s.MaxConsecutiveBlankLines = 1
	}
}

func (s *Settings) validate() error {
	if !s.CompressJSON && !s.NormalizeWhitespace && !s.StripANSI {
		return ErrNoTransforms
	}
	if s.MinLength < 0 {
		return ErrNegativeMin
	}
	if s.MaxConsecutiveBlankLines < 1 {
		return ErrBadBlankLines
	}
	for _, r := range s.TargetRoles {
		if strings.TrimSpace(r) == "" {
			return ErrUnknownRole
		}
	}
	return nil
}

func (s *Settings) index() {
	if len(s.TargetRoles) == 0 {
		return
	}
	s.roleSet = make(map[string]struct{}, len(s.TargetRoles))
	for _, r := range s.TargetRoles {
		s.roleSet[strings.ToLower(strings.TrimSpace(r))] = struct{}{}
	}
}

// appliesToRole reports whether a message with the given role should be
// compressed. An empty TargetRoles matches every role.
func (s Settings) appliesToRole(role string) bool {
	if s.roleSet == nil {
		return true
	}
	_, ok := s.roleSet[strings.ToLower(strings.TrimSpace(role))]
	return ok
}

// describe renders the enabled transforms for error/telemetry context.
func (s Settings) describe() string {
	parts := make([]string, 0, 3)
	if s.CompressJSON {
		parts = append(parts, "json")
	}
	if s.NormalizeWhitespace {
		parts = append(parts, "whitespace")
	}
	if s.StripANSI {
		parts = append(parts, "ansi")
	}
	return fmt.Sprintf("[%s]", strings.Join(parts, ","))
}

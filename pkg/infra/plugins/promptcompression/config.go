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

// defaultMaxBodyBytes caps how large a request body the transform pipeline
// will process. Bodies above the cap pass through untouched so per-request
// CPU cost stays bounded on the proxy hot path.
const defaultMaxBodyBytes = 1 << 20 // 1 MiB

var (
	ErrNoTransforms  = errors.New("prompt_compression: at least one transform must be enabled")
	ErrNegativeMin   = errors.New("prompt_compression: min_length must not be negative")
	ErrEmptyRole     = errors.New("prompt_compression: target_roles contains an empty role")
	ErrBadBlankLines = errors.New("prompt_compression: max_consecutive_blank_lines must be >= 1")
	ErrBadMaxBody    = errors.New("prompt_compression: max_body_bytes must not be negative")
)

// wireSettings is the raw operator payload. Pointer fields distinguish "unset"
// (which takes the documented default, matching the catalog schema) from an
// explicit value, so an explicit false or 0 is honored rather than silently
// rewritten.
type wireSettings struct {
	CompressJSON             *bool    `mapstructure:"compress_json"`
	NormalizeWhitespace      *bool    `mapstructure:"normalize_whitespace"`
	StripANSI                *bool    `mapstructure:"strip_ansi"`
	MaxConsecutiveBlankLines *int     `mapstructure:"max_consecutive_blank_lines"`
	MinLength                int      `mapstructure:"min_length"`
	MaxBodyBytes             *int     `mapstructure:"max_body_bytes"`
	TargetRoles              []string `mapstructure:"target_roles"`
}

// Settings is the resolved configuration for the prompt compression plugin.
// Every transform is lossless or near-lossless and deterministic, so the same
// input always compresses to the same bytes — which keeps provider
// prompt-cache prefixes stable across turns.
type Settings struct {
	// CompressJSON minifies standalone JSON message content, fenced ```json
	// blocks, and tool-call arguments (whitespace-only, fully lossless).
	// Defaults to true.
	CompressJSON bool
	// NormalizeWhitespace trims trailing spaces per line (preserving Markdown
	// two-space hard line breaks) and collapses long runs of blank lines.
	// Defaults to true.
	NormalizeWhitespace bool
	// StripANSI removes ANSI escape (color/cursor) sequences, common in captured
	// terminal and CI logs. Defaults to true.
	StripANSI bool
	// MaxConsecutiveBlankLines caps runs of blank lines when NormalizeWhitespace
	// is on. Defaults to 1; explicit values below 1 are rejected.
	MaxConsecutiveBlankLines int
	// MinLength skips messages whose content is shorter than this many bytes, so
	// tiny stable messages are never rewritten (avoids cache churn for no gain).
	MinLength int
	// MaxBodyBytes skips the whole pipeline for request bodies larger than this
	// many bytes, bounding per-request CPU cost. Defaults to 1 MiB; an explicit
	// 0 disables the cap.
	MaxBodyBytes int
	// TargetRoles restricts compression to messages with these roles (e.g.
	// "tool", "user"). Empty means all roles, including the system prompt.
	TargetRoles []string

	roleSet map[string]struct{}
}

func parseConfig(settings map[string]any) (Settings, error) {
	wire, err := pluginutil.Parse[wireSettings](settings)
	if err != nil {
		return Settings{}, err
	}
	cfg := wire.resolve()
	if err := cfg.validate(); err != nil {
		return Settings{}, err
	}
	cfg.index()
	return cfg, nil
}

// resolve materializes defaults for unset fields: the three transforms default
// to enabled, matching the catalog schema the admin UI renders.
func (w wireSettings) resolve() Settings {
	cfg := Settings{
		CompressJSON:             true,
		NormalizeWhitespace:      true,
		StripANSI:                true,
		MaxConsecutiveBlankLines: 1,
		MinLength:                w.MinLength,
		MaxBodyBytes:             defaultMaxBodyBytes,
		TargetRoles:              w.TargetRoles,
	}
	if w.CompressJSON != nil {
		cfg.CompressJSON = *w.CompressJSON
	}
	if w.NormalizeWhitespace != nil {
		cfg.NormalizeWhitespace = *w.NormalizeWhitespace
	}
	if w.StripANSI != nil {
		cfg.StripANSI = *w.StripANSI
	}
	if w.MaxConsecutiveBlankLines != nil {
		cfg.MaxConsecutiveBlankLines = *w.MaxConsecutiveBlankLines
	}
	if w.MaxBodyBytes != nil {
		cfg.MaxBodyBytes = *w.MaxBodyBytes
	}
	return cfg
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
	if s.MaxBodyBytes < 0 {
		return ErrBadMaxBody
	}
	for _, r := range s.TargetRoles {
		if strings.TrimSpace(r) == "" {
			return ErrEmptyRole
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

// withinBodyCap reports whether a request body of the given size is small
// enough to run through the transform pipeline. A zero cap disables the check.
func (s Settings) withinBodyCap(size int) bool {
	return s.MaxBodyBytes == 0 || size <= s.MaxBodyBytes
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

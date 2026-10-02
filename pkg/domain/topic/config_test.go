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
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

func ptr[T any](v T) *T { return &v }

func topics(n int) []Topic {
	out := make([]Topic, n)
	for i := range out {
		out[i] = Topic{Name: fmt.Sprintf("topic-%d", i), Definition: "a definition"}
	}
	return out
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{name: "nil config", cfg: nil},
		{name: "enabled with one topic", cfg: &Config{Enabled: true, Topics: topics(1)}},
		{name: "enabled with the maximum", cfg: &Config{Enabled: true, Topics: topics(MaxTopics)}},
		{name: "disabled without topics", cfg: &Config{Enabled: false}},
		{name: "enabled without topics", cfg: &Config{Enabled: true}, wantErr: true},
		{name: "over the maximum", cfg: &Config{Enabled: true, Topics: topics(MaxTopics + 1)}, wantErr: true},
		{name: "disabled over the maximum", cfg: &Config{Topics: topics(MaxTopics + 1)}, wantErr: true},
		{name: "blank name", cfg: &Config{Enabled: true, Topics: []Topic{{Name: "  ", Definition: "d"}}}, wantErr: true},
		{name: "blank definition", cfg: &Config{Enabled: true, Topics: []Topic{{Name: "n", Definition: " "}}}, wantErr: true},
		{name: "name at the limit", cfg: &Config{Enabled: true, Topics: []Topic{{Name: strings.Repeat("é", MaxTopicNameChars), Definition: "d"}}}},
		{name: "name over the limit", cfg: &Config{Enabled: true, Topics: []Topic{{Name: strings.Repeat("n", MaxTopicNameChars+1), Definition: "d"}}}, wantErr: true},
		{name: "definition at the limit", cfg: &Config{Enabled: true, Topics: []Topic{{Name: "n", Definition: strings.Repeat("é", MaxTopicDefinitionChars)}}}},
		{name: "definition over the limit", cfg: &Config{Enabled: true, Topics: []Topic{{Name: "n", Definition: strings.Repeat("d", MaxTopicDefinitionChars+1)}}}, wantErr: true},
		{
			name:    "duplicated name after trimming",
			cfg:     &Config{Enabled: true, Topics: []Topic{{Name: "billing", Definition: "d"}, {Name: " billing ", Definition: "d"}}},
			wantErr: true,
		},
		{name: "threshold at bounds", cfg: &Config{Enabled: true, Topics: topics(1), Threshold: ptr(1.0)}},
		{name: "threshold below zero", cfg: &Config{Enabled: true, Topics: topics(1), Threshold: ptr(-0.1)}, wantErr: true},
		{name: "threshold above one", cfg: &Config{Enabled: true, Topics: topics(1), Threshold: ptr(1.1)}, wantErr: true},
		{name: "threshold NaN", cfg: &Config{Enabled: true, Topics: topics(1), Threshold: ptr(math.NaN())}, wantErr: true},
		{name: "sampling zero", cfg: &Config{Enabled: true, Topics: topics(1), SamplingRate: ptr(0.0)}},
		{name: "sampling above one", cfg: &Config{Enabled: true, Topics: topics(1), SamplingRate: ptr(1.5)}, wantErr: true},
		{name: "window omitted", cfg: &Config{Enabled: true, Topics: topics(1), MessageWindow: 0}},
		{name: "window at maximum", cfg: &Config{Enabled: true, Topics: topics(1), MessageWindow: MaxMessageWindow}},
		{name: "window negative", cfg: &Config{Enabled: true, Topics: topics(1), MessageWindow: -1}, wantErr: true},
		{name: "window over maximum", cfg: &Config{Enabled: true, Topics: topics(1), MessageWindow: MaxMessageWindow + 1}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				if !errors.Is(err, ErrInvalidConfig) || !errors.Is(err, commonerrors.ErrValidation) {
					t.Fatalf("error %v does not wrap ErrInvalidConfig and ErrValidation", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestConfigValidateDoesNotMutate(t *testing.T) {
	t.Parallel()
	cfg := &Config{Enabled: true, Topics: []Topic{{Name: " billing ", Definition: "  refunds and invoices "}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg.Topics[0]; got.Name != " billing " || got.Definition != "  refunds and invoices " {
		t.Fatalf("Validate mutated the config: %+v", got)
	}
}

func TestConfigValidateConcurrentOnSharedConfig(t *testing.T) {
	t.Parallel()
	cfg := &Config{Enabled: true, Topics: []Topic{{Name: " billing ", Definition: "  refunds "}}}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cfg.Validate(); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestConfigNormalized(t *testing.T) {
	t.Parallel()

	var nilCfg *Config
	if nilCfg.Normalized() != nil {
		t.Fatal("nil config must normalise to nil")
	}

	src := &Config{Enabled: true, MessageWindow: 4, Topics: []Topic{{Name: " billing ", Definition: "  refunds and invoices "}}}
	got := src.Normalized()
	if tp := got.Topics[0]; tp.Name != "billing" || tp.Definition != "refunds and invoices" {
		t.Fatalf("topic not trimmed: %+v", tp)
	}
	if !got.Enabled || got.MessageWindow != 4 {
		t.Fatalf("other fields lost: %+v", got)
	}
	if src.Topics[0].Name != " billing " {
		t.Fatalf("Normalized mutated its receiver: %+v", src.Topics[0])
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("normalised config must validate: %v", err)
	}
}

func TestConfigAccessors(t *testing.T) {
	t.Parallel()

	var nilCfg *Config
	if nilCfg.IsEnabled() {
		t.Fatal("nil config reports enabled")
	}
	if got := nilCfg.Window(); got != DefaultMessageWindow {
		t.Fatalf("nil Window() = %d, want %d", got, DefaultMessageWindow)
	}
	if got := nilCfg.Rate(); got != 1 {
		t.Fatalf("nil Rate() = %v, want 1", got)
	}

	if (&Config{Enabled: true}).IsEnabled() {
		t.Fatal("enabled config without topics reports enabled")
	}
	if (&Config{Topics: topics(1)}).IsEnabled() {
		t.Fatal("disabled config reports enabled")
	}

	cfg := &Config{Enabled: true, Topics: topics(1), MessageWindow: 7, SamplingRate: ptr(0.25)}
	if !cfg.IsEnabled() {
		t.Fatal("enabled config reports disabled")
	}
	if got := cfg.Window(); got != 7 {
		t.Fatalf("Window() = %d, want 7", got)
	}
	if got := cfg.Rate(); got != 0.25 {
		t.Fatalf("Rate() = %v, want 0.25", got)
	}
}

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
	"errors"
	"math"
	"strings"
	"sync"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

const testRegistryID = "0190e0d2-6c1f-7a5e-9a3b-1f2e3d4c5b6a"

func ptr[T any](v T) *T { return &v }

func enabled() *Config {
	return &Config{Enabled: true, RegistryID: testRegistryID, Model: "gpt-4o-mini"}
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	with := func(mut func(*Config)) *Config {
		c := enabled()
		mut(c)
		return c
	}
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{name: "nil config", cfg: nil},
		{name: "enabled with registry and model", cfg: enabled()},
		{name: "disabled without registry", cfg: &Config{}},
		{name: "enabled without registry", cfg: with(func(c *Config) { c.RegistryID = " " }), wantErr: true},
		{name: "enabled without model", cfg: with(func(c *Config) { c.Model = "" }), wantErr: true},
		{name: "registry not a uuid", cfg: with(func(c *Config) { c.RegistryID = "nope" }), wantErr: true},
		{name: "disabled with a bad registry", cfg: &Config{RegistryID: "nope"}, wantErr: true},
		{name: "model too long", cfg: with(func(c *Config) { c.Model = strings.Repeat("m", MaxModelChars+1) }), wantErr: true},
		{name: "sampling zero", cfg: with(func(c *Config) { c.SamplingRate = ptr(0.0) })},
		{name: "sampling one", cfg: with(func(c *Config) { c.SamplingRate = ptr(1.0) })},
		{name: "sampling above one", cfg: with(func(c *Config) { c.SamplingRate = ptr(1.5) }), wantErr: true},
		{name: "sampling negative", cfg: with(func(c *Config) { c.SamplingRate = ptr(-0.1) }), wantErr: true},
		{name: "sampling NaN", cfg: with(func(c *Config) { c.SamplingRate = ptr(math.NaN()) }), wantErr: true},
		{name: "window omitted", cfg: with(func(c *Config) { c.MessageWindow = 0 })},
		{name: "window at maximum", cfg: with(func(c *Config) { c.MessageWindow = MaxMessageWindow })},
		{name: "window negative", cfg: with(func(c *Config) { c.MessageWindow = -1 }), wantErr: true},
		{name: "window over maximum", cfg: with(func(c *Config) { c.MessageWindow = MaxMessageWindow + 1 }), wantErr: true},
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

func TestConfigValidateConcurrentOnSharedConfig(t *testing.T) {
	t.Parallel()
	cfg := &Config{Enabled: true, RegistryID: " " + testRegistryID + " ", Model: " gpt "}
	var wg sync.WaitGroup
	for range 16 {
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

	src := &Config{Enabled: true, RegistryID: " " + strings.ToUpper(testRegistryID) + " ", Model: " gpt-4o-mini "}
	got := src.Normalized()
	if got.RegistryID != testRegistryID || got.Model != "gpt-4o-mini" {
		t.Fatalf("not trimmed: %+v", got)
	}
	if got.MessageWindow != DefaultMessageWindow || got.SamplingRate == nil || *got.SamplingRate != DefaultSamplingRate {
		t.Fatalf("defaults not made explicit: %+v", got)
	}
	if src.Model != " gpt-4o-mini " || src.SamplingRate != nil {
		t.Fatalf("Normalized mutated its receiver: %+v", src)
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
	if _, ok := nilCfg.Registry(); ok {
		t.Fatal("nil config reports a registry")
	}
	if (&Config{Enabled: true, Model: "m"}).IsEnabled() {
		t.Fatal("enabled config without registry reports enabled")
	}
	if (&Config{RegistryID: testRegistryID, Model: "m"}).IsEnabled() {
		t.Fatal("disabled config reports enabled")
	}

	cfg := &Config{Enabled: true, RegistryID: testRegistryID, Model: "m", MessageWindow: 7, SamplingRate: ptr(0.25)}
	if !cfg.IsEnabled() {
		t.Fatal("enabled config reports disabled")
	}
	if got := cfg.Window(); got != 7 {
		t.Fatalf("Window() = %d, want 7", got)
	}
	if got := cfg.Rate(); got != 0.25 {
		t.Fatalf("Rate() = %v, want 0.25", got)
	}
	if id, ok := cfg.Registry(); !ok || id.String() != testRegistryID {
		t.Fatalf("Registry() = %v, %v", id, ok)
	}
}

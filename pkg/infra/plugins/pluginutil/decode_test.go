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

package pluginutil

import (
	"strings"
	"testing"
)

type sampleSettings struct {
	CategorySeverity map[string]int `mapstructure:"category_severity"`
	MaxTokens        int            `mapstructure:"max_tokens"`
	Endpoint         string         `mapstructure:"endpoint"`
}

func TestDecodeHumanizesObjectInsteadOfNumber(t *testing.T) {
	t.Parallel()
	_, err := Parse[sampleSettings](map[string]any{
		"category_severity": map[string]any{
			"Hate": map[string]any{},
		},
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
	msg := err.Error()
	want := `field "category_severity.Hate" must be a whole number but received an object`
	if !strings.Contains(msg, want) {
		t.Fatalf("expected message to contain %q, got %q", want, msg)
	}
	if strings.Contains(msg, "unconvertible") || strings.Contains(msg, "interface {}") {
		t.Fatalf("message still leaks raw decoder output: %q", msg)
	}
}

func TestDecodeHumanizesMultipleFields(t *testing.T) {
	t.Parallel()
	_, err := Parse[sampleSettings](map[string]any{
		"category_severity": map[string]any{
			"Hate":     map[string]any{},
			"Violence": map[string]any{},
		},
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
	msg := err.Error()
	for _, key := range []string{"category_severity.Hate", "category_severity.Violence"} {
		if !strings.Contains(msg, key) {
			t.Fatalf("expected message to mention %q, got %q", key, msg)
		}
	}
}

func TestDecodeSucceedsWithValidSettings(t *testing.T) {
	t.Parallel()
	cfg, err := Parse[sampleSettings](map[string]any{
		"category_severity": map[string]any{"Hate": 4},
		"max_tokens":        100,
		"endpoint":          "https://example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CategorySeverity["Hate"] != 4 || cfg.MaxTokens != 100 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

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

package registry_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestNormalizeModelLabels_TrimsAndClears(t *testing.T) {
	t.Parallel()

	got, err := registry.NormalizeModelLabels(map[string]string{"  arn:aws:bedrock:x  ": "  Claude  "})
	if err != nil {
		t.Fatalf("NormalizeModelLabels: %v", err)
	}
	if len(got) != 1 || got["arn:aws:bedrock:x"] != "Claude" {
		t.Fatalf("got %v, want trimmed key and value", got)
	}

	empty, err := registry.NormalizeModelLabels(map[string]string{})
	if err != nil || empty != nil {
		t.Fatalf("empty map = %v, %v; want nil, nil", empty, err)
	}
}

func TestNormalizeModelLabels_Rejects(t *testing.T) {
	t.Parallel()

	tooMany := make(map[string]string, registry.MaxModelLabels+1)
	for i := range registry.MaxModelLabels + 1 {
		tooMany["model-"+strconv.Itoa(i)] = "Model"
	}
	tests := map[string]map[string]string{
		"empty key":       {"  ": "Name"},
		"empty value":     {"gpt-4o": " "},
		"value too long":  {"gpt-4o": strings.Repeat("x", registry.MaxModelLabelValueLength+1)},
		"key too long":    {strings.Repeat("k", registry.MaxModelLabelKeyLength+1): "Name"},
		"too many":        tooMany,
		"duplicate trims": {"gpt-4o": "A", " gpt-4o ": "B"},
		"NUL in value":    {"gpt-4o": "GPT\x004o"},
		"control in key":  {"gpt\x07-4o": "GPT-4o"},
	}
	for name, labels := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := registry.NormalizeModelLabels(labels)
			if !errors.Is(err, registry.ErrInvalidModelLabels) || !errors.Is(err, commonerrors.ErrValidation) {
				t.Fatalf("err = %v, want ErrInvalidModelLabels wrapping ErrValidation", err)
			}
		})
	}
}

func TestNormalizeModelLabels_AcceptsLimits(t *testing.T) {
	t.Parallel()

	labels := map[string]string{strings.Repeat("k", registry.MaxModelLabelKeyLength): strings.Repeat("é", registry.MaxModelLabelValueLength)}
	if _, err := registry.NormalizeModelLabels(labels); err != nil {
		t.Fatalf("labels at the limits refused: %v", err)
	}
}

func TestLLMTargetValidate_NormalizesModelLabels(t *testing.T) {
	t.Parallel()

	b, err := registry.NewLLMRegistry(ids.New[ids.GatewayKind](), "bedrock", "", &registry.LLMTarget{
		Provider:    "bedrock",
		Auth:        registry.NewAPIKeyAuth("sk-test"),
		ModelLabels: map[string]string{" arn:aws:bedrock:x ": " Claude "},
	})
	if err != nil {
		t.Fatalf("NewLLMRegistry: %v", err)
	}
	if got := b.ModelLabels()["arn:aws:bedrock:x"]; got != "Claude" {
		t.Fatalf("label = %q, want Claude", got)
	}

	b.LLMTarget.ModelLabels = map[string]string{}
	if err := b.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if b.ModelLabels() != nil {
		t.Fatalf("empty labels kept as %v, want nil", b.ModelLabels())
	}
}

func TestModelDisplayName_FirstMatchWins(t *testing.T) {
	t.Parallel()

	labels := map[string]string{"arn:x": "Profile", "claude": "Claude"}
	if got := registry.ModelDisplayName(labels, "", "arn:x", "claude"); got != "Profile" {
		t.Fatalf("got %q, want Profile", got)
	}
	if got := registry.ModelDisplayName(labels, "other", "claude"); got != "Claude" {
		t.Fatalf("got %q, want Claude", got)
	}
	if got := registry.ModelDisplayName(labels, "other"); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
	if got := registry.ModelDisplayName(nil, "arn:x"); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}
